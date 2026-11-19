//go:build linux

package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var errCollectorClosed = errors.New("eBPF collector closed")

type linuxCollector struct {
	mu           sync.RWMutex
	coll         *cebpf.Collection
	links        []link.Link
	rbReader     *ringbuf.Reader
	eventsCh     chan KernelEvent
	doneCh       chan struct{}
	readDone     chan struct{}
	readStarted  bool
	detached     bool
	closed       bool
	closeOnce    sync.Once
	decodeErrors atomic.Uint64
}

func NewCollector(bpfObjPath string) (Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	useEmbedded, objPath := SelectBPFCollectionSource(bpfObjPath, len(embeddedBPFObj), resolveBPFObjectPath)
	var spec *cebpf.CollectionSpec
	var err error
	if useEmbedded {
		spec, err = cebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedBPFObj))
	} else {
		spec, err = cebpf.LoadCollectionSpec(objPath)
	}
	if err != nil {
		if useEmbedded {
			return nil, fmt.Errorf("load embedded BPF collection spec: %w", err)
		}
		return nil, fmt.Errorf("load BPF collection spec %q: %w", objPath, err)
	}

	coll, err := cebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load BPF collection into kernel: %w", err)
	}

	c := &linuxCollector{
		coll:     coll,
		eventsCh: make(chan KernelEvent, 1024),
		doneCh:   make(chan struct{}),
		readDone: make(chan struct{}),
	}

	mkdirProg := coll.Programs["handle_cgroup_mkdir"]
	execProg := coll.Programs["handle_sched_process_exec"]
	sysEnterProg := coll.Programs["handle_sys_enter"]
	forkProg := coll.Programs["handle_sched_process_fork"]
	exitProg := coll.Programs["handle_sched_process_exit"]
	if mkdirProg == nil || execProg == nil || sysEnterProg == nil || forkProg == nil || exitProg == nil {
		_ = c.Close()
		return nil, fmt.Errorf("missing required BPF programs in %q", objPath)
	}

	attach := func(cat, name string, prog *cebpf.Program) error {
		l, err := link.Tracepoint(cat, name, prog, nil)
		if err != nil {
			return fmt.Errorf("attach tracepoint/%s/%s: %w", cat, name, err)
		}
		c.links = append(c.links, l)
		return nil
	}

	// Core hooks: without these the profiler cannot observe containers at
	// all — a failure here is fatal.
	l1, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "cgroup_mkdir",
		Program: mkdirProg,
	})
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("attach raw_tracepoint/cgroup_mkdir: %w", err)
	}
	c.links = append(c.links, l1)
	if err := attach("sched", "sched_process_exec", execProg); err != nil {
		_ = c.Close()
		return nil, err
	}

	// Mandatory exit cleanup BEFORE fork marking: if exit cleanup cannot
	// attach, PID/TID reuse could leave workload threads suppressed inside
	// runtime_tids.
	lExit, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exit",
		Program: exitProg,
	})
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("attach raw_tracepoint/sched_process_exit: %w", err)
	}
	c.links = append(c.links, lExit)

	// Fork refinement hook is best-effort on unusual kernels: if linking
	// refuses it, secondary "docker exec" setup syscalls may be over-recorded
	// rather than hidden.
	if l4, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_fork",
		Program: forkProg,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[seccomp-profiler] warn: attach raw_tracepoint/sched_process_fork: %v; runtime-suppression degraded: secondary docker exec setup syscalls may be recorded\n", err)
	} else {
		c.links = append(c.links, l4)
	}

	l3, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: sysEnterProg,
	})
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("attach raw_tracepoint/sys_enter: %w", err)
	}
	c.links = append(c.links, l3)

	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		_ = c.Close()
		return nil, fmt.Errorf("missing events ringbuf map in BPF collection")
	}
	rb, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("open events ringbuf reader: %w", err)
	}
	c.rbReader = rb
	c.readStarted = true

	go c.readLoop()
	return c, nil
}

func (c *linuxCollector) readLoop() {
	defer close(c.readDone)
	defer close(c.eventsCh)
	for {
		rec, err := c.rbReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			select {
			case <-c.doneCh:
				return
			case <-time.After(5 * time.Millisecond):
				continue
			}
		}
		ev, err := DecodeKernelEvent(rec.RawSample)
		if err != nil {
			c.decodeErrors.Add(1)
			continue
		}
		select {
		case c.eventsCh <- ev:
		case <-c.doneCh:
			return
		}
	}
}

func (c *linuxCollector) TrackCgroup(cgroupID uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.coll == nil {
		return errCollectorClosed
	}
	m := c.coll.Maps["syscalls_per_cgroup"]
	if m == nil {
		return fmt.Errorf("syscalls_per_cgroup map not found")
	}
	var empty CgroupStats
	err := m.Update(&cgroupID, &empty, cebpf.UpdateNoExist)
	if err != nil && !errors.Is(err, cebpf.ErrKeyExist) {
		return err
	}
	return nil
}

func (c *linuxCollector) Events() <-chan KernelEvent {
	return c.eventsCh
}

func (c *linuxCollector) Flush() (map[uint64]CgroupStats, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || c.coll == nil {
		return nil, errCollectorClosed
	}
	m := c.coll.Maps["syscalls_per_cgroup"]
	if m == nil {
		return nil, fmt.Errorf("syscalls_per_cgroup map not found")
	}
	out := make(map[uint64]CgroupStats)
	var key uint64
	var val CgroupStats
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		out[key] = val
	}
	if err := iter.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func (c *linuxCollector) FlushCgroup(cgroupID uint64) (CgroupStats, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || c.coll == nil {
		return CgroupStats{}, false, errCollectorClosed
	}
	m := c.coll.Maps["syscalls_per_cgroup"]
	if m == nil {
		return CgroupStats{}, false, fmt.Errorf("syscalls_per_cgroup map not found")
	}
	var val CgroupStats
	if err := m.Lookup(&cgroupID, &val); err != nil {
		if errors.Is(err, cebpf.ErrKeyNotExist) {
			return CgroupStats{}, false, nil
		}
		return CgroupStats{}, false, err
	}
	return val, true, nil
}

func (c *linuxCollector) DeleteCgroup(cgroupID uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.coll == nil {
		return errCollectorClosed
	}
	stats := c.coll.Maps["syscalls_per_cgroup"]
	candidates := c.coll.Maps["candidate_cgroups"]
	if stats == nil || candidates == nil {
		return fmt.Errorf("BPF maps not found")
	}
	if err := stats.Delete(&cgroupID); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete syscalls_per_cgroup %d: %w", cgroupID, err)
	}
	if err := candidates.Delete(&cgroupID); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete candidate_cgroups %d: %w", cgroupID, err)
	}
	return nil
}

// kernelErrorCounters mirrors C struct error_counters in bpf/profiler.bpf.c.
type kernelErrorCounters struct {
	CgroupMapFull   uint64
	RingbufDrops    uint64
	OobSyscalls     uint64
	PathTruncations uint64
	ReadErrors      uint64
}

func (c *linuxCollector) ErrorStats() (ErrorStats, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || c.coll == nil {
		return ErrorStats{}, errCollectorClosed
	}
	m := c.coll.Maps["error_stats"]
	if m == nil {
		return ErrorStats{}, fmt.Errorf("error_stats map not found")
	}
	var key uint32 = 0
	var kVal kernelErrorCounters
	if err := m.Lookup(&key, &kVal); err != nil {
		return ErrorStats{}, fmt.Errorf("lookup error_stats[0]: %w", err)
	}
	return ErrorStats{
		CgroupMapFull:   kVal.CgroupMapFull,
		RingbufDrops:    kVal.RingbufDrops,
		OobSyscalls:     kVal.OobSyscalls,
		PathTruncations: kVal.PathTruncations,
		ReadErrors:      kVal.ReadErrors,
		DecodeErrors:    c.decodeErrors.Load(),
	}, nil
}

func (c *linuxCollector) detachLocked() {
	if c.detached {
		return
	}
	c.detached = true
	for _, l := range c.links {
		_ = l.Close()
	}
	c.links = nil
}

// Detach unhooks all BPF programs (idempotent). After Detach no new map
// updates or events are produced, so Flush sees a stable snapshot.
func (c *linuxCollector) Detach() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.detachLocked()
	return nil
}

func (c *linuxCollector) Close() error {
	c.closeOnce.Do(func() {
		close(c.doneCh)
		c.mu.RLock()
		rb := c.rbReader
		waitRead := c.readStarted
		c.mu.RUnlock()
		if rb != nil {
			_ = rb.Close()
		}
		if waitRead {
			<-c.readDone
		}
		c.mu.Lock()
		c.closed = true
		c.detachLocked()
		if c.coll != nil {
			c.coll.Close()
			c.coll = nil
		}
		c.rbReader = nil
		c.mu.Unlock()
	})
	return nil
}

func resolveBPFObjectPathWith(
	explicit string,
	envVal string,
	exePath string,
	euid int,
	existsFn func(string) bool,
) string {
	if explicit != "" {
		return explicit
	}
	if envVal != "" {
		return envVal
	}
	var candidates []string
	if exePath != "" {
		exeDir := filepath.Dir(exePath)
		candidates = append(candidates,
			filepath.Join(exeDir, "profiler.bpf.o"),
			filepath.Join(exeDir, "bpf", "profiler.bpf.o"),
		)
	}
	candidates = append(candidates,
		"/usr/lib/seccomp-profiler/profiler.bpf.o",
		"/usr/local/share/seccomp-profiler/profiler.bpf.o",
	)
	if euid != 0 {
		// Never fall back to an untrusted CWD relative path when running as root.
		candidates = append(candidates, "bpf/profiler.bpf.o")
	}
	for _, p := range candidates {
		if existsFn != nil && existsFn(p) {
			return p
		}
	}
	if euid == 0 {
		return "/usr/local/share/seccomp-profiler/profiler.bpf.o"
	}
	return "bpf/profiler.bpf.o"
}

func resolveBPFObjectPath(explicit string) string {
	exe, _ := os.Executable()
	return resolveBPFObjectPathWith(
		explicit,
		os.Getenv("SECCOMP_PROFILER_BPF_OBJ"),
		exe,
		os.Geteuid(),
		func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		},
	)
}

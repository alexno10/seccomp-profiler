//go:build linux

package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type linuxCollector struct {
	coll     *cebpf.Collection
	links    []link.Link
	rbReader *ringbuf.Reader
	eventsCh chan KernelEvent
	doneCh   chan struct{}
	detached bool
}

func NewCollector(bpfObjPath string) (Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	objPath := resolveBPFObjectPath(bpfObjPath)
	var spec *cebpf.CollectionSpec
	var err error
	if _, statErr := os.Stat(objPath); statErr == nil {
		spec, err = cebpf.LoadCollectionSpec(objPath)
	} else if len(embeddedBPFObj) > 0 {
		spec, err = cebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedBPFObj))
	} else {
		spec, err = cebpf.LoadCollectionSpec(objPath)
	}
	if err != nil {
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
	}

	mkdirProg := coll.Programs["handle_cgroup_mkdir"]
	execProg := coll.Programs["handle_sched_process_exec"]
	sysEnterProg := coll.Programs["handle_sys_enter"]
	execEnterProg := coll.Programs["handle_sys_enter_execve"]
	execEnterAtProg := coll.Programs["handle_sys_enter_execveat"]
	forkProg := coll.Programs["handle_sched_process_fork"]
	if mkdirProg == nil || execProg == nil || sysEnterProg == nil ||
		execEnterProg == nil || execEnterAtProg == nil || forkProg == nil {
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
	if err := attach("cgroup", "cgroup_mkdir", mkdirProg); err != nil {
		_ = c.Close()
		return nil, err
	}
	if err := attach("sched", "sched_process_exec", execProg); err != nil {
		_ = c.Close()
		return nil, err
	}

	// Suppression-refinement hooks are best-effort: if a kernel refuses to
	// link one of them, runtime setup syscalls of secondary "docker exec"
	// workloads may be recorded (over-permissive profiles, never
	// under-recording), which the summary reveals. Losing the daemon over
	// a kernel quirk would be strictly worse.
	for _, h := range []struct {
		cat  string
		name string
		prog *cebpf.Program
	}{
		{"sched", "sched_process_fork", forkProg},
		{"syscalls", "sys_enter_execve", execEnterProg},
		{"syscalls", "sys_enter_execveat", execEnterAtProg},
	} {
		if err := attach(h.cat, h.name, h.prog); err != nil {
			fmt.Fprintf(os.Stderr, "[seccomp-profiler] warn: %v; runtime-suppression degraded: secondary docker exec setup syscalls may be recorded\n", err)
		}
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

	go c.readLoop()
	return c, nil
}

func (c *linuxCollector) readLoop() {
	defer close(c.eventsCh)
	for {
		rec, err := c.rbReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		ev, err := DecodeKernelEvent(rec.RawSample)
		if err != nil {
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
	stats := c.coll.Maps["syscalls_per_cgroup"]
	candidates := c.coll.Maps["candidate_cgroups"]
	if stats == nil || candidates == nil {
		return fmt.Errorf("BPF maps not found")
	}
	_ = stats.Delete(&cgroupID)
	_ = candidates.Delete(&cgroupID)
	return nil
}

func (c *linuxCollector) ErrorStats() (ErrorStats, error) {
	m := c.coll.Maps["error_stats"]
	if m == nil {
		return ErrorStats{}, fmt.Errorf("error_stats map not found")
	}
	var key uint32 = 0
	var val ErrorStats
	if err := m.Lookup(&key, &val); err != nil {
		if errors.Is(err, cebpf.ErrKeyNotExist) {
			return ErrorStats{}, nil
		}
		return ErrorStats{}, err
	}
	return val, nil
}

// Detach unhooks all BPF programs (idempotent). After Detach no new map
// updates or events are produced, so Flush sees a stable snapshot.
func (c *linuxCollector) Detach() error {
	if c.detached {
		return nil
	}
	c.detached = true
	for _, l := range c.links {
		_ = l.Close()
	}
	c.links = nil
	return nil
}

func (c *linuxCollector) Close() error {
	select {
	case <-c.doneCh:
	default:
		close(c.doneCh)
	}
	if c.rbReader != nil {
		_ = c.rbReader.Close()
	}
	_ = c.Detach()
	if c.coll != nil {
		c.coll.Close()
	}
	return nil
}

func resolveBPFObjectPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("SECCOMP_PROFILER_BPF_OBJ"); env != "" {
		return env
	}
	candidates := []string{
		"bpf/profiler.bpf.o",
		"/usr/local/share/seccomp-profiler/profiler.bpf.o",
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates,
			filepath.Join(filepath.Dir(exe), "profiler.bpf.o"),
			filepath.Join(filepath.Dir(exe), "bpf", "profiler.bpf.o"),
		)
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "bpf/profiler.bpf.o"
}

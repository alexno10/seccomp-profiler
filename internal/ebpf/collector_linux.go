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
	coll      *cebpf.Collection
	links     []link.Link
	rbReader  *ringbuf.Reader
	eventsCh  chan KernelEvent
	doneCh    chan struct{}
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
	if mkdirProg == nil || execProg == nil || sysEnterProg == nil {
		_ = c.Close()
		return nil, fmt.Errorf("missing required BPF programs in %q", objPath)
	}

	l1, err := link.Tracepoint("cgroup", "cgroup_mkdir", mkdirProg, nil)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("attach tracepoint/cgroup/cgroup_mkdir: %w", err)
	}
	c.links = append(c.links, l1)

	l2, err := link.Tracepoint("sched", "sched_process_exec", execProg, nil)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("attach tracepoint/sched/sched_process_exec: %w", err)
	}
	c.links = append(c.links, l2)

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

func (c *linuxCollector) Close() error {
	select {
	case <-c.doneCh:
	default:
		close(c.doneCh)
	}
	if c.rbReader != nil {
		_ = c.rbReader.Close()
	}
	for _, l := range c.links {
		_ = l.Close()
	}
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

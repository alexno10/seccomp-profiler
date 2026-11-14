package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	EventCgroupMkdir uint32 = 1
	EventExec        uint32 = 2
)

type CgroupStats struct {
	Counts      [512]uint32
	CompatCount uint32
	Pad         uint32
}

// ErrorStats mirrors the kernel-side error counters map. Any non-zero value
// means the profiler silently lost visibility (full map, dropped ring buffer
// event, or an out-of-range syscall id) and the resulting profile may be
// incomplete.
type ErrorStats struct {
	CgroupMapFull uint64 `json:"cgroupMapFull"`
	RingbufDrops  uint64 `json:"ringbufDrops"`
	OobSyscalls   uint64 `json:"oobSyscalls"`
}

func (e ErrorStats) Any() bool {
	return e.CgroupMapFull > 0 || e.RingbufDrops > 0 || e.OobSyscalls > 0
}

func (e ErrorStats) String() string {
	return fmt.Sprintf("cgroupMapFull=%d ringbufDrops=%d oobSyscalls=%d", e.CgroupMapFull, e.RingbufDrops, e.OobSyscalls)
}

type KernelEvent struct {
	Type         uint32
	CgroupID     uint64
	CgroupPath   string
	ExecFilename string
}

type Collector interface {
	TrackCgroup(cgroupID uint64) error
	Events() <-chan KernelEvent
	Flush() (map[uint64]CgroupStats, error)
	// FlushCgroup reads a single cgroup's stats without deleting them.
	FlushCgroup(cgroupID uint64) (CgroupStats, bool, error)
	// DeleteCgroup removes a cgroup's stats and candidate entries from the
	// kernel maps (called when the container dies to keep the maps bounded).
	DeleteCgroup(cgroupID uint64) error
	// ErrorStats reads the kernel error counters.
	ErrorStats() (ErrorStats, error)
	// Detach unhooks the BPF programs so no new events/stat updates occur
	// before Flush. Close still releases everything.
	Detach() error
	Close() error
}

const RawKernelEventSize = 272

func DecodeKernelEvent(raw []byte) (KernelEvent, error) {
	if len(raw) < RawKernelEventSize {
		return KernelEvent{}, fmt.Errorf("short kernel event buffer: %d bytes", len(raw))
	}
	evType := binary.LittleEndian.Uint32(raw[0:4])
	cgroupID := binary.LittleEndian.Uint64(raw[8:16])
	str := cString(raw[16:RawKernelEventSize])
	ev := KernelEvent{
		Type:     evType,
		CgroupID: cgroupID,
	}
	switch evType {
	case EventCgroupMkdir:
		ev.CgroupPath = str
	case EventExec:
		ev.ExecFilename = str
	default:
		return KernelEvent{}, fmt.Errorf("unknown kernel event type: %d", evType)
	}
	return ev, nil
}

func cString(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx != -1 {
		return string(b[:idx])
	}
	return string(b)
}

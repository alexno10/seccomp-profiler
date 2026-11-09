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
	Close() error
}

type rawKernelEvent struct {
	Type     uint32
	Pad      uint32
	CgroupID uint64
	Path     [256]byte
}

func DecodeKernelEvent(raw []byte) (KernelEvent, error) {
	if len(raw) < binary.Size(rawKernelEvent{}) {
		return KernelEvent{}, fmt.Errorf("short kernel event buffer: %d bytes", len(raw))
	}
	var r rawKernelEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &r); err != nil {
		return KernelEvent{}, err
	}
	str := cString(r.Path[:])
	ev := KernelEvent{
		Type:     r.Type,
		CgroupID: r.CgroupID,
	}
	switch r.Type {
	case EventCgroupMkdir:
		ev.CgroupPath = str
	case EventExec:
		ev.ExecFilename = str
	}
	return ev, nil
}

func cString(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx != -1 {
		return string(b[:idx])
	}
	return string(b)
}

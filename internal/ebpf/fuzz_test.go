package ebpf_test

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/ebpf"
)

// FuzzDecodeKernelEvent guards the kernel-event decoder against malformed
// ring buffer samples.
func FuzzDecodeKernelEvent(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, '/', 0})
	f.Add(make([]byte, 272))

	mkdirSeed := make([]byte, 272)
	binary.LittleEndian.PutUint32(mkdirSeed[0:4], ebpf.EventCgroupMkdir)
	binary.LittleEndian.PutUint64(mkdirSeed[8:16], 4242)
	copy(mkdirSeed[16:], "/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add(mkdirSeed)

	execSeed := make([]byte, 272)
	binary.LittleEndian.PutUint32(execSeed[0:4], ebpf.EventExec)
	binary.LittleEndian.PutUint64(execSeed[8:16], 4242)
	copy(execSeed[16:], "/usr/local/bin/app")
	f.Add(execSeed)

	f.Fuzz(func(t *testing.T, raw []byte) {
		ev, err := ebpf.DecodeKernelEvent(raw)
		if len(raw) < ebpf.RawKernelEventSize {
			if err == nil {
				t.Fatalf("expected error for short buffer len=%d", len(raw))
			}
			return
		}
		if err != nil {
			return
		}
		if ev.Type != ebpf.EventCgroupMkdir && ev.Type != ebpf.EventExec {
			t.Fatalf("decoded unknown event type %d without error", ev.Type)
		}
		if strings.ContainsRune(ev.CgroupPath, '\x00') || strings.ContainsRune(ev.ExecFilename, '\x00') {
			t.Fatalf("decoded string contains NUL byte: %+v", ev)
		}
		if ev.CgroupPath != "" && ev.ExecFilename != "" {
			t.Fatalf("CgroupPath and ExecFilename must be mutually exclusive: %+v", ev)
		}
	})
}

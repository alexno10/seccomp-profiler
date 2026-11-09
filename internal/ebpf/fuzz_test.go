package ebpf_test

import (
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/ebpf"
)

// FuzzDecodeKernelEvent guards the kernel-event decoder against malformed
// ring buffer samples.
func FuzzDecodeKernelEvent(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, '/', 0})
	f.Add(make([]byte, 272))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ebpf.DecodeKernelEvent(raw)
	})
}

package syscalls_test

import (
	"reflect"
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/syscalls"
)

func TestSyscallTableRoundTripAndArchSpecific(t *testing.T) {
	if !syscalls.IsKnownArch(syscalls.ArchAMD64) || !syscalls.IsKnownArch(syscalls.ArchARM64) {
		t.Fatal("expected amd64 and arm64 to be known arches")
	}
	for _, bad := range []syscalls.Arch{"", "riscv64", "386"} {
		if syscalls.IsKnownArch(bad) {
			t.Fatalf("expected %q not to be a known arch", bad)
		}
		if got := syscalls.SeccompArchitectures(bad, false); got != nil {
			t.Fatalf("expected nil SeccompArchitectures for unknown arch %q, got %v", bad, got)
		}
		if _, ok := syscalls.NameByNumber(bad, 0); ok {
			t.Fatalf("expected NameByNumber false for unknown arch %q", bad)
		}
		if _, ok := syscalls.NumberByName(bad, "read"); ok {
			t.Fatalf("expected NumberByName false for unknown arch %q", bad)
		}
	}

	if got := syscalls.SeccompArchitectures(syscalls.ArchAMD64, false); !reflect.DeepEqual(got, []string{"SCMP_ARCH_X86_64"}) {
		t.Fatalf("unexpected amd64 non-compat arches: %v", got)
	}
	if got := syscalls.SeccompArchitectures(syscalls.ArchAMD64, true); !reflect.DeepEqual(got, []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"}) {
		t.Fatalf("unexpected amd64 compat arches: %v", got)
	}
	if got := syscalls.SeccompArchitectures(syscalls.ArchARM64, false); !reflect.DeepEqual(got, []string{"SCMP_ARCH_AARCH64"}) {
		t.Fatalf("unexpected arm64 non-compat arches: %v", got)
	}
	if got := syscalls.SeccompArchitectures(syscalls.ArchARM64, true); !reflect.DeepEqual(got, []string{"SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM"}) {
		t.Fatalf("unexpected arm64 compat arches: %v", got)
	}

	// Verify bijection across [0..511] on both amd64 and arm64.
	for _, arch := range []syscalls.Arch{syscalls.ArchAMD64, syscalls.ArchARM64} {
		count := 0
		for nr := 0; nr < 512; nr++ {
			name, ok := syscalls.NameByNumber(arch, nr)
			if !ok {
				continue
			}
			count++
			if name == "" || name == "syscalls" {
				t.Fatalf("arch=%s nr=%d invalid syscall name %q", arch, nr, name)
			}
			gotNr, ok := syscalls.NumberByName(arch, name)
			if !ok || gotNr != nr {
				t.Fatalf("arch=%s nr=%d name=%q round-trip mismatch: ok=%v gotNr=%d", arch, nr, name, ok, gotNr)
			}
		}
		if count < 300 {
			t.Fatalf("arch=%s expected >=300 syscalls, got %d", arch, count)
		}
	}

	// Arch-specific exclusions: arch_prctl/access/dup2 exist on amd64, not arm64.
	for _, name := range []string{"arch_prctl", "access", "dup2"} {
		if _, ok := syscalls.NumberByName(syscalls.ArchAMD64, name); !ok {
			t.Fatalf("expected %q to exist on amd64", name)
		}
		if _, ok := syscalls.NumberByName(syscalls.ArchARM64, name); ok {
			t.Fatalf("expected %q not to exist on arm64", name)
		}
	}
}

package baseline_test

import (
	"reflect"
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/baseline"
	"github.com/alexno10/seccomp-profiler/internal/syscalls"
)

func TestSyscallLookupAndArch(t *testing.T) {
	if name, ok := syscalls.NameByNumber(syscalls.ArchAMD64, 0); !ok || name != "read" {
		t.Fatalf("expected amd64 syscall 0 = read, got %q (%v)", name, ok)
	}
	if nr, ok := syscalls.NumberByName(syscalls.ArchAMD64, "read"); !ok || nr != 0 {
		t.Fatalf("expected amd64 read = 0, got %d (%v)", nr, ok)
	}
	if name, ok := syscalls.NameByNumber(syscalls.ArchARM64, 63); !ok || name != "read" {
		t.Fatalf("expected arm64 syscall 63 = read, got %q (%v)", name, ok)
	}
	if nr, ok := syscalls.NumberByName(syscalls.ArchARM64, "read"); !ok || nr != 63 {
		t.Fatalf("expected arm64 read = 63, got %d (%v)", nr, ok)
	}
	if _, ok := syscalls.NameByNumber(syscalls.ArchAMD64, 500); ok {
		t.Fatalf("syscall 500 must not exist (guards against IG syscall_1f4 bug)")
	}
	if _, ok := syscalls.NameByNumber(syscalls.ArchAMD64, 512); ok {
		t.Fatalf("x32 syscall 512 must be filtered out")
	}
	if got := syscalls.SeccompArchitectures(syscalls.ArchAMD64, false); !reflect.DeepEqual(got, []string{"SCMP_ARCH_X86_64"}) {
		t.Fatalf("expected native-only [SCMP_ARCH_X86_64], got %v", got)
	}
	if got := syscalls.SeccompArchitectures(syscalls.ArchAMD64, true); !reflect.DeepEqual(got, []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"}) {
		t.Fatalf("expected compat arch list, got %v", got)
	}
	if got := syscalls.SeccompArchitectures(syscalls.ArchARM64, false); !reflect.DeepEqual(got, []string{"SCMP_ARCH_AARCH64"}) {
		t.Fatalf("expected native-only [SCMP_ARCH_AARCH64], got %v", got)
	}
}

func TestLayerSyscallsAndDetectRuntimes(t *testing.T) {
	got := baseline.DetectRuntimes([]string{"/usr/local/bin/python3.12", "/bin/sh"}, "debian:bookworm")
	if !reflect.DeepEqual(got, []string{"python"}) {
		t.Fatalf("expected [python], got %v", got)
	}

	layers := baseline.LayerSyscalls(baseline.ModeStandard, "python")
	for _, mustHave := range []string{"execve", "newfstatat", "faccessat2", "getdents64", "epoll_pwait", "mmap"} {
		found := false
		for _, sc := range layers[baseline.SourceRuntime] {
			if sc == mustHave {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected baseline-runtime to contain post-seccomp runc transition syscall %q", mustHave)
		}
	}
	if len(layers[baseline.SourceLifecycle]) != 17 {
		t.Fatalf("expected 17 lifecycle syscalls, got %d", len(layers[baseline.SourceLifecycle]))
	}
	if len(layers["baseline-lang:python"]) == 0 {
		t.Fatalf("expected python language baseline syscalls")
	}
}

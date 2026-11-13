package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/profile"
)

func TestKernelAtLeast_PrereleaseSuffixes(t *testing.T) {
	cases := []struct {
		release string
		want    bool
	}{
		{"6.12-arch1-1", true},
		{"6.8-rc1", true},
		{"6.6+bpo-amd64", true},
		{"5.19.0-1025-azure", true},
		{"5.18-arch1-1", false},
		{"5.15.0-100-generic", false},
	}
	for _, tc := range cases {
		if got := kernelAtLeast(tc.release, 5, 19); got != tc.want {
			t.Fatalf("kernelAtLeast(%q, 5, 19) = %v, want %v", tc.release, got, tc.want)
		}
	}
}

func TestRunDiff_RespectsExplicitDefaultTarget(t *testing.T) {
	tmp := t.TempDir()
	currPath := filepath.Join(tmp, "api.json")
	commPath := filepath.Join(tmp, "base.json")
	allowPath := filepath.Join(tmp, "accepted.yml")

	comm := profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls:      []profile.OCISyscallRule{{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"}},
	}
	curr := profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls:      []profile.OCISyscallRule{{Names: []string{"read", "ptrace"}, Action: "SCMP_ACT_ALLOW"}},
	}
	cb, _ := json.Marshal(comm)
	kb, _ := json.Marshal(curr)
	_ = os.WriteFile(commPath, cb, 0o644)
	_ = os.WriteFile(currPath, kb, 0o644)
	// Approve ptrace specifically for target "default" (NOT "api").
	_ = os.WriteFile(allowPath, []byte("version: 1\naccepted:\n  - target: default\n    syscall: ptrace\n    reason: ok\n"), 0o644)

	err := runDiff([]string{
		"--target", "default",
		"--committed", commPath,
		"--current", currPath,
		"--allow-file", allowPath,
		"--fail-on", "high-risk",
	})
	if err != nil {
		t.Fatalf("expected explicit --target default to match default approval and pass, got: %v", err)
	}
}

func TestRunMerge_ValidatesPolicyBeforeWritingAndDedupsOverlappingShards(t *testing.T) {
	tmp := t.TempDir()
	shardDir := filepath.Join(tmp, "shards")
	outDir := filepath.Join(tmp, "out")
	rawDir := filepath.Join(tmp, "raw")
	_ = os.MkdirAll(shardDir, 0o755)

	shardPath := filepath.Join(shardDir, "api.profile.v1.json")
	shard := profile.RawProfileV1{
		SchemaVersion: "v1",
		Host:          profile.RawHostInfo{Arch: "amd64", SeccompArch: "SCMP_ARCH_X86_64"},
		Target:        profile.RawTargetInfo{Name: "api", GroupBy: "image", ContainerCount: 1},
		Syscalls:      map[string]profile.RawSyscallEntry{"read": {Sources: []string{"observed"}, TotalCalls: 10, ContainersSeen: 1}},
	}
	sb, _ := json.Marshal(shard)
	_ = os.WriteFile(shardPath, sb, 0o644)

	// 1. Invalid --fail-on must fail BEFORE creating/writing outDir.
	lockPath := filepath.Join(tmp, "lock.json")
	if err := runMerge([]string{
		"--input-dir", shardDir,
		"--output-dir", outDir,
		"--raw-dir", rawDir,
		"--lock-file", lockPath,
		"--fail-on", "bogus",
	}); err == nil {
		t.Fatal("expected error for invalid --fail-on")
	}
	if _, err := os.Stat(filepath.Join(outDir, "api.json")); !os.IsNotExist(err) {
		t.Fatalf("runMerge wrote %s even though --fail-on was invalid", filepath.Join(outDir, "api.json"))
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("runMerge wrote %s even though --fail-on was invalid", lockPath)
	}

	// 2. Overlapping --input-dir and explicit shardPath must NOT double-count TotalCalls.
	if err := runMerge([]string{
		"--input-dir", shardDir,
		"--output-dir", outDir,
		"--raw-dir", rawDir,
		"--lock-file", filepath.Join(tmp, "lock.json"),
		"--allow-file", filepath.Join(tmp, "missing.yml"),
		shardPath,
	}); err != nil {
		t.Fatalf("runMerge failed: %v", err)
	}
	mergedRaw, err := profile.LoadRawProfileV1(filepath.Join(rawDir, "api.profile.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mergedRaw.Syscalls["read"].TotalCalls != 10 {
		t.Fatalf("expected deduplicated TotalCalls=10, got %d", mergedRaw.Syscalls["read"].TotalCalls)
	}
}

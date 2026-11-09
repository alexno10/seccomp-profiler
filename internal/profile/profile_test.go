package profile_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/baseline"
	"github.com/alexno10/seccomp-profiler/internal/profile"
	"github.com/alexno10/seccomp-profiler/internal/selector"
	"github.com/alexno10/seccomp-profiler/internal/syscalls"
)

func TestBuildProfileAndRawV1(t *testing.T) {
	target := selector.MatchedTarget{
		Name:    "api",
		GroupBy: "compose-service",
		Containers: []selector.ContainerRecord{
			{ID: "c1", Image: "myorg/api:v1", Labels: map[string]string{"com.docker.compose.service": "api"}, DurationMs: 1200},
			{ID: "c2", Image: "myorg/api:v1", Labels: map[string]string{"com.docker.compose.service": "api"}, DurationMs: 800},
		},
		MergedHits:           map[int]uint32{0: 150, 41: 4}, // 0=read, 41=socket on amd64
		ContainersPerSyscall: map[int]int{0: 2, 41: 1},
		CompatHits:           0,
		ExecutedBins:         []string{"/usr/local/bin/go"},
	}

	built, err := profile.Build(target, profile.BuildOptions{
		Arch:             syscalls.ArchAMD64,
		Kernel:           "6.8.0-1015-azure",
		GeneratorVersion: "0.1.0",
		GeneratedAt:      time.Date(2026, 11, 5, 18, 50, 0, 0, time.UTC),
		BaselineMode:     baseline.ModeStandard,
		RuntimeMode:      "auto",
		ExtraAllow:       []string{"nanosleep", "custom_extra"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(built.OCI.Architectures, []string{"SCMP_ARCH_X86_64"}) {
		t.Fatalf("expected native-only [SCMP_ARCH_X86_64], got %v", built.OCI.Architectures)
	}
	if built.Raw.SchemaVersion != "v1" || built.Raw.Target.ContainerCount != 2 {
		t.Fatalf("unexpected raw metadata: %+v", built.Raw)
	}
	readMeta, ok := built.Raw.Syscalls["read"]
	if !ok || readMeta.TotalCalls != 150 || readMeta.ContainersSeen != 2 {
		t.Fatalf("unexpected read metadata: %+v", readMeta)
	}
	if !reflect.DeepEqual(readMeta.Sources, []string{"observed", "baseline-runtime"}) {
		t.Fatalf("expected read sources [observed, baseline-runtime], got %v", readMeta.Sources)
	}
	sigMeta, ok := built.Raw.Syscalls["rt_sigreturn"]
	if !ok || sigMeta.TotalCalls != 0 || sigMeta.ContainersSeen != 0 {
		t.Fatalf("unexpected rt_sigreturn metadata: %+v", sigMeta)
	}
}

func TestWriteTargetFilesLockProtection(t *testing.T) {
	tmp := t.TempDir()
	outDir := filepath.Join(tmp, "profiles")
	rawDir := filepath.Join(tmp, "raw")
	lockFile := filepath.Join(tmp, "lock.json")

	target := selector.MatchedTarget{
		Name:                 "api",
		GroupBy:              "image",
		Containers:           []selector.ContainerRecord{{ID: "c1", Image: "myorg/api:v1"}},
		MergedHits:           map[int]uint32{0: 10},
		ContainersPerSyscall: map[int]int{0: 1},
	}
	built, err := profile.Build(target, profile.BuildOptions{
		Arch:         syscalls.ArchAMD64,
		BaselineMode: baseline.ModeMinimal,
		RuntimeMode:  "none",
	})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	// Case A: Fresh checkout without lock.json where <outDir>/api.json already exists on disk.
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	handwritten := []byte("{\n  \"defaultAction\": \"SCMP_ACT_ERRNO\"\n}\n")
	apiPath := filepath.Join(outDir, "api.json")
	if err := os.WriteFile(apiPath, handwritten, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := profile.WriteTargetFiles(outDir, rawDir, lockFile, []*profile.BuiltProfile{built})
	if err != nil {
		t.Fatalf("WriteTargetFiles Case A failed: %v", err)
	}
	if len(res) != 1 || !res[0].ProtectedManualEdit {
		t.Fatalf("expected ProtectedManualEdit=true in Case A, got %+v", res)
	}
	gotDisk, _ := os.ReadFile(apiPath)
	if !reflect.DeepEqual(gotDisk, handwritten) {
		t.Fatalf("api.json was overwritten in Case A!")
	}
	if _, err := os.Stat(filepath.Join(outDir, "api.suggested.json")); err != nil {
		t.Fatalf("expected api.suggested.json in Case A: %v", err)
	}

	// Case B: Generated file recorded in lock.json, then modified by a human.
	outDirB := filepath.Join(tmp, "profilesB")
	rawDirB := filepath.Join(tmp, "rawB")
	lockFileB := filepath.Join(tmp, "lockB.json")

	resB1, err := profile.WriteTargetFiles(outDirB, rawDirB, lockFileB, []*profile.BuiltProfile{built})
	if err != nil {
		t.Fatalf("WriteTargetFiles Case B1 failed: %v", err)
	}
	if resB1[0].ProtectedManualEdit {
		t.Fatalf("expected initial write not to be protected")
	}

	apiPathB := filepath.Join(outDirB, "api.json")
	if err := os.WriteFile(apiPathB, handwritten, 0o644); err != nil {
		t.Fatal(err)
	}

	resB2, err := profile.WriteTargetFiles(outDirB, rawDirB, lockFileB, []*profile.BuiltProfile{built})
	if err != nil {
		t.Fatalf("WriteTargetFiles Case B2 failed: %v", err)
	}
	if !resB2[0].ProtectedManualEdit {
		t.Fatalf("expected ProtectedManualEdit=true after manual edit in Case B2")
	}
	gotDiskB, _ := os.ReadFile(apiPathB)
	if !reflect.DeepEqual(gotDiskB, handwritten) {
		t.Fatalf("api.json was overwritten after manual edit in Case B2!")
	}
	if _, err := os.Stat(filepath.Join(outDirB, "api.suggested.json")); err != nil {
		t.Fatalf("expected api.suggested.json in Case B2: %v", err)
	}
}

func TestMergeRawProfiles(t *testing.T) {
	shard1 := &profile.RawProfileV1{
		SchemaVersion:    "v1",
		GeneratedAt:      "2026-11-05T18:50:00Z",
		GeneratorVersion: "0.2.0",
		Host: profile.RawHostInfo{
			Arch:        "amd64",
			SeccompArch: "SCMP_ARCH_X86_64",
			Kernel:      "6.8.0-1015-azure",
		},
		Target: profile.RawTargetInfo{
			Name:               "api",
			GroupBy:            "compose-service",
			ContainerCount:     1,
			DetectedRuntimes:   []string{"go"},
			CompatSyscallCount: 0,
			Containers: []profile.RawContainerInfo{
				{ID: "c1", Image: "myorg/api:v1", DurationMs: 500},
			},
		},
		Syscalls: map[string]profile.RawSyscallEntry{
			"read":   {Sources: []string{"observed", "baseline-runtime"}, TotalCalls: 100, ContainersSeen: 1},
			"socket": {Sources: []string{"observed"}, TotalCalls: 3, ContainersSeen: 1},
		},
	}
	shard2 := &profile.RawProfileV1{
		SchemaVersion:    "v1",
		GeneratedAt:      "2026-11-05T18:52:00Z",
		GeneratorVersion: "0.2.0",
		Host: profile.RawHostInfo{
			Arch:        "amd64",
			SeccompArch: "SCMP_ARCH_X86_64",
			Kernel:      "6.8.0-1015-azure",
		},
		Target: profile.RawTargetInfo{
			Name:               "api",
			GroupBy:            "compose-service",
			ContainerCount:     2,
			DetectedRuntimes:   []string{"go", "python"},
			CompatSyscallCount: 0,
			Containers: []profile.RawContainerInfo{
				{ID: "c2", Image: "myorg/api:v1", DurationMs: 600},
				{ID: "c3", Image: "myorg/api:v1", DurationMs: 700},
			},
		},
		Syscalls: map[string]profile.RawSyscallEntry{
			"read":    {Sources: []string{"observed", "baseline-runtime"}, TotalCalls: 250, ContainersSeen: 2},
			"connect": {Sources: []string{"observed"}, TotalCalls: 5, ContainersSeen: 1},
		},
	}

	merged, err := profile.MergeRawProfiles([]*profile.RawProfileV1{shard1, shard2}, time.Date(2026, 11, 5, 19, 0, 0, 0, time.UTC), "0.2.0")
	if err != nil {
		t.Fatalf("MergeRawProfiles failed: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged target, got %d", len(merged))
	}
	b := merged[0]
	if b.TargetName != "api" || b.Raw.Target.ContainerCount != 3 || len(b.Raw.Target.Containers) != 3 {
		t.Fatalf("unexpected merged target container count: %+v", b.Raw.Target)
	}
	if !reflect.DeepEqual(b.Raw.Target.DetectedRuntimes, []string{"go", "python"}) {
		t.Fatalf("expected merged runtimes [go, python], got %v", b.Raw.Target.DetectedRuntimes)
	}
	if b.Raw.Syscalls["read"].TotalCalls != 350 || b.Raw.Syscalls["read"].ContainersSeen != 3 {
		t.Fatalf("expected read TotalCalls=350 ContainersSeen=3, got %+v", b.Raw.Syscalls["read"])
	}
	if !reflect.DeepEqual(b.OCI.Syscalls[0].Names, []string{"connect", "read", "socket"}) {
		t.Fatalf("expected sorted OCI names [connect, read, socket], got %v", b.OCI.Syscalls[0].Names)
	}
}

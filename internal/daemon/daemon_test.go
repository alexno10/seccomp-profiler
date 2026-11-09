package daemon_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/baseline"
	"github.com/alexno10/seccomp-profiler/internal/daemon"
	"github.com/alexno10/seccomp-profiler/internal/docker"
	"github.com/alexno10/seccomp-profiler/internal/ebpf"
	"github.com/alexno10/seccomp-profiler/internal/syscalls"
)

type mockCollector struct {
	eventsCh chan ebpf.KernelEvent
	stats    map[uint64]ebpf.CgroupStats
	tracked  []uint64
}

func (m *mockCollector) TrackCgroup(id uint64) error {
	m.tracked = append(m.tracked, id)
	return nil
}
func (m *mockCollector) Events() <-chan ebpf.KernelEvent { return m.eventsCh }
func (m *mockCollector) Flush() (map[uint64]ebpf.CgroupStats, error) {
	return m.stats, nil
}
func (m *mockCollector) Close() error { return nil }

func TestDaemonEndToEndAndIdempotentStop(t *testing.T) {
	tmp := t.TempDir()
	outDir := filepath.Join(tmp, "profiles")
	rawDir := filepath.Join(tmp, "raw")
	lockFile := filepath.Join(tmp, "lock.json")
	stoppedMarker := filepath.Join(tmp, "stopped")

	cid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var st ebpf.CgroupStats
	st.Counts[0] = 12 // read
	st.Counts[1] = 8  // write

	mc := &mockCollector{
		eventsCh: make(chan ebpf.KernelEvent, 16),
		stats:    map[uint64]ebpf.CgroupStats{9001: st},
	}
	corr := docker.NewCorrelator(nil)
	corr.RecordDockerEvent(docker.DockerEvent{
		Action: "create",
		ID:     cid,
		Image:  "myorg/api:latest",
		Labels: map[string]string{"com.docker.compose.service": "api"},
	})
	corr.RecordKernelEvent(ebpf.KernelEvent{
		Type:         ebpf.EventCgroupMkdir,
		CgroupID:     9001,
		CgroupPath:   "/docker/" + cid,
	})
	corr.RecordKernelEvent(ebpf.KernelEvent{
		Type:         ebpf.EventExec,
		CgroupID:     9001,
		ExecFilename: "/usr/local/bin/go",
	})
	close(mc.eventsCh)

	cfg := daemon.Config{
		ControlAddr:       filepath.Join(tmp, "ctl.sock"),
		StoppedMarkerPath: stoppedMarker,
		OutputDir:         outDir,
		RawDir:            rawDir,
		LockFile:          lockFile,
		CommittedProfile:  filepath.Join(outDir, "{name}.json"),
		AllowFile:         filepath.Join(tmp, "accepted.yml"),
		GroupBy:           "auto",
		BaselineMode:      baseline.ModeStandard,
		RuntimeMode:       "auto",
		OnChange:          "report",
		FailOn:            "high-risk",
		Arch:              syscalls.ArchAMD64,
		Kernel:            "6.8.0-test",
	}

	srv := daemon.NewServer(cfg, mc, corr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("srv.Start failed: %v", err)
	}

	if err := daemon.Ping(srv.Addr()); err != nil {
		t.Fatalf("daemon.Ping failed: %v", err)
	}

	resp1, err := daemon.Stop(srv.Addr(), stoppedMarker)
	if err != nil {
		t.Fatalf("first daemon.Stop failed: %v", err)
	}
	if !resp1.OK || !resp1.GatePassed {
		t.Fatalf("unexpected stop response: %+v", resp1)
	}
	if _, err := os.Stat(filepath.Join(outDir, "api.json")); err != nil {
		t.Fatalf("expected api.json to be written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rawDir, "api.profile.v1.json")); err != nil {
		t.Fatalf("expected api.profile.v1.json to be written: %v", err)
	}
	if _, err := os.Stat(lockFile); err != nil {
		t.Fatalf("expected lock.json to be written: %v", err)
	}
	if !strings.Contains(resp1.MarkdownSummary, "### Target: `api`") {
		t.Fatalf("expected markdown summary to include api target, got:\n%s", resp1.MarkdownSummary)
	}

	// Second STOP call must return idempotently via cached result / stopped marker.
	resp2, err := daemon.Stop(srv.Addr(), stoppedMarker)
	if err != nil {
		t.Fatalf("second daemon.Stop failed: %v", err)
	}
	if resp2.ProfilesDir != resp1.ProfilesDir || resp2.NewSyscallsCount != resp1.NewSyscallsCount {
		t.Fatalf("second Stop response mismatch: %+v vs %+v", resp2, resp1)
	}
}

func TestDaemonPreservesCommittedSyscallsAndArgsAndRejectsCorruptBaseline(t *testing.T) {
	tmp := t.TempDir()
	outDir := filepath.Join(tmp, "profiles")
	rawDir := filepath.Join(tmp, "raw")
	lockFile := filepath.Join(tmp, "lock.json")
	stoppedMarker := filepath.Join(tmp, "stopped")

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	committedJSON := `{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "chmod"],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["ioctl"],
      "action": "SCMP_ACT_ALLOW",
      "args": [{"index": 1, "value": 21505, "op": "SCMP_CMP_EQ"}]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(outDir, "api.json"), []byte(committedJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	cid := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	var st ebpf.CgroupStats
	st.Counts[0] = 5 // read only (chmod not observed in this run)

	mc := &mockCollector{
		eventsCh: make(chan ebpf.KernelEvent, 16),
		stats:    map[uint64]ebpf.CgroupStats{9002: st},
	}
	// Buffer kernel events in channel without pre-feeding correlator to test draining on STOP.
	mc.eventsCh <- ebpf.KernelEvent{
		Type:       ebpf.EventCgroupMkdir,
		CgroupID:   9002,
		CgroupPath: "/docker/" + cid,
	}
	close(mc.eventsCh)

	corr := docker.NewCorrelator(nil)
	corr.RecordDockerEvent(docker.DockerEvent{
		Action: "create",
		ID:     cid,
		Image:  "myorg/api:latest",
		Labels: map[string]string{"com.docker.compose.service": "api"},
	})

	cfg := daemon.Config{
		ControlAddr:       filepath.Join(tmp, "ctl2.sock"),
		StoppedMarkerPath: stoppedMarker,
		OutputDir:         outDir,
		RawDir:            rawDir,
		LockFile:          lockFile,
		CommittedProfile:  filepath.Join(outDir, "{name}.json"),
		AllowFile:         filepath.Join(tmp, "accepted.yml"),
		GroupBy:           "auto",
		BaselineMode:      baseline.ModeNone,
		RuntimeMode:       "none",
		OnChange:          "report",
		FailOn:            "none",
		Arch:              syscalls.ArchAMD64,
	}

	srv := daemon.NewServer(cfg, mc, corr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}

	resp, err := daemon.Stop(srv.Addr(), stoppedMarker)
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	// 1. Diff summary must still report -2 removed (chmod, ioctl) informationally.
	if !strings.Contains(resp.MarkdownSummary, "-2 removed (informational)") {
		t.Fatalf("expected -2 removed (informational) in summary, got:\n%s", resp.MarkdownSummary)
	}
	// 2. Suggested profile must preserve "chmod" and the "ioctl" args rule!
	suggestedBytes, err := os.ReadFile(filepath.Join(outDir, "api.suggested.json"))
	if err != nil {
		t.Fatalf("read api.suggested.json: %v", err)
	}
	suggStr := string(suggestedBytes)
	if !strings.Contains(suggStr, `"chmod"`) || !strings.Contains(suggStr, `"SCMP_CMP_EQ"`) {
		t.Fatalf("expected suggested profile to preserve committed chmod and ioctl args rule, got:\n%s", suggStr)
	}

	// 3. Corrupt committed profile must fail Stop with an explicit error.
	if err := os.WriteFile(filepath.Join(outDir, "api.json"), []byte("{corrupt-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	stoppedMarkerCorrupt := filepath.Join(tmp, "stopped-corrupt")
	mc2 := &mockCollector{
		eventsCh: make(chan ebpf.KernelEvent),
		stats:    map[uint64]ebpf.CgroupStats{9002: st},
	}
	close(mc2.eventsCh)
	cfg.ControlAddr = filepath.Join(tmp, "ctl3.sock")
	cfg.StoppedMarkerPath = stoppedMarkerCorrupt
	srv2 := daemon.NewServer(cfg, mc2, corr)
	if err := srv2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.Stop(srv2.Addr(), stoppedMarkerCorrupt); err == nil {
		t.Fatalf("expected Stop to return an error when committed profile has corrupt JSON")
	}
}

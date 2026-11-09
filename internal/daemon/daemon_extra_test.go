package daemon_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/baseline"
	"github.com/alexno10/seccomp-profiler/internal/daemon"
	"github.com/alexno10/seccomp-profiler/internal/docker"
	"github.com/alexno10/seccomp-profiler/internal/ebpf"
	"github.com/alexno10/seccomp-profiler/internal/syscalls"
)

func newTestServer(t *testing.T, cfg daemon.Config, mc *mockCollector, corr *docker.Correlator) *runningServer {
	t.Helper()
	srv, err := daemon.NewServer(cfg, mc, corr)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	return &runningServer{srv: srv, cancel: cancel}
}

type runningServer struct {
	srv    *daemon.Server
	cancel context.CancelFunc
}

func (r *runningServer) stop() {
	r.cancel()
	_ = r.srv.Wait()
}

// Review item 7: the daemon must exit on SIGTERM/SIGINT instead of leaving a
// root process with attached eBPF programs behind.
func TestDaemonShutsDownOnContextCancel(t *testing.T) {
	tmp := t.TempDir()
	cid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var st ebpf.CgroupStats
	st.Counts[0] = 1

	mc := &mockCollector{
		eventsCh: make(chan ebpf.KernelEvent, 4),
		stats:    map[uint64]ebpf.CgroupStats{9003: st},
	}
	corr := docker.NewCorrelator(nil)
	corr.RecordDockerEvent(docker.DockerEvent{
		Action: "create",
		ID:     cid,
		Image:  "alpine:3.20",
	})
	corr.RecordKernelEvent(ebpf.KernelEvent{
		Type:       ebpf.EventCgroupMkdir,
		CgroupID:   9003,
		CgroupPath: "/docker/" + cid,
	})

	cfg := daemon.Config{
		ControlAddr:      filepath.Join(tmp, "ctl-stop.sock"),
		OutputDir:        filepath.Join(tmp, "profiles"),
		RawDir:           filepath.Join(tmp, "raw"),
		LockFile:         filepath.Join(tmp, "lock.json"),
		BaselineMode:     baseline.ModeNone,
		RuntimeMode:      "none",
		Arch:             syscalls.ArchAMD64,
		FailOn:           "none",
		GeneratorVersion: "test",
	}
	run := newTestServer(t, cfg, mc, corr)
	defer run.stop()

	done := make(chan struct{})
	go func() {
		_ = run.srv.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("Wait returned before context cancel")
	default:
	}

	run.cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not shut down after context cancel (SIGTERM)")
	}
}

// Review item 4: kernel error counters must fail the gate instead of letting
// an incomplete profile pass silently.
func TestDaemonKernelErrorsFailGate(t *testing.T) {
	tmp := t.TempDir()
	cid := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	var st ebpf.CgroupStats
	st.Counts[0] = 1

	mc := &mockCollector{
		eventsCh: make(chan ebpf.KernelEvent, 4),
		stats:    map[uint64]ebpf.CgroupStats{9004: st},
		errs:     ebpf.ErrorStats{RingbufDrops: 3},
	}
	corr := docker.NewCorrelator(nil)
	corr.RecordDockerEvent(docker.DockerEvent{Action: "create", ID: cid, Image: "alpine:3.20"})
	corr.RecordKernelEvent(ebpf.KernelEvent{
		Type:       ebpf.EventCgroupMkdir,
		CgroupID:   9004,
		CgroupPath: "/docker/" + cid,
	})

	cfg := daemon.Config{
		ControlAddr:       filepath.Join(tmp, "ctl-err.sock"),
		StoppedMarkerPath: filepath.Join(tmp, "stopped-err"),
		OutputDir:         filepath.Join(tmp, "profiles"),
		RawDir:            filepath.Join(tmp, "raw"),
		LockFile:          filepath.Join(tmp, "lock.json"),
		BaselineMode:      baseline.ModeNone,
		RuntimeMode:       "none",
		Arch:              syscalls.ArchAMD64,
		FailOn:            "high-risk",
		GeneratorVersion:  "test",
	}
	run := newTestServer(t, cfg, mc, corr)
	defer run.stop()

	resp, err := daemon.Stop(run.srv.Addr(), cfg.StoppedMarkerPath)
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if resp.GatePassed {
		t.Fatalf("expected gate to fail on kernel error counters, got: %+v", resp)
	}
	if !strings.Contains(resp.GateReason, "ringbufDrops=3") {
		t.Fatalf("expected kernel error detail in gate reason, got: %s", resp.GateReason)
	}
}

// Review item 6: on-change=update-pr writes generated profiles to the
// committed-profile location in the working tree.
func TestDaemonUpdatePrWritesCommittedProfiles(t *testing.T) {
	tmp := t.TempDir()
	committedDir := filepath.Join(tmp, "committed")
	if err := os.MkdirAll(committedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cid := "1111111111111111111111111111111111111111111111111111111111111111"
	var st ebpf.CgroupStats
	st.Counts[0] = 1

	mc := &mockCollector{
		eventsCh: make(chan ebpf.KernelEvent, 4),
		stats:    map[uint64]ebpf.CgroupStats{9005: st},
	}
	corr := docker.NewCorrelator(nil)
	corr.RecordDockerEvent(docker.DockerEvent{Action: "create", ID: cid, Image: "alpine:3.20"})
	corr.RecordKernelEvent(ebpf.KernelEvent{
		Type:       ebpf.EventCgroupMkdir,
		CgroupID:   9005,
		CgroupPath: "/docker/" + cid,
	})

	cfg := daemon.Config{
		ControlAddr:       filepath.Join(tmp, "ctl-upd.sock"),
		StoppedMarkerPath: filepath.Join(tmp, "stopped-upd"),
		OutputDir:         filepath.Join(tmp, "out"),
		RawDir:            filepath.Join(tmp, "raw"),
		LockFile:          filepath.Join(tmp, "lock.json"),
		CommittedProfile:  filepath.Join(tmp, "baseline", "{name}.json"),
		WorkingCommitted:  filepath.Join(committedDir, "{name}.json"),
		BaselineMode:      baseline.ModeNone,
		RuntimeMode:       "none",
		Arch:              syscalls.ArchAMD64,
		OnChange:          "update-pr",
		FailOn:            "high-risk",
		GeneratorVersion:  "test",
	}
	run := newTestServer(t, cfg, mc, corr)
	defer run.stop()

	resp, err := daemon.Stop(run.srv.Addr(), cfg.StoppedMarkerPath)
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !resp.GatePassed {
		t.Fatalf("gate should pass: %s", resp.GateReason)
	}
	updated, err := os.ReadFile(filepath.Join(committedDir, "alpine.json"))
	if err != nil {
		t.Fatalf("expected update-pr to write committed profile: %v", err)
	}
	if !strings.Contains(string(updated), `"defaultAction"`) {
		t.Fatalf("unexpected written profile: %s", updated)
	}
	if !strings.Contains(resp.MarkdownSummary, "update-pr") {
		t.Fatalf("expected summary to mention update-pr, got:\n%s", resp.MarkdownSummary)
	}
}

// Review item 15: invalid inputs must fail fast at daemon start.
func TestDaemonValidatesConfigEarly(t *testing.T) {
	base := daemon.Config{
		BaselineMode: baseline.Mode("standrad"),
		RuntimeMode:  "none",
		Arch:         syscalls.ArchAMD64,
	}
	if err := daemon.ValidateConfig(base); err == nil {
		t.Fatal("expected typo baseline mode to be rejected")
	}
	if err := daemon.ValidateConfig(daemon.Config{RuntimeMode: "rust"}); err == nil {
		t.Fatal("expected unknown runtime to be rejected")
	}
	if err := daemon.ValidateConfig(daemon.Config{FailOn: "sometimes"}); err == nil {
		t.Fatal("expected invalid fail-on to be rejected")
	}
	if err := daemon.ValidateConfig(daemon.Config{ExtraAllow: []string{"not_a_syscall"}}); err == nil {
		t.Fatal("expected unknown extra-allow syscall to be rejected")
	}
	if err := daemon.ValidateConfig(daemon.Config{ExtraAllow: []string{"openat"}}); err != nil {
		t.Fatalf("expected valid extra-allow to pass: %v", err)
	}
}

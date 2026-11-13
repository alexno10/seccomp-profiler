package daemon_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

func TestDaemonUpdatePrDistinctPathsTwoRunsAndSamePathHandEdit(t *testing.T) {
	// Scenario 1: Two consecutive runs with OutputDir != WorkingCommitted.
	// Run 2 observes an additional syscall and must update committed/alpine.json directly
	// (NOT falsely treat PR #1's own committed profile as hand-edited).
	tmp := t.TempDir()
	outDir := filepath.Join(tmp, "out")
	rawDir := filepath.Join(tmp, "raw")
	lockFile := filepath.Join(tmp, "lock.json")
	committedDir := filepath.Join(tmp, "committed")
	if err := os.MkdirAll(committedDir, 0o755); err != nil {
		t.Fatal(err)
	}

	cid := "1111111111111111111111111111111111111111111111111111111111111111"
	runOnce := func(sockName string, hits map[int]uint32) *daemon.StopResponse {
		var st ebpf.CgroupStats
		for nr, cnt := range hits {
			st.Counts[nr] = cnt
		}
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
			ControlAddr:       filepath.Join(tmp, sockName+".sock"),
			StoppedMarkerPath: filepath.Join(tmp, sockName+".stopped"),
			OutputDir:         outDir,
			RawDir:            rawDir,
			LockFile:          lockFile,
			CommittedProfile:  filepath.Join(committedDir, "{name}.json"),
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
			t.Fatalf("%s Stop: %v", sockName, err)
		}
		return resp
	}

	_ = runOnce("run1", map[int]uint32{0: 1})
	resp2 := runOnce("run2", map[int]uint32{0: 1, 1: 2})
	if !resp2.OK || !resp2.GatePassed {
		t.Fatalf("run2 failed: %+v", resp2)
	}
	committedData, err := os.ReadFile(filepath.Join(committedDir, "alpine.json"))
	if err != nil {
		t.Fatalf("read committed alpine.json: %v", err)
	}
	if !strings.Contains(string(committedData), `"write"`) {
		t.Fatalf("expected run2 update-pr to update committed alpine.json with write, got:\n%s", committedData)
	}
	if _, statErr := os.Stat(filepath.Join(committedDir, "alpine.suggested.json")); !os.IsNotExist(statErr) {
		t.Fatalf("did not expect spurious alpine.suggested.json for tool-generated profile")
	}

	// Scenario 2: Same path (OutputDir == WorkingCommitted dir) with hand-edited profile & no lock.json -> must NOT overwrite.
	tmp2 := t.TempDir()
	sharedDir := filepath.Join(tmp2, "profiles")
	if err := os.MkdirAll(sharedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	handwritten := []byte("{\n  \"defaultAction\": \"SCMP_ACT_ERRNO\",\n  \"architectures\": [\"SCMP_ARCH_X86_64\"],\n  \"syscalls\": [{\"names\": [\"read\"], \"action\": \"SCMP_ACT_ALLOW\"}]\n}\n")
	if err := os.WriteFile(filepath.Join(sharedDir, "alpine.json"), handwritten, 0o644); err != nil {
		t.Fatal(err)
	}
	var st2 ebpf.CgroupStats
	st2.Counts[0] = 1
	st2.Counts[1] = 1
	mc2 := &mockCollector{
		eventsCh: make(chan ebpf.KernelEvent, 4),
		stats:    map[uint64]ebpf.CgroupStats{9006: st2},
	}
	corr2 := docker.NewCorrelator(nil)
	corr2.RecordDockerEvent(docker.DockerEvent{Action: "create", ID: cid, Image: "alpine:3.20"})
	corr2.RecordKernelEvent(ebpf.KernelEvent{Type: ebpf.EventCgroupMkdir, CgroupID: 9006, CgroupPath: "/docker/" + cid})
	cfg2 := daemon.Config{
		ControlAddr:       filepath.Join(tmp2, "shared.sock"),
		StoppedMarkerPath: filepath.Join(tmp2, "shared.stopped"),
		OutputDir:         sharedDir,
		RawDir:            filepath.Join(tmp2, "raw"),
		LockFile:          filepath.Join(tmp2, "missing-lock.json"),
		CommittedProfile:  filepath.Join(sharedDir, "{name}.json"),
		WorkingCommitted:  filepath.Join(sharedDir, "{name}.json"),
		BaselineMode:      baseline.ModeNone,
		RuntimeMode:       "none",
		Arch:              syscalls.ArchAMD64,
		OnChange:          "update-pr",
		FailOn:            "high-risk",
		GeneratorVersion:  "test",
	}
	runShared := newTestServer(t, cfg2, mc2, corr2)
	defer runShared.stop()
	if _, err := daemon.Stop(runShared.srv.Addr(), cfg2.StoppedMarkerPath); err != nil {
		t.Fatalf("shared Stop: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(sharedDir, "alpine.json"))
	if string(after) != string(handwritten) {
		t.Fatalf("hand-edited shared profile was overwritten: %s", after)
	}
	if _, err := os.Stat(filepath.Join(sharedDir, "alpine.suggested.json")); err != nil {
		t.Fatalf("expected alpine.suggested.json next to protected hand-edited profile: %v", err)
	}
}

type strictCollector struct {
	eventsCh     chan ebpf.KernelEvent
	stats        map[uint64]ebpf.CgroupStats
	flushStarted chan struct{}
	closeOnce    sync.Once
	closeCount   atomic.Int32
	inStopOps    atomic.Int32
	closed       atomic.Bool
	overlapErr   atomic.Bool
}

func (s *strictCollector) TrackCgroup(uint64) error { return nil }
func (s *strictCollector) Events() <-chan ebpf.KernelEvent {
	return s.eventsCh
}
func (s *strictCollector) Detach() error {
	if s.closed.Load() {
		s.overlapErr.Store(true)
	}
	return nil
}
func (s *strictCollector) Flush() (map[uint64]ebpf.CgroupStats, error) {
	s.inStopOps.Add(1)
	defer s.inStopOps.Add(-1)
	select {
	case <-s.flushStarted:
	default:
		close(s.flushStarted)
	}
	time.Sleep(15 * time.Millisecond)
	if s.closed.Load() {
		s.overlapErr.Store(true)
	}
	out := make(map[uint64]ebpf.CgroupStats, len(s.stats))
	for k, v := range s.stats {
		out[k] = v
	}
	return out, nil
}
func (s *strictCollector) FlushCgroup(id uint64) (ebpf.CgroupStats, bool, error) {
	return ebpf.CgroupStats{}, false, nil
}
func (s *strictCollector) DeleteCgroup(uint64) error { return nil }
func (s *strictCollector) ErrorStats() (ebpf.ErrorStats, error) {
	if s.closed.Load() {
		s.overlapErr.Store(true)
	}
	return ebpf.ErrorStats{}, nil
}
func (s *strictCollector) Close() error {
	s.closeCount.Add(1)
	if s.inStopOps.Load() > 0 {
		s.overlapErr.Store(true)
	}
	s.closed.Store(true)
	s.closeOnce.Do(func() { close(s.eventsCh) })
	return nil
}

func TestDaemonShutdownSynchronizesStopCancelAndSingleClose(t *testing.T) {
	tmp := t.TempDir()
	cid := "2222222222222222222222222222222222222222222222222222222222222222"
	var st ebpf.CgroupStats
	st.Counts[0] = 3

	sc := &strictCollector{
		eventsCh:     make(chan ebpf.KernelEvent, 8),
		stats:        map[uint64]ebpf.CgroupStats{9010: st},
		flushStarted: make(chan struct{}),
	}
	corr := docker.NewCorrelator(nil)
	corr.RecordDockerEvent(docker.DockerEvent{Action: "create", ID: cid, Image: "alpine:3.20"})
	corr.RecordKernelEvent(ebpf.KernelEvent{Type: ebpf.EventCgroupMkdir, CgroupID: 9010, CgroupPath: "/docker/" + cid})

	cfg := daemon.Config{
		ControlAddr:       filepath.Join(tmp, "sync.sock"),
		StoppedMarkerPath: filepath.Join(tmp, "sync.stopped"),
		OutputDir:         filepath.Join(tmp, "out"),
		RawDir:            filepath.Join(tmp, "raw"),
		LockFile:          filepath.Join(tmp, "lock.json"),
		BaselineMode:      baseline.ModeNone,
		RuntimeMode:       "none",
		Arch:              syscalls.ArchAMD64,
		OnChange:          "report",
		FailOn:            "high-risk",
		GeneratorVersion:  "test",
	}
	srv, err := daemon.NewServer(cfg, sc, corr)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Race STOP against immediate context cancellation while Flush() is active.
	stopDone := make(chan error, 1)
	go func() {
		_, err := daemon.Stop(srv.Addr(), cfg.StoppedMarkerPath)
		stopDone <- err
	}()
	<-sc.flushStarted
	cancel()

	if err := <-stopDone; err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	_ = srv.Wait()

	if sc.overlapErr.Load() {
		t.Fatal("collector.Close() overlapped active Stop() Flush/Detach/ErrorStats operations")
	}
	if got := sc.closeCount.Load(); got != 1 {
		t.Fatalf("expected collector.Close() to be called exactly once by daemon, got %d", got)
	}
}

package daemon

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/docker"
	"github.com/alexno10/seccomp-profiler/internal/ebpf"
)

func TestValidateConfig_GroupByAndLoopbackTCP(t *testing.T) {
	for _, badGroup := range []string{"compose_service", "label:", "pod"} {
		if err := ValidateConfig(Config{GroupBy: badGroup}); err == nil {
			t.Fatalf("expected invalid GroupBy %q to fail validation", badGroup)
		}
	}
	for _, goodGroup := range []string{"", "auto", "compose-service", "image", "label:app", "label:com.example/svc"} {
		if err := ValidateConfig(Config{GroupBy: goodGroup}); err != nil {
			t.Fatalf("expected valid GroupBy %q to pass, got %v", goodGroup, err)
		}
	}

	for _, badTCP := range []string{"tcp://0.0.0.0:8080", "tcp://[::]:8080", "tcp://:8080", "tcp://192.168.1.50:8080"} {
		if err := ValidateConfig(Config{ControlAddr: badTCP}); err == nil {
			t.Fatalf("expected non-loopback ControlAddr %q to be rejected", badTCP)
		}
	}
	for _, goodTCP := range []string{"tcp://127.0.0.1:0", "tcp://[::1]:0", "tcp://localhost:8080"} {
		if err := ValidateConfig(Config{ControlAddr: goodTCP}); err != nil {
			t.Fatalf("expected loopback ControlAddr %q to pass, got %v", goodTCP, err)
		}
	}
}

func TestStop_DialsLiveDaemonEvenWhenMarkerExists(t *testing.T) {
	tmp := t.TempDir()
	marker := filepath.Join(tmp, "stopped")
	if err := os.WriteFile(marker, []byte(`{"ok":true,"gatePassed":true,"gateReason":"stale"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	corr := docker.NewCorrelator(func(string) (uint64, error) { return 0, os.ErrNotExist })
	srv, err := NewServer(Config{
		ControlAddr: "tcp://127.0.0.1:0",
		OutputDir:   filepath.Join(tmp, "out"),
		RawDir:      filepath.Join(tmp, "raw"),
		LockFile:    filepath.Join(tmp, "lock.json"),
		// Deliberately leave StoppedMarkerPath empty so Start does not remove marker.
	}, nil, corr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- srv.Wait()
	}()

	resp, err := Stop(srv.Addr(), marker)
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if resp.GateReason == "stale" {
		t.Fatalf("Stop returned stale marker instead of dialing live daemon: %+v", resp)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("srv.Wait returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("live daemon was not stopped because stale marker short-circuited Stop()")
	}
}

type errStatsCollector struct{}

func (errStatsCollector) TrackCgroup(uint64) error        { return nil }
func (errStatsCollector) Events() <-chan ebpf.KernelEvent { return make(chan ebpf.KernelEvent) }
func (errStatsCollector) Flush() (map[uint64]ebpf.CgroupStats, error) {
	return map[uint64]ebpf.CgroupStats{}, nil
}
func (errStatsCollector) FlushCgroup(uint64) (ebpf.CgroupStats, bool, error) {
	return ebpf.CgroupStats{}, false, nil
}
func (errStatsCollector) DeleteCgroup(uint64) error { return nil }
func (errStatsCollector) ErrorStats() (ebpf.ErrorStats, error) {
	return ebpf.ErrorStats{RingbufDrops: 1}, nil
}
func (errStatsCollector) Detach() error { return nil }
func (errStatsCollector) Close() error  { return nil }

func TestExecuteStop_CaseInsensitiveFailOnNoneWithKernelErrors(t *testing.T) {
	tmp := t.TempDir()
	corr := docker.NewCorrelator(func(string) (uint64, error) { return 0, os.ErrNotExist })
	srv, err := NewServer(Config{
		ControlAddr: "tcp://127.0.0.1:0",
		OutputDir:   filepath.Join(tmp, "out"),
		RawDir:      filepath.Join(tmp, "raw"),
		LockFile:    filepath.Join(tmp, "lock.json"),
		FailOn:      "NONE",
	}, errStatsCollector{}, corr)
	if err != nil {
		t.Fatal(err)
	}
	resp := srv.executeStop()
	if !resp.OK || !resp.GatePassed {
		t.Fatalf("expected GatePassed=true when FailOn=NONE, got %+v", resp)
	}
}

func TestHandleConn_InvalidCommandValidJSONAndUnixSocketPerms(t *testing.T) {
	tmp := t.TempDir()
	corr := docker.NewCorrelator(func(string) (uint64, error) { return 0, os.ErrNotExist })
	srv, err := NewServer(Config{
		ControlAddr: "tcp://127.0.0.1:0",
		OutputDir:   filepath.Join(tmp, "out"),
		RawDir:      filepath.Join(tmp, "raw"),
		LockFile:    filepath.Join(tmp, "lock.json"),
	}, nil, corr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = srv.Wait()
	}()

	network, address := parseControlAddr(srv.Addr())
	conn, err := dialControl(network, address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("BAD\x07CMD\n"))
	var resp StopResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("expected valid JSON response for control-byte command, got decode err: %v", err)
	}
	if resp.OK || !strings.Contains(resp.Error, "unknown command") {
		t.Fatalf("unexpected response: %+v", resp)
	}

	if runtime.GOOS != "windows" {
		sockPath := filepath.Join(tmp, "ctl.sock")
		us, err := NewServer(Config{
			ControlAddr: sockPath,
			OutputDir:   filepath.Join(tmp, "out2"),
			RawDir:      filepath.Join(tmp, "raw2"),
			LockFile:    filepath.Join(tmp, "lock2.json"),
		}, nil, docker.NewCorrelator(func(string) (uint64, error) { return 0, os.ErrNotExist }))
		if err != nil {
			t.Fatal(err)
		}
		uctx, ucancel := context.WithCancel(context.Background())
		defer ucancel()
		if err := us.Start(uctx); err != nil {
			t.Fatal(err)
		}
		defer func() {
			ucancel()
			_ = us.Wait()
		}()
		fi, err := os.Stat(sockPath)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("expected unix socket mode 0600, got %o", fi.Mode().Perm())
		}
	}
	_ = net.ErrClosed
}

type testStopCollector struct {
	eventsCh chan ebpf.KernelEvent
	stats    map[uint64]ebpf.CgroupStats
}

func (c *testStopCollector) TrackCgroup(uint64) error        { return nil }
func (c *testStopCollector) Events() <-chan ebpf.KernelEvent { return c.eventsCh }
func (c *testStopCollector) Flush() (map[uint64]ebpf.CgroupStats, error) {
	return c.stats, nil
}
func (c *testStopCollector) FlushCgroup(id uint64) (ebpf.CgroupStats, bool, error) {
	st, ok := c.stats[id]
	return st, ok, nil
}
func (c *testStopCollector) DeleteCgroup(uint64) error            { return nil }
func (c *testStopCollector) ErrorStats() (ebpf.ErrorStats, error) { return ebpf.ErrorStats{}, nil }
func (c *testStopCollector) Detach() error                        { return nil }
func (c *testStopCollector) Close() error                         { return nil }

func TestExecuteStop_DeadContainerInEventsChDoesNotSelfDeadlock(t *testing.T) {
	tmp := t.TempDir()
	cid := strings.Repeat("d", 64)
	var st ebpf.CgroupStats
	st.Counts[0] = 7

	// Collector whose Events() stays open and holds an EventCgroupMkdir for an
	// already-dead container, which previously triggered ReclaimCgroup -> s.mu.Lock()
	// self-deadlock inside executeStop.
	mc := &testStopCollector{
		eventsCh: make(chan ebpf.KernelEvent, 8),
		stats:    map[uint64]ebpf.CgroupStats{7777: st},
	}
	corr := docker.NewCorrelator(func(string) (uint64, error) { return 0, os.ErrNotExist })
	corr.RecordDockerEvent(docker.DockerEvent{Action: "start", ID: cid, Image: "alpine:3.20", TimeNano: 100})
	corr.RecordDockerEvent(docker.DockerEvent{Action: "die", ID: cid, TimeNano: 200})
	corr.BindCgroup(7777, cid)
	mc.eventsCh <- ebpf.KernelEvent{Type: ebpf.EventCgroupMkdir, CgroupID: 7777, CgroupPath: "/docker/" + cid}

	srv, err := NewServer(Config{
		ControlAddr:       "tcp://127.0.0.1:0",
		StoppedMarkerPath: filepath.Join(tmp, "stopped"),
		OutputDir:         filepath.Join(tmp, "out"),
		RawDir:            filepath.Join(tmp, "raw"),
		LockFile:          filepath.Join(tmp, "lock.json"),
		BaselineMode:      "none",
		RuntimeMode:       "none",
		FailOn:            "none",
	}, mc, corr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = srv.Wait()
	}()

	start := time.Now()
	resp, err := Stop(srv.Addr(), filepath.Join(tmp, "stopped"))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected OK=true, got %+v", resp)
	}
	if elapsed > 1200*time.Millisecond {
		t.Fatalf("executeStop self-deadlocked draining eventsCh for dead container (elapsed %v)", elapsed)
	}
	if _, err := os.Stat(filepath.Join(tmp, "out", "alpine.json")); err != nil {
		t.Fatalf("expected alpine.json after draining eventsCh, err=%v", err)
	}
}

func TestExecuteStop_DriftDetectedBeforeWriteTargetFilesAndUpdatePrSkipsOnGateFailure(t *testing.T) {
	tmp := t.TempDir()
	baseDir := filepath.Join(tmp, "base")
	workDir := filepath.Join(tmp, "work")
	rawDir := filepath.Join(tmp, "raw")
	_ = os.MkdirAll(baseDir, 0o755)
	_ = os.MkdirAll(workDir, 0o755)

	baseJSON := []byte(`{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64"],"syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}`)
	tamperedWorkJSON := []byte(`{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64"],"syscalls":[{"names":["read","mount"],"action":"SCMP_ACT_ALLOW"}]}`)
	if err := os.WriteFile(filepath.Join(baseDir, "alpine.json"), baseJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "alpine.json"), tamperedWorkJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	cid := strings.Repeat("a", 64)
	var st ebpf.CgroupStats
	st.Counts[0] = 1 // read
	mc := &testStopCollector{
		eventsCh: make(chan ebpf.KernelEvent, 4),
		stats:    map[uint64]ebpf.CgroupStats{8888: st},
	}
	close(mc.eventsCh)
	corr := docker.NewCorrelator(func(string) (uint64, error) { return 0, os.ErrNotExist })
	corr.RecordDockerEvent(docker.DockerEvent{Action: "create", ID: cid, Image: "alpine:3.20"})
	corr.RecordKernelEvent(ebpf.KernelEvent{Type: ebpf.EventCgroupMkdir, CgroupID: 8888, CgroupPath: "/docker/" + cid})

	// Test 1: OutputDir == WorkingCommitted, and workDir was tampered relative to baseDir.
	// Drift MUST still be reported even though WriteTargetFiles runs during STOP.
	srv, err := NewServer(Config{
		ControlAddr:       "tcp://127.0.0.1:0",
		StoppedMarkerPath: filepath.Join(tmp, "stopped1"),
		OutputDir:         workDir,
		RawDir:            rawDir,
		LockFile:          filepath.Join(tmp, "lock.json"),
		CommittedProfile:  filepath.Join(baseDir, "{name}.json"),
		WorkingCommitted:  filepath.Join(workDir, "{name}.json"),
		BaselineMode:      "none",
		RuntimeMode:       "none",
		OnChange:          "report",
		FailOn:            "high-risk",
	}, mc, corr)
	if err != nil {
		t.Fatal(err)
	}
	resp := srv.executeStop()
	if !resp.OK {
		t.Fatalf("unexpected executeStop error: %+v", resp)
	}
	if !strings.Contains(resp.MarkdownSummary, "differs from") {
		t.Fatalf("expected PR drift warning before WriteTargetFiles overwrites workDir, got summary:\n%s", resp.MarkdownSummary)
	}

	// Test 2: update-pr MUST NOT call SyncCommittedProfiles when security gate fails.
	workComm2 := filepath.Join(tmp, "committed-work")
	out2 := filepath.Join(tmp, "out2")
	_ = os.MkdirAll(workComm2, 0o755)
	if err := os.WriteFile(filepath.Join(workComm2, "alpine.json"), baseJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	var stHigh ebpf.CgroupStats
	stHigh.Counts[0] = 1
	stHigh.Counts[101] = 1 // amd64 ptrace
	mc2 := &testStopCollector{
		eventsCh: make(chan ebpf.KernelEvent, 4),
		stats:    map[uint64]ebpf.CgroupStats{8889: stHigh},
	}
	close(mc2.eventsCh)
	corr2 := docker.NewCorrelator(func(string) (uint64, error) { return 0, os.ErrNotExist })
	corr2.RecordDockerEvent(docker.DockerEvent{Action: "create", ID: cid, Image: "alpine:3.20"})
	corr2.RecordKernelEvent(ebpf.KernelEvent{Type: ebpf.EventCgroupMkdir, CgroupID: 8889, CgroupPath: "/docker/" + cid})

	srv2, err := NewServer(Config{
		ControlAddr:       "tcp://127.0.0.1:0",
		StoppedMarkerPath: filepath.Join(tmp, "stopped2"),
		OutputDir:         out2,
		RawDir:            filepath.Join(tmp, "raw2"),
		LockFile:          filepath.Join(tmp, "lock2.json"),
		CommittedProfile:  filepath.Join(baseDir, "{name}.json"),
		WorkingCommitted:  filepath.Join(workComm2, "{name}.json"),
		BaselineMode:      "none",
		RuntimeMode:       "none",
		OnChange:          "update-pr",
		FailOn:            "high-risk",
	}, mc2, corr2)
	if err != nil {
		t.Fatal(err)
	}
	resp2 := srv2.executeStop()
	if resp2.GatePassed {
		t.Fatalf("expected gate failure on unapproved ptrace")
	}
	afterWork2, _ := os.ReadFile(filepath.Join(workComm2, "alpine.json"))
	if string(afterWork2) != string(baseJSON) {
		t.Fatalf("update-pr must not update WorkingCommitted when gate fails: %s", afterWork2)
	}
	if _, statErr := os.Stat(filepath.Join(workComm2, "alpine.suggested.json")); !os.IsNotExist(statErr) {
		t.Fatalf("did not expect SyncCommittedProfiles to write into WorkingCommitted when gate fails")
	}
}

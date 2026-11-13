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

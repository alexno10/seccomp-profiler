package docker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/ebpf"
)

func TestExtractContainerID_DinDNestedPaths(t *testing.T) {
	outer := strings.Repeat("a", 64)
	inner := strings.Repeat("b", 64)

	cases := []struct {
		name   string
		path   string
		wantID string
		wantOK bool
	}{
		{
			name:   "nested systemd scope then docker dir",
			path:   "/system.slice/docker-" + outer + ".scope/docker/" + inner,
			wantID: inner,
			wantOK: true,
		},
		{
			name:   "nested docker dir then scope",
			path:   "/docker/" + outer + "/docker-" + inner + ".scope",
			wantID: inner,
			wantOK: true,
		},
		{
			name:   "uppercase nested normalized to lowercase",
			path:   "/docker/" + strings.ToUpper(outer) + "/docker-" + strings.ToUpper(inner) + ".scope",
			wantID: inner,
			wantOK: true,
		},
		{
			name:   "overlong 128-hex hash is not container id",
			path:   "/system.slice/" + strings.Repeat("c", 128) + ".scope",
			wantID: "",
			wantOK: false,
		},
		{
			name:   "no hex64 id",
			path:   "/system.slice/nginx.service",
			wantID: "",
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ExtractContainerID(tc.path)
			if ok != tc.wantOK || got != tc.wantID {
				t.Fatalf("ExtractContainerID(%q) = (%q, %v), want (%q, %v)", tc.path, got, ok, tc.wantID, tc.wantOK)
			}
		})
	}
}

func TestResolveContainerCgroupInodeFromProc(t *testing.T) {
	cid := strings.Repeat("d", 64)
	tmp := t.TempDir()
	cgRoot := filepath.Join(tmp, "cgroup")

	// Create candidate target directories inside fake cgroupfs.
	v1Dir := filepath.Join(cgRoot, "user.slice")
	v2Dir := filepath.Join(cgRoot, "system.slice", "docker-"+cid+".scope")
	dindDir := filepath.Join(cgRoot, "docker", strings.Repeat("a", 64), "docker-"+cid+".scope")
	for _, d := range []string{cgRoot, v1Dir, v2Dir, dindDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	inodes := map[string]uint64{
		filepath.Clean(cgRoot):  1,
		filepath.Clean(v1Dir):   100,
		filepath.Clean(v2Dir):   200,
		filepath.Clean(dindDir): 300,
	}
	fakeStat := func(p string) (uint64, error) {
		if _, err := os.Stat(p); err != nil {
			return 0, err
		}
		if ino, ok := inodes[filepath.Clean(p)]; ok {
			return ino, nil
		}
		return 0, os.ErrNotExist
	}

	t.Run("prioritizes unified v2 over v1 and ignores root slash", func(t *testing.T) {
		procData := []byte("12:pids:/\n11:memory:/user.slice\n0::/system.slice/docker-" + cid + ".scope\n")
		ino, err := resolveContainerCgroupInodeFromProc(cgRoot, procData, cid, fakeStat)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ino != 200 {
			t.Fatalf("got inode %d, want 200 (unified v2 matching containerID)", ino)
		}
	})

	t.Run("rejects root slash cgroup", func(t *testing.T) {
		procData := []byte("0::/\n")
		_, err := resolveContainerCgroupInodeFromProc(cgRoot, procData, cid, fakeStat)
		if err == nil {
			t.Fatalf("expected error for root '/' cgroup path, got nil")
		}
	})

	t.Run("rejects unrelated host PID cgroup lacking containerID", func(t *testing.T) {
		procData := []byte("0::/user.slice\n")
		_, err := resolveContainerCgroupInodeFromProc(cgRoot, procData, cid, fakeStat)
		if err == nil {
			t.Fatalf("expected error for unrelated cgroup path lacking containerID, got nil")
		}
	})

	t.Run("finds nested DinD cgroup via fallback walk when candidates and proc fail", func(t *testing.T) {
		// Remove top-level v2Dir so candidate/proc fail, leaving nested dindDir.
		_ = os.RemoveAll(v2Dir)
		ino, err := resolveContainerCgroupInode(
			context.Background(),
			cgRoot,
			filepath.Join(tmp, "proc"),
			cid,
			func(context.Context, string) (string, error) { return "999999", nil },
			fakeStat,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ino != 300 {
			t.Fatalf("got inode %d, want 300 from nested DinD cgroup", ino)
		}
	})

	t.Run("respects context timeout for wedged docker inspect", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := resolveContainerCgroupInode(
			ctx,
			filepath.Join(tmp, "empty-cgroup"),
			filepath.Join(tmp, "proc"),
			cid,
			func(callCtx context.Context, _ string) (string, error) {
				<-callCtx.Done()
				return "", callCtx.Err()
			},
			fakeStat,
		)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected DeadlineExceeded, got %v", err)
		}
	})
}

func TestReadDockerEventStream_ErrorsAndLargeLines(t *testing.T) {
	t.Run("propagates wait error with stderr detail", func(t *testing.T) {
		r := strings.NewReader("")
		wantErr := errors.New("docker daemon unavailable")
		err := readDockerEventStream(context.Background(), r, func(DockerEvent) {}, func() error {
			return wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected %v, got %v", wantErr, err)
		}
	})

	t.Run("handles event lines larger than 64KiB", func(t *testing.T) {
		cid := strings.Repeat("e", 64)
		bigLabel := strings.Repeat("x", 96*1024)
		line := `{"status":"start","id":"` + cid + `","timeNano":123,"Actor":{"ID":"` + cid + `","Attributes":{"image":"alpine","name":"big","huge":"` + bigLabel + `"}}}` + "\n"
		var got []DockerEvent
		err := readDockerEventStream(context.Background(), strings.NewReader(line), func(ev DockerEvent) {
			got = append(got, ev)
		}, func() error { return nil })
		if err != nil {
			t.Fatalf("unexpected error on >64KiB event line: %v", err)
		}
		if len(got) != 1 || got[0].ID != cid {
			t.Fatalf("got events %+v, want 1 event for %s", got, cid)
		}
	})

	t.Run("skips >1MiB lines without breaking stream", func(t *testing.T) {
		cid := strings.Repeat("f", 64)
		huge := `{"status":"start","id":"bad","huge":"` + strings.Repeat("a", 1200*1024) + `"}` + "\n"
		good := `{"status":"start","id":"` + cid + `","timeNano":456,"Actor":{"ID":"` + cid + `","Attributes":{"image":"alpine"}}}` + "\n"
		var got []DockerEvent
		err := readDockerEventStream(context.Background(), strings.NewReader(huge+good), func(ev DockerEvent) {
			got = append(got, ev)
		}, func() error { return nil })
		if err != nil {
			t.Fatalf("expected >1MiB line to be skipped cleanly, got err=%v", err)
		}
		if len(got) != 1 || got[0].ID != cid {
			t.Fatalf("expected subsequent event %s after oversized line, got %+v", cid, got)
		}
	})

	t.Run("cancels child before waitFn on reader error", func(t *testing.T) {
		canceled := false
		pr, pw := newErrReader(errors.New("broken stream"))
		_ = pw
		err := readDockerEventStreamWithCancel(
			context.Background(),
			pr,
			func(DockerEvent) {},
			func() { canceled = true },
			func() error {
				if !canceled {
					return errors.New("waitFn ran before cancelFn")
				}
				return nil
			},
		)
		if err == nil || !canceled {
			t.Fatalf("expected read error with cancelFn called first, got err=%v canceled=%v", err, canceled)
		}
	})
}

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

func newErrReader(err error) (failingReader, struct{}) {
	return failingReader{err: err}, struct{}{}
}

func TestScanRunningContainers_ToleratesVanishedContainerInBatch(t *testing.T) {
	cid1 := strings.Repeat("1", 64)
	cid2 := strings.Repeat("2", 64)

	runCmd := func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "ps" {
			return []byte(cid1 + "\n" + cid2 + "\n"), nil
		}
		if len(args) > 0 && args[0] == "inspect" {
			// Batch inspect (more than 1 ID after "--") fails because cid2 vanished.
			idCount := 0
			for _, a := range args[1:] {
				if len(a) == 64 {
					idCount++
				}
			}
			if idCount > 1 {
				return nil, errors.New("Error response from daemon: No such object: " + cid2)
			}
			if args[len(args)-1] == cid2 {
				return nil, errors.New("Error response from daemon: No such object: " + cid2)
			}
			return []byte(`[{"Id":"` + cid1 + `","Name":"/web","Config":{"Image":"nginx:alpine","Labels":{"app":"web"}},"State":{"Pid":0}}]`), nil
		}
		return nil, errors.New("unexpected command")
	}

	evs, _, err := scanRunningContainersWithRunner(context.Background(), runCmd, func(string) (uint64, error) {
		return 0, os.ErrNotExist
	})
	if err != nil {
		t.Fatalf("expected vanished container fallback to succeed, got %v", err)
	}
	if len(evs) != 1 || evs[0].ID != cid1 {
		t.Fatalf("expected 1 running event for %s, got %+v", cid1, evs)
	}
}

func TestStaleDieReplayAndDeadStatsCoalesceAndBinsCap(t *testing.T) {
	cid := strings.Repeat("c", 64)
	corr := NewCorrelator(func(string) (uint64, error) { return 0, os.ErrNotExist })

	// 1. Stale die replay before restarted startNano must NOT mark container dead.
	corr.RecordDockerEvent(DockerEvent{Action: "start", ID: cid, Image: "alpine:3.20", TimeNano: 2000})
	corr.RecordDockerEvent(DockerEvent{Action: "die", ID: cid, TimeNano: 1000})
	if corr.IsContainerDead(cid) {
		t.Fatal("stale replayed die event (timeNano < startNano) must not mark restarted container dead")
	}

	// 2. Empty live map entry must not clobber deadStats snapshot.
	corr.BindCgroup(5001, cid)
	var dead ebpf.CgroupStats
	dead.Counts[0] = 17
	dead.CompatCount = 3
	corr.RecordDeadStats(5001, dead)
	recs := corr.BuildRecords(map[uint64]ebpf.CgroupStats{5001: {}})
	if len(recs) != 1 || recs[0].SyscallHits[0] != 17 || recs[0].CompatHits != 3 {
		t.Fatalf("expected empty live entry not to clobber deadStats, got %+v", recs)
	}

	// 3. cgroupBins must deduplicate and cap at maxBinsPerCgroup (256).
	for i := 0; i < 400; i++ {
		corr.RecordKernelEvent(ebpf.KernelEvent{
			Type:         ebpf.EventExec,
			CgroupID:     5001,
			ExecFilename: "/bin/tool-" + string(rune('a'+(i%26))) + "-" + string(rune('a'+((i/26)%26))),
		})
	}
	recsCap := corr.BuildRecords(map[uint64]ebpf.CgroupStats{5001: {}})
	if len(recsCap[0].ExecutedBins) > maxBinsPerCgroup {
		t.Fatalf("expected executed bins capped at %d, got %d", maxBinsPerCgroup, len(recsCap[0].ExecutedBins))
	}
}

func TestAsyncResolverDoesNotBlockRecordDockerEventAndExitErrorStderr(t *testing.T) {
	cid := strings.Repeat("9", 64)
	release := make(chan struct{})
	corr := NewCorrelator(func(id string) (uint64, error) {
		<-release
		return 8844, nil
	})
	done := make(chan struct{})
	go func() {
		corr.RecordDockerEvent(DockerEvent{Action: "start", ID: cid, Image: "alpine:3.20", TimeNano: 10})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("RecordDockerEvent blocked on slow InodeResolver")
	}
	close(release)
	corr.WaitResolutions(time.Second)
	if cgs := corr.CgroupsForContainer(cid); len(cgs) != 1 || cgs[0] != 8844 {
		t.Fatalf("expected async resolver to bind 8844, got %v", cgs)
	}

	// I13: Real *exec.ExitError carries "No such object" in Stderr while Error() is "exit status 1".
	cmd := exec.Command("go", "version")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "echo Error: No such object: deadbeef 1>&2 && exit 1")
	} else {
		cmd = exec.Command("sh", "-c", "echo 'Error: No such object: deadbeef' >&2; exit 1")
	}
	_, err := cmd.Output()
	if err == nil || !isContainerNotFoundErr(err) {
		t.Fatalf("expected isContainerNotFoundErr to inspect ExitError.Stderr, got err=%v", err)
	}
}

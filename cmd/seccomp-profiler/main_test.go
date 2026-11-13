package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/docker"
	"github.com/alexno10/seccomp-profiler/internal/ebpf"
	"github.com/alexno10/seccomp-profiler/internal/profile"
)

func TestRunMergeSupportsPruneWorkingCommittedAndUpdatePr(t *testing.T) {
	tmp := t.TempDir()
	shardDir := filepath.Join(tmp, "shards")
	outDir := filepath.Join(tmp, "out")
	rawDir := filepath.Join(tmp, "raw")
	commDir := filepath.Join(tmp, "committed")
	if err := os.MkdirAll(shardDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(commDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write committed profile with read + obsolete chmod.
	commProfile := profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls:      []profile.OCISyscallRule{{Names: []string{"read", "chmod"}, Action: "SCMP_ACT_ALLOW"}},
	}
	commBytes, _ := json.MarshalIndent(commProfile, "", "  ")
	if err := os.WriteFile(filepath.Join(commDir, "api.json"), commBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	// Shard only observes read.
	shard := profile.RawProfileV1{
		SchemaVersion: "v1",
		Host:          profile.RawHostInfo{Arch: "amd64", SeccompArch: "SCMP_ARCH_X86_64"},
		Target:        profile.RawTargetInfo{Name: "api", GroupBy: "image", ContainerCount: 1},
		Syscalls: map[string]profile.RawSyscallEntry{
			"read": {Sources: []string{"observed"}, TotalCalls: 10, ContainersSeen: 1},
		},
	}
	shardBytes, _ := json.MarshalIndent(shard, "", "  ")
	if err := os.WriteFile(filepath.Join(shardDir, "api.profile.v1.json"), shardBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	lockPath := filepath.Join(tmp, "lock.json")
	sum := sha256.Sum256(commBytes)
	commSum := hex.EncodeToString(sum[:])
	if err := os.WriteFile(lockPath, []byte(`{"files":{"api":"`+commSum+`"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	err := runMerge([]string{
		"--input-dir", shardDir,
		"--output-dir", outDir,
		"--raw-dir", rawDir,
		"--lock-file", lockPath,
		"--committed-profile", filepath.Join(commDir, "{name}.json"),
		"--working-committed-profile", filepath.Join(commDir, "{name}.json"),
		"--allow-file", filepath.Join(tmp, "missing-accepted.yml"),
		"--on-change", "update-pr",
		"--prune",
	})
	if err != nil {
		t.Fatalf("runMerge failed: %v", err)
	}

	mergedCommitted, err := os.ReadFile(filepath.Join(commDir, "api.json"))
	if err != nil {
		t.Fatalf("read updated committed profile: %v", err)
	}
	if strings.Contains(string(mergedCommitted), `"chmod"`) {
		t.Fatalf("expected --prune in runMerge to remove chmod, got:\n%s", mergedCommitted)
	}
	if !strings.Contains(string(mergedCommitted), `"read"`) {
		t.Fatalf("expected read in updated committed profile, got:\n%s", mergedCommitted)
	}
}

func TestStartDockerEventWatcherWaitsForInFlightHandlerOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var handlerDone atomic.Bool
	handlerStarted := make(chan struct{})

	streamFn := func(ctx context.Context, onEvent func(docker.DockerEvent)) error {
		onEvent(docker.DockerEvent{Action: "die", ID: "abc"})
		<-ctx.Done()
		return ctx.Err()
	}
	handle := func(ev docker.DockerEvent) {
		close(handlerStarted)
		time.Sleep(25 * time.Millisecond)
		handlerDone.Store(true)
	}

	startDockerEventWatcher(ctx, &wg, streamFn, handle)
	<-handlerStarted
	cancel()
	wg.Wait()

	if !handlerDone.Load() {
		t.Fatal("wg.Wait() returned before in-flight docker event handler completed")
	}
}

type fakeCollector struct {
	mu      sync.Mutex
	stats   map[uint64]ebpf.CgroupStats
	deleted []uint64
}

func (f *fakeCollector) TrackCgroup(uint64) error        { return nil }
func (f *fakeCollector) Events() <-chan ebpf.KernelEvent { return nil }
func (f *fakeCollector) ErrorStats() (ebpf.ErrorStats, error) {
	return ebpf.ErrorStats{}, nil
}
func (f *fakeCollector) Detach() error { return nil }
func (f *fakeCollector) Close() error  { return nil }

func (f *fakeCollector) Flush() (map[uint64]ebpf.CgroupStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[uint64]ebpf.CgroupStats, len(f.stats))
	for k, v := range f.stats {
		out[k] = v
	}
	return out, nil
}

func (f *fakeCollector) FlushCgroup(cgID uint64) (ebpf.CgroupStats, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.stats[cgID]
	return st, ok, nil
}

func (f *fakeCollector) DeleteCgroup(cgID uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.stats, cgID)
	f.deleted = append(f.deleted, cgID)
	return nil
}

func (f *fakeCollector) wasDeleted(cgID uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range f.deleted {
		if id == cgID {
			return true
		}
	}
	return false
}

func TestDieBeforeKernelCgroupMkdirReclaimsBPFMap(t *testing.T) {
	cid := strings.Repeat("f", 64)
	corr := docker.NewCorrelator(func(string) (uint64, error) { return 0, os.ErrNotExist })

	var st ebpf.CgroupStats
	st.Counts[0] = 5
	fc := &fakeCollector{stats: map[uint64]ebpf.CgroupStats{42: st}}

	// Container exits (<100ms) and docker "die" arrives before ringbuf delivers EVENT_CGROUP_MKDIR.
	handleDockerContainerEvent(docker.DockerEvent{
		Action:   "start",
		ID:       cid,
		Image:    "alpine:3.20",
		Name:     "short",
		TimeNano: 100,
	}, corr, fc)
	handleDockerContainerEvent(docker.DockerEvent{
		Action:   "die",
		ID:       cid,
		TimeNano: 200,
	}, corr, fc)

	// Delayed ringbuf event arrives afterwards.
	handleKernelCollectorEvent(ebpf.KernelEvent{
		Type:       ebpf.EventCgroupMkdir,
		CgroupID:   42,
		CgroupPath: "/docker/" + cid,
	}, corr, fc)

	if !fc.wasDeleted(42) {
		t.Fatal("expected cgroup 42 to be flushed and deleted from BPF maps when delayed EventCgroupMkdir arrives after die")
	}
	liveStats, _ := fc.Flush()
	records := corr.BuildRecords(liveStats)
	if len(records) != 1 || records[0].SyscallHits[0] != 5 {
		t.Fatalf("expected flushed stats preserved in BuildRecords after reclaim, got %+v", records)
	}
}

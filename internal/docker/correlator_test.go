package docker_test

import (
	"os"
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/docker"
	"github.com/alexno10/seccomp-profiler/internal/ebpf"
)

func TestCorrelatorShortLivedContainerFallback(t *testing.T) {
	containerID := "e6bc6e0298901234567890abcdef1234567890abcdef1234567890abcdef1234"
	// Simulate ENOENT when userspace tries to stat the cgroup of a <100ms --rm container.
	corr := docker.NewCorrelator(func(id string) (uint64, error) {
		return 0, os.ErrNotExist
	})

	corr.RecordDockerEvent(docker.DockerEvent{
		Action:   "create",
		ID:       containerID,
		Image:    "alpine:3.20",
		Name:     "short_lived_true",
		Labels:   map[string]string{"com.docker.compose.service": "runner"},
		TimeNano: 1000_000_000,
	})
	corr.RecordDockerEvent(docker.DockerEvent{
		Action:   "start",
		ID:       containerID,
		Image:    "alpine:3.20",
		TimeNano: 1010_000_000,
	})
	corr.RecordDockerEvent(docker.DockerEvent{
		Action:   "die",
		ID:       containerID,
		TimeNano: 1055_000_000, // 45ms duration
	})

	// Kernel ringbuf events arrive with cgroup_id 778899 and path containing the 64-hex container ID.
	corr.RecordKernelEvent(ebpf.KernelEvent{
		Type:       ebpf.EventCgroupMkdir,
		CgroupID:   778899,
		CgroupPath: "/system.slice/docker-" + containerID + ".scope",
	})
	corr.RecordKernelEvent(ebpf.KernelEvent{
		Type:         ebpf.EventExec,
		CgroupID:     778899,
		ExecFilename: "/bin/true",
	})

	var stats ebpf.CgroupStats
	stats.Counts[0] = 3  // read
	stats.Counts[59] = 1 // execve

	records := corr.BuildRecords(map[uint64]ebpf.CgroupStats{
		778899: stats,
	})
	if len(records) != 1 {
		t.Fatalf("expected 1 correlated ContainerRecord, got %d", len(records))
	}
	r := records[0]
	if r.ID != containerID || r.Image != "alpine:3.20" {
		t.Fatalf("unexpected container identity: %+v", r)
	}
	if len(r.ExecutedBins) != 1 || r.ExecutedBins[0] != "/bin/true" {
		t.Fatalf("expected ExecutedBins=[/bin/true], got %v", r.ExecutedBins)
	}
	if r.SyscallHits[0] != 3 || r.SyscallHits[59] != 1 {
		t.Fatalf("unexpected SyscallHits: %v", r.SyscallHits)
	}
	if r.DurationMs != 45 {
		t.Fatalf("expected DurationMs=45, got %d", r.DurationMs)
	}
}

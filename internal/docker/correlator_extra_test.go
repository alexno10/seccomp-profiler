package docker_test

import (
	"os"
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/docker"
	"github.com/alexno10/seccomp-profiler/internal/ebpf"
)

var errNotFound = os.ErrNotExist

// Review Low: ephemeral Docker event attributes (exitCode, execID, signal)
// must not pollute container labels / raw artifacts.
func TestEphemeralEventAttributesAreDropped(t *testing.T) {
	line := []byte(`{"Action":"die","Actor":{"ID":"abc","Attributes":{"image":"alpine:3.20","name":"x","exitCode":"137","execID":"e1","signal":"SIGKILL","com.docker.compose.service":"api"}}}`)
	ev, err := docker.ParseDockerEventJSON(line)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ev.Labels["exitCode"]; ok {
		t.Fatal("exitCode leaked into labels")
	}
	if _, ok := ev.Labels["execID"]; ok {
		t.Fatal("execID leaked into labels")
	}
	if _, ok := ev.Labels["signal"]; ok {
		t.Fatal("signal leaked into labels")
	}
	if ev.Labels["com.docker.compose.service"] != "api" {
		t.Fatalf("real labels must survive: %+v", ev.Labels)
	}
}

// Review item 4: stats of dead containers survive BPF map cleanup and are
// merged into the final records.
func TestDeadStatsSurviveMapCleanup(t *testing.T) {
	cid := "e6bc6e0298901234567890abcdef1234567890abcdef1234567890abcdef1234"
	corr := docker.NewCorrelator(func(id string) (uint64, error) { return 0, errNotFound })

	corr.RecordDockerEvent(docker.DockerEvent{Action: "create", ID: cid, Image: "alpine:3.20"})
	corr.RecordKernelEvent(ebpf.KernelEvent{
		Type:       ebpf.EventCgroupMkdir,
		CgroupID:   4242,
		CgroupPath: "/docker/" + cid,
	})

	var st ebpf.CgroupStats
	st.Counts[0] = 9
	corr.RecordDeadStats(4242, st)

	// The daemon flushed + deleted the live entry before Stop.
	records := corr.BuildRecords(map[uint64]ebpf.CgroupStats{})
	if len(records) != 1 {
		t.Fatalf("expected dead container to still be recorded, got %d", len(records))
	}
	if records[0].SyscallHits[0] != 9 {
		t.Fatalf("expected hits=9 from dead stats, got %+v", records[0].SyscallHits)
	}
	if len(corr.CgroupsForContainer(cid)) != 1 {
		t.Fatal("expected cgroup binding lookup for die-cleanup")
	}

	// Double counting must be impossible: live entry wins over dead snapshot.
	records2 := corr.BuildRecords(map[uint64]ebpf.CgroupStats{4242: st})
	if records2[0].SyscallHits[0] != 9 {
		t.Fatalf("live+dead double count: %+v", records2[0].SyscallHits)
	}
}

// Review item 20: pre-existing containers carry the partial flag end-to-end.
func TestPreexistingContainersAreFlagged(t *testing.T) {
	cid := "1111111111111111111111111111111111111111111111111111111111111111"
	corr := docker.NewCorrelator(func(id string) (uint64, error) { return 0, errNotFound })
	corr.RecordDockerEvent(docker.DockerEvent{
		Action:      "start",
		ID:          cid,
		Image:       "alpine:3.20",
		Preexisting: true,
	})
	corr.RecordKernelEvent(ebpf.KernelEvent{
		Type:       ebpf.EventCgroupMkdir,
		CgroupID:   7,
		CgroupPath: "/docker/" + cid,
	})
	records := corr.BuildRecords(map[uint64]ebpf.CgroupStats{7: {}})
	if len(records) != 1 || !records[0].Preexisting {
		t.Fatalf("expected preexisting flag, got %+v", records)
	}
}

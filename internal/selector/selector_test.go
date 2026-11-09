package selector_test

import (
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/selector"
)

func TestNormalizeImageName(t *testing.T) {
	got := selector.NormalizeImageName("localhost:5000/myorg/payment-api:v1.2.3@sha256:abcdef0123456789")
	if got != "payment-api" {
		t.Fatalf("expected payment-api, got %q", got)
	}
	if got2 := selector.NormalizeImageName("localhost:5000/redis@sha256:12345"); got2 != "redis" {
		t.Fatalf("expected redis, got %q", got2)
	}
}

func TestBuiltInExclusionsAndZeroConfigGrouping(t *testing.T) {
	containers := []selector.ContainerRecord{
		{
			ID:          "111",
			Image:       "testcontainers/ryuk:0.5.1",
			SyscallHits: map[int]uint32{0: 10},
		},
		{
			ID:          "222",
			Image:       "moby/buildkit:latest",
			SyscallHits: map[int]uint32{1: 5},
		},
		{
			ID:           "333",
			Image:        "myorg/app:test1",
			ExecutedBins: []string{"/app/server"},
			SyscallHits:  map[int]uint32{0: 100, 1: 50},
		},
		{
			ID:           "444",
			Image:        "myorg/app:test2",
			ExecutedBins: []string{"/bin/sh"},
			SyscallHits:  map[int]uint32{0: 200, 39: 1},
		},
		{
			ID:          "555",
			Image:       "postgres:16",
			Labels:      map[string]string{"com.docker.compose.service": "db"},
			SyscallHits: map[int]uint32{0: 10},
		},
	}

	targets, skipped := selector.Evaluate(selector.Config{GroupBy: "auto"}, containers)
	if len(skipped) != 2 {
		t.Fatalf("expected 2 skipped infra containers, got %d", len(skipped))
	}
	for _, s := range skipped {
		if s.Reason != "excluded-default" {
			t.Fatalf("expected reason excluded-default, got %q", s.Reason)
		}
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets (app, db), got %d", len(targets))
	}
	if targets[0].Name != "app" || targets[1].Name != "db" {
		t.Fatalf("expected sorted targets [app, db], got [%s, %s]", targets[0].Name, targets[1].Name)
	}
	app := targets[0]
	if len(app.Containers) != 2 {
		t.Fatalf("expected 2 containers in app, got %d", len(app.Containers))
	}
	if app.MergedHits[0] != 300 || app.ContainersPerSyscall[0] != 2 {
		t.Fatalf("expected syscall 0 hits=300 containers=2, got hits=%d containers=%d", app.MergedHits[0], app.ContainersPerSyscall[0])
	}
	if app.MergedHits[39] != 1 || app.ContainersPerSyscall[39] != 1 {
		t.Fatalf("expected syscall 39 hits=1 containers=1, got hits=%d containers=%d", app.MergedHits[39], app.ContainersPerSyscall[39])
	}
	if targets[1].GroupBy != "compose-service" {
		t.Fatalf("expected db GroupBy=compose-service, got %q", targets[1].GroupBy)
	}
}

func TestExplicitSelectorsMergeAndUnmatched(t *testing.T) {
	cfg := selector.Config{
		Rules: []selector.TargetRule{
			{Name: "backend", ImageGlob: "myorg/api:*", Labels: map[string]string{"tier": "backend"}},
			{Name: "backend", ImageGlob: "myorg/worker:*"},
		},
	}
	containers := []selector.ContainerRecord{
		{
			ID:          "c1",
			Image:       "myorg/api:v1",
			Labels:      map[string]string{"tier": "backend", "env": "ci"},
			SyscallHits: map[int]uint32{0: 10},
		},
		{
			ID:          "c2",
			Image:       "myorg/worker:v1",
			SyscallHits: map[int]uint32{1: 20},
		},
		{
			ID:          "c3",
			Image:       "redis:7",
			SyscallHits: map[int]uint32{0: 5},
		},
	}

	targets, skipped := selector.Evaluate(cfg, containers)
	if len(targets) != 1 || targets[0].Name != "backend" || len(targets[0].Containers) != 2 {
		t.Fatalf("expected 1 merged backend target with 2 containers, got %+v", targets)
	}
	if len(skipped) != 1 || skipped[0].ID != "c3" || skipped[0].Reason != "unmatched-selector" {
		t.Fatalf("expected c3 skipped with unmatched-selector, got %+v", skipped)
	}
}

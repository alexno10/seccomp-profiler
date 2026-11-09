package selector_test

import (
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/selector"
)

func makeRec(id, image string, labels map[string]string) selector.ContainerRecord {
	return selector.ContainerRecord{
		ID:          id,
		Image:       image,
		Labels:      labels,
		SyscallHits: map[int]uint32{0: 1},
	}
}

// Review item 5: target names derived from labels must never traverse paths.
func TestLabelTraversalIsSkipped(t *testing.T) {
	evil := makeRec("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "alpine:3.20",
		map[string]string{"com.docker.compose.service": "../../../etc/evil"})
	targets, skipped := selector.Evaluate(selector.Config{GroupBy: "auto"}, []selector.ContainerRecord{evil})
	if len(targets) != 0 {
		t.Fatalf("expected no targets for traversal label, got %+v", targets)
	}
	if len(skipped) != 1 || skipped[0].Reason != "invalid-target-name" {
		t.Fatalf("expected invalid-target-name skip, got %+v", skipped)
	}
}

// Image-ID-only references must not all collapse into a target named "sha256".
func TestSha256ImageFallsBackToContainerID(t *testing.T) {
	rec := makeRec("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "sha256:deadbeef", nil)
	targets, _ := selector.Evaluate(selector.Config{GroupBy: "auto"}, []selector.ContainerRecord{rec})
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Name != "abcdef123456" {
		t.Fatalf("expected container ID fallback name, got %q", targets[0].Name)
	}
}

// Review item 20: compose-project filter limits profiling to one project.
func TestComposeProjectFilter(t *testing.T) {
	in := makeRec("1", "alpine", map[string]string{"com.docker.compose.project": "projA"})
	out := makeRec("2", "alpine", map[string]string{"com.docker.compose.project": "projB"})
	noLabel := makeRec("3", "alpine", nil)

	targets, skipped := selector.Evaluate(selector.Config{ComposeProject: "projA"}, []selector.ContainerRecord{in, out, noLabel})
	if len(targets) != 1 || len(targets[0].Containers) != 1 {
		t.Fatalf("expected only projA container, got %+v", targets)
	}
	if len(skipped) != 2 {
		t.Fatalf("expected 2 skipped, got %+v", skipped)
	}
	for _, s := range skipped {
		if s.Reason != "compose-project-mismatch" {
			t.Fatalf("unexpected reason %q", s.Reason)
		}
	}
}

func FuzzParseTargetsInput(f *testing.F) {
	f.Add("image:myorg/api:* -> api\nlabels:a=b,c=d -> svc")
	f.Add("# comment\n- image:x->name")
	f.Add("labels:=\nimage:")
	f.Fuzz(func(t *testing.T, raw string) {
		for _, r := range selector.ParseTargetsInput(raw) {
			if r.ImageGlob == "" && len(r.Labels) == 0 {
				t.Fatalf("rule with no matcher: %+v", r)
			}
		}
	})
}

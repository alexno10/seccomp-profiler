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
		SyscallHits: map[int]uint64{0: 1},
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

func TestParseTargetsInputWithErr_Hardening(t *testing.T) {
	// 1. Shorthand with spaces after "image:"/"labels:", spaces around commas, and inline comment.
	rules, err := selector.ParseTargetsInputWithErr("image: myorg/api:* labels: tier=backend, env=ci -> api # main service\n")
	if err != nil {
		t.Fatalf("expected spaced shorthand with comment to parse, got %v", err)
	}
	if len(rules) != 1 || rules[0].Name != "api" || rules[0].ImageGlob != "myorg/api:*" ||
		rules[0].Labels["tier"] != "backend" || rules[0].Labels["env"] != "ci" {
		t.Fatalf("unexpected parsed shorthand rule: %+v", rules)
	}

	// 2. Multi-line YAML list format advertised by action.yml.
	yamlInput := `
- name: worker
  image: myorg/worker:*
  labels:
    tier: backend
    queue: high
`
	rules, err = selector.ParseTargetsInputWithErr(yamlInput)
	if err != nil {
		t.Fatalf("expected multi-line YAML targets to parse, got %v", err)
	}
	if len(rules) != 1 || rules[0].Name != "worker" || rules[0].ImageGlob != "myorg/worker:*" ||
		rules[0].Labels["tier"] != "backend" || rules[0].Labels["queue"] != "high" {
		t.Fatalf("unexpected parsed YAML rule: %+v", rules)
	}

	// 3. Empty/comments-only returns nil, nil (auto-discovery).
	rules, err = selector.ParseTargetsInputWithErr("# comment only\n   \n")
	if err != nil || len(rules) != 0 {
		t.Fatalf("expected comments-only targets to return empty/nil, got rules=%+v err=%v", rules, err)
	}

	// 4. Malformed rules and invalid target names must fail closed, never silently auto-discover.
	badInputs := []string{
		"-> api",
		"labels: -> api",
		"image: -> api",
		"image:myorg/api:* -> ../evil",
		"image:myorg/api:* -> api.suggested",
		"image:myorg/api:* ->",
		"- name: ../evil\n  image: alpine:*",
		"- name: only-name-no-matcher",
		"image:a image:b",
		"labels:badpair -> api",
		"foo bar baz -> api",
	}
	for _, bad := range badInputs {
		if got, err := selector.ParseTargetsInputWithErr(bad); err == nil {
			t.Fatalf("expected ParseTargetsInputWithErr(%q) to fail, got rules=%+v", bad, got)
		}
	}
}

func TestMatchRules_MissingLabelDoesNotMatchEmptyValue(t *testing.T) {
	cfg := selector.Config{
		Rules: []selector.TargetRule{
			{Name: "labeled", Labels: map[string]string{"tier": ""}},
		},
	}
	missing := makeRec("1", "alpine:3.20", map[string]string{"other": "1"})
	presentEmpty := makeRec("2", "alpine:3.20", map[string]string{"tier": ""})

	targets, skipped := selector.Evaluate(cfg, []selector.ContainerRecord{missing, presentEmpty})
	if len(targets) != 1 || len(targets[0].Containers) != 1 || targets[0].Containers[0].ID != "2" {
		t.Fatalf("expected only container with present empty label to match, got %+v", targets)
	}
	if len(skipped) != 1 || skipped[0].ID != "1" || skipped[0].Reason != "unmatched-selector" {
		t.Fatalf("expected container missing label to be unmatched-selector, got %+v", skipped)
	}
}

func TestExtraExcludesOverrideRulesCaseInsensitiveGroupByAndContainerImageName(t *testing.T) {
	// I14: ExtraExcludes must exclude matching images even when explicit Rules match them.
	cfg := selector.Config{
		Rules:         []selector.TargetRule{{Name: "any", ImageGlob: "*"}},
		ExtraExcludes: []string{"myorg/secret:*"},
	}
	_, skipped := selector.Evaluate(cfg, []selector.ContainerRecord{
		makeRec("c1", "myorg/secret:v1", nil),
	})
	if len(skipped) != 1 || skipped[0].Reason != "excluded-user" {
		t.Fatalf("expected ExtraExcludes to override Rules with excluded-user, got %+v", skipped)
	}

	// I14 + M3: Case-insensitive GroupBy ("IMAGE", "LABEL:...") and real image named "container".
	targets, _ := selector.Evaluate(selector.Config{GroupBy: "LABEL:App"}, []selector.ContainerRecord{
		makeRec("abcdef1234567890", "myorg/container:v1", map[string]string{"App": "web"}),
	})
	if len(targets) != 1 || targets[0].Name != "web" {
		t.Fatalf("expected case-insensitive LABEL:App to resolve web, got %+v", targets)
	}
	targetsImg, _ := selector.Evaluate(selector.Config{GroupBy: "IMAGE"}, []selector.ContainerRecord{
		makeRec("abcdef1234567890", "myorg/container:v1", nil),
	})
	if len(targetsImg) != 1 || targetsImg[0].Name != "container" {
		t.Fatalf("expected myorg/container:v1 target name to remain \"container\", got %+v", targetsImg)
	}
}

func TestParseTargetsInput_DashIndentQuotedKeysAndCommentEscapes(t *testing.T) {
	yamlWithSpacedDash := `
-   labels:
      "app.kubernetes.io/name": web
    image: "foo\\" # real inline comment
    name: web-app
`
	rules, err := selector.ParseTargetsInputWithErr(yamlWithSpacedDash)
	if err != nil {
		t.Fatalf("expected spaced dash YAML with quoted key and trailing backslash string to parse, got %v", err)
	}
	if len(rules) != 1 || rules[0].Name != "web-app" || rules[0].ImageGlob != `foo\\` || rules[0].Labels["app.kubernetes.io/name"] != "web" {
		t.Fatalf("unexpected parsed rule: %+v", rules)
	}

	shorthandWithHash := `image:"myorg/api:*" labels:note="a # b",env='c # d' -> api # end`
	rulesShort, err := selector.ParseTargetsInputWithErr(shorthandWithHash)
	if err != nil {
		t.Fatalf("expected shorthand with # inside quoted label to parse, got %v", err)
	}
	if len(rulesShort) != 1 || rulesShort[0].Labels["note"] != "a # b" || rulesShort[0].Labels["env"] != "c # d" {
		t.Fatalf("unexpected shorthand parsed rule: %+v", rulesShort)
	}
}

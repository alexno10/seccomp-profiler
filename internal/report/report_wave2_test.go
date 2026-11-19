package report_test

import (
	"strings"
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/diff"
	"github.com/alexno10/seccomp-profiler/internal/report"
	"github.com/alexno10/seccomp-profiler/internal/selector"
)

func TestRenderMarkdown_RendersDiffTablesWithoutProfilesAndEscapesCells(t *testing.T) {
	md := report.RenderMarkdown(report.SummaryInput{
		Diffs: []*diff.TargetDiff{
			{
				TargetName:           "api",
				HasCommittedBaseline: true,
				Added: []diff.AddedSyscall{
					{
						Name:            "ptrace",
						Risk:            diff.RiskHigh,
						RiskReason:      "proc|inject\nline2`tick",
						Sources:         []string{"observed"},
						ContainersSeen:  1,
						ContainerTotal:  1,
						ApprovalExpired: true,
						ApprovalExpires: "2020-01-01|bad",
					},
				},
				Escalated: []diff.EscalatedSyscall{
					{Name: "clone", Risk: diff.RiskHigh, RiskReason: "dropped|mask"},
				},
				Removed: []string{"chmod"},
			},
		},
		Skipped: []selector.SkippedContainer{
			{
				ID:     "abc|def",
				Image:  "alpine:3.20",
				Labels: map[string]string{"k": "v|x"},
				Reason: "bad|reason\nnewline",
			},
		},
		GatePassed: false,
		GateReason: "gate|failed\nnext",
	})

	for _, want := range []string{
		"### Target: `api`",
		"#### Newly Added Syscalls",
		"`ptrace`",
		"#### Constraint Escalations",
		"`clone`",
		"Removed syscalls",
		"`chmod`",
		`abc\|def`,
		`bad\|reason newline`,
		`gate\|failed next`,
		`2020-01-01\|bad`,
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("expected markdown to contain %q, got:\n%s", want, md)
		}
	}
}

func TestRenderMarkdown_EscapesHTMLTagsBracketsAndShowsPrunedWording(t *testing.T) {
	md := report.RenderMarkdown(report.SummaryInput{
		Diffs: []*diff.TargetDiff{
			{
				TargetName:           "api",
				HasCommittedBaseline: true,
				Added: []diff.AddedSyscall{
					{
						Name:           "ptrace",
						Risk:           diff.RiskHigh,
						RiskReason:     "debug",
						Sources:        []string{"observed"},
						ContainersSeen: 1,
						ContainerTotal: 1,
						Approved:       true,
						ApprovalReason: "ok <!-- hide --> [link](https://evil.example)",
					},
				},
				ArgsChangeDetails: []diff.ArgsChange{
					{Name: "socket", Risk: diff.RiskMedium, Approved: false},
				},
				Removed: []string{"chmod"},
			},
		},
		DriftNotes: []string{"<details>spoof</details>"},
		Prune:      true,
		GatePassed: false,
		GateReason: "<!-- comment -->",
	})

	for _, forbidden := range []string{"<!--", "<details>", "[link](https://evil.example)", "informational only"} {
		if strings.Contains(md, forbidden) {
			t.Fatalf("expected unescaped token %q to be escaped/omitted, got:\n%s", forbidden, md)
		}
	}
	for _, want := range []string{
		"+1 new syscalls (2 high-risk)",
		"-1 removed (pruned)",
		"Removed syscalls (pruned from generated profile):",
		"&lt;!--",
		"&lt;details&gt;",
		`\[link\]`,
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("expected %q in rendered markdown, got:\n%s", want, md)
		}
	}
}

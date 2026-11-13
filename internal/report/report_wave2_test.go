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

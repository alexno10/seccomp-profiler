package report_test

import (
	"strings"
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/diff"
	"github.com/alexno10/seccomp-profiler/internal/profile"
	"github.com/alexno10/seccomp-profiler/internal/report"
	"github.com/alexno10/seccomp-profiler/internal/selector"
)

func TestRenderMarkdown(t *testing.T) {
	built := &profile.BuiltProfile{
		TargetName: "api",
		OCI: profile.OCISeccompProfile{
			DefaultAction: "SCMP_ACT_ERRNO",
			Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		},
		Raw: profile.RawProfileV1{
			SchemaVersion: "v1",
			Target: profile.RawTargetInfo{
				Name:               "api",
				GroupBy:            "compose-service",
				ContainerCount:     3,
				DetectedRuntimes:   []string{"go"},
				CompatSyscallCount: 4,
			},
			Syscalls: map[string]profile.RawSyscallEntry{
				"read":         {Sources: []string{"observed", "baseline-runtime"}, TotalCalls: 100, ContainersSeen: 3},
				"ptrace":       {Sources: []string{"observed"}, TotalCalls: 1, ContainersSeen: 1},
				"rt_sigreturn": {Sources: []string{"baseline-lifecycle"}, TotalCalls: 0, ContainersSeen: 0},
				"rseq":         {Sources: []string{"baseline-lang:go"}, TotalCalls: 0, ContainersSeen: 0},
			},
		},
	}

	td := &diff.TargetDiff{
		TargetName:           "api",
		HasCommittedBaseline: true,
		Added: []diff.AddedSyscall{
			{
				Name:           "ptrace",
				Risk:           diff.RiskHigh,
				RiskReason:     "Container escape / process memory inspection & injection",
				Sources:        []string{"observed"},
				TotalCalls:     1,
				ContainersSeen: 1,
				ContainerTotal: 3,
				Approved:       false,
			},
		},
		Removed: []string{"chmod", "chown"},
	}

	in := report.SummaryInput{
		Profiles: []*profile.BuiltProfile{built},
		WriteResults: []profile.WriteResult{
			{
				TargetName:          "api",
				ProfilePath:         ".seccomp-profiler/profiles/api.json",
				SuggestedPath:       ".seccomp-profiler/profiles/api.suggested.json",
				RawPath:             ".seccomp-profiler/raw/api.profile.v1.json",
				ProtectedManualEdit: true,
			},
		},
		Diffs: []*diff.TargetDiff{td},
		Skipped: []selector.SkippedContainer{
			{
				ID:     "deadbeef1234",
				Image:  "testcontainers/ryuk:0.5.1",
				Labels: map[string]string{"org.testcontainers": "true"},
				Reason: "excluded-default",
			},
		},
		GatePassed: false,
		GateReason: "unapproved high-risk syscalls detected: api:ptrace",
	}

	md := report.RenderMarkdown(in)

	checks := []string{
		"+1 new syscalls (1 high-risk)  -2 removed (informational)",
		"observed",
		"baseline-runtime",
		"baseline-lifecycle",
		"baseline-lang:go",
		"rt_sigreturn",
		"1/3",
		"32-bit compatibility syscalls detected",
		"testcontainers/ryuk:0.5.1",
		"excluded-default",
		".seccomp-profiler/accepted.yml",
		".github/CODEOWNERS",
		"api.suggested.json",
	}
	for _, want := range checks {
		if !strings.Contains(md, want) {
			t.Fatalf("expected markdown to contain %q, got:\n%s", want, md)
		}
	}
}

package diff_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/baseline"
	"github.com/alexno10/seccomp-profiler/internal/diff"
	"github.com/alexno10/seccomp-profiler/internal/profile"
)

func TestBaselineLifecycleRiskInvariant(t *testing.T) {
	layers := baseline.LayerSyscalls(baseline.ModeStandard, "")
	for _, sc := range layers[baseline.SourceLifecycle] {
		risk, _ := diff.ClassifySyscall(sc)
		if risk != diff.RiskLow {
			t.Fatalf("baseline-lifecycle syscall %q must be RiskLow, got %q", sc, risk)
		}
	}
}

func TestResolveCommittedProfilePath(t *testing.T) {
	got := diff.ResolveCommittedProfilePath("seccomp/{name}.json", "api", 3)
	if got != filepath.FromSlash("seccomp/api.json") && got != "seccomp/api.json" {
		t.Fatalf("expected seccomp/api.json, got %q", got)
	}
}

func TestCanonicalDiffAsymmetricAndApprovals(t *testing.T) {
	committed := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{
				Names:  []string{"write", "read", "chmod"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
	current := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{
				Names:  []string{"read", "write", "ptrace"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
	raw := &profile.RawProfileV1{
		Target: profile.RawTargetInfo{Name: "api", ContainerCount: 3},
		Syscalls: map[string]profile.RawSyscallEntry{
			"read":   {Sources: []string{"observed"}, TotalCalls: 10, ContainersSeen: 3},
			"write":  {Sources: []string{"observed"}, TotalCalls: 5, ContainersSeen: 3},
			"ptrace": {Sources: []string{"observed"}, TotalCalls: 1, ContainersSeen: 1},
		},
	}
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

	// 1. Unapproved ptrace -> fails high-risk gate; removed chmod is informational.
	td, err := diff.Compare("api", committed, current, raw, nil, now)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	if len(td.Removed) != 1 || td.Removed[0] != "chmod" {
		t.Fatalf("expected Removed=[chmod], got %v", td.Removed)
	}
	if len(td.Added) != 1 || td.Added[0].Name != "ptrace" || td.Added[0].Risk != diff.RiskHigh {
		t.Fatalf("expected Added=[ptrace (high)], got %+v", td.Added)
	}
	passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{td}, "report", "high-risk")
	if err != nil || passed {
		t.Fatalf("expected gate to fail on unapproved ptrace, passed=%v err=%v", passed, err)
	}

	// 2. Only removed syscall -> passes gate even under onChange=fail / failOn=any-new.
	tdRemovedOnly, err := diff.Compare("api", committed, &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read", "write"}, Action: "SCMP_ACT_ALLOW"},
		},
	}, raw, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{tdRemovedOnly}, "fail", "any-new"); err != nil || !passed {
		t.Fatalf("expected removed-only diff to pass gate, passed=%v err=%v", passed, err)
	}

	// 3. Valid approval in accepted.yml -> passes high-risk gate.
	tmp := t.TempDir()
	accPath := filepath.Join(tmp, "accepted.yml")
	accYAML := `version: 1
accepted:
  - target: api
    syscall: ptrace
    reason: "debug harness in CI"
    expires: 2027-01-01
`
	if err := os.WriteFile(accPath, []byte(accYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	approvals, err := diff.LoadApprovals(accPath)
	if err != nil {
		t.Fatalf("LoadApprovals failed: %v", err)
	}
	tdApproved, err := diff.Compare("api", committed, current, raw, approvals, now)
	if err != nil {
		t.Fatal(err)
	}
	if !tdApproved.Added[0].Approved {
		t.Fatalf("expected ptrace to be approved")
	}
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{tdApproved}, "report", "high-risk"); err != nil || !passed {
		t.Fatalf("expected approved ptrace to pass high-risk gate, passed=%v err=%v", passed, err)
	}

	// 4. Expired approval -> must NOT bypass fail-on and must be marked Expired.
	expApprovals := []diff.ApprovalEntry{
		{Target: "api", Syscall: "ptrace", Reason: "old", Expires: "2026-01-01"},
	}
	tdExpired, err := diff.Compare("api", committed, current, raw, expApprovals, now)
	if err != nil {
		t.Fatal(err)
	}
	if tdExpired.Added[0].Approved || !tdExpired.Added[0].ApprovalExpired {
		t.Fatalf("expected expired approval to have Approved=false, ApprovalExpired=true, got %+v", tdExpired.Added[0])
	}
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{tdExpired}, "report", "high-risk"); err != nil || passed {
		t.Fatalf("expected expired approval to fail gate, passed=%v err=%v", passed, err)
	}

	// 5. on-change=update-pr passes gate when high-risk syscalls are approved, and fails when unapproved high-risk syscalls exist.
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{tdApproved}, "update-pr", "high-risk"); err != nil || !passed {
		t.Fatalf("expected approved diff with on-change=update-pr to pass gate, passed=%v err=%v", passed, err)
	}
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{td}, "update-pr", "high-risk"); err != nil || passed {
		t.Fatalf("expected unapproved high-risk diff with on-change=update-pr to fail gate, passed=%v err=%v", passed, err)
	}
}

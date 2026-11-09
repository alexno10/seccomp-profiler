package diff_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/diff"
	"github.com/alexno10/seccomp-profiler/internal/profile"
)

// The hand-rolled accepted.yml parser is fail-closed: unknown keys and
// misplaced list items are errors, and quoted values survive inline comments.
func TestLoadApprovalsParserHardening(t *testing.T) {
	tmp := t.TempDir()
	write := func(content string) string {
		p := filepath.Join(tmp, "accepted.yml")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	entries, err := diff.LoadApprovals(write("version: 1\naccepted:\n  - target: api\n    syscall: bpf\n    reason: \"needs it # not a comment\"\n"))
	if err != nil {
		t.Fatalf("valid file rejected: %v", err)
	}
	if len(entries) != 1 || entries[0].Reason != "needs it # not a comment" {
		t.Fatalf("quoted value with # mangled: %+v", entries)
	}

	if _, err := diff.LoadApprovals(write("accepted:\n  - target: api\n    syscall: bpf\n    unknown_key: x\n")); err == nil {
		t.Fatal("unknown key must be rejected, not silently ignored")
	}

	if _, err := diff.LoadApprovals(write("accpeted:\n  - target: api\n")); err == nil {
		t.Fatal("typo'd header with list items must be rejected")
	}

	if entries, err := diff.LoadApprovals(write("version: 1\n")); err != nil || len(entries) != 0 {
		t.Fatalf("empty accepted list must be valid: %v %v", entries, err)
	}
}

// Review item 2: a syscall that was only allowed under argument constraints
// must never silently become an unconditional allow. The escalation is
// reported separately and treated as high-risk drift.
func TestConditionalToUnconditionalEscalation(t *testing.T) {
	masked := []profile.OCISyscallArg{{Index: 0, Value: 2114060288, Op: "SCMP_CMP_MASKED_EQ"}}
	committed := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"clone"}, Action: "SCMP_ACT_ALLOW", Args: masked},
		},
	}
	current := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read", "clone"}, Action: "SCMP_ACT_ALLOW"},
		},
	}

	td, err := diff.Compare("api", committed, current, nil, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(td.Added) != 0 {
		t.Fatalf("clone must appear as escalation, not addition: %+v", td.Added)
	}
	if len(td.Escalated) != 1 || td.Escalated[0].Name != "clone" {
		t.Fatalf("expected escalated [clone], got %+v", td.Escalated)
	}
	if td.Escalated[0].Risk != diff.RiskHigh {
		t.Fatalf("escalation must be high risk, got %s", td.Escalated[0].Risk)
	}
	if passed, reason, err := diff.EvaluateGate([]*diff.TargetDiff{td}, "report", "high-risk"); err != nil || passed {
		t.Fatalf("expected gate failure on escalation, passed=%v err=%v reason=%s", passed, err, reason)
	}

	// Unchanged conditional rule: no escalation, no addition.
	sameArgs := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read", "clone"}, Action: "SCMP_ACT_ALLOW", Args: masked},
		},
	}
	tdSame, err := diff.Compare("api", committed, sameArgs, nil, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(tdSame.Escalated) != 0 || len(tdSame.Added) != 0 || len(tdSame.ArgsChanged) != 0 {
		t.Fatalf("identical conditional rule must be silent: %+v", tdSame)
	}

	// Tightened/loosened args are informational.
	tightened := []profile.OCISyscallArg{{Index: 0, Value: 1, Op: "SCMP_CMP_MASKED_EQ"}}
	tdChanged, err := diff.Compare("api", committed, &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read", "clone"}, Action: "SCMP_ACT_ALLOW", Args: tightened},
		},
	}, nil, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(tdChanged.Escalated) != 0 {
		t.Fatalf("arg change within conditional rules is not an escalation: %+v", tdChanged.Escalated)
	}
	if len(tdChanged.ArgsChanged) != 1 || tdChanged.ArgsChanged[0] != "clone" {
		t.Fatalf("expected ArgsChanged=[clone], got %+v", tdChanged.ArgsChanged)
	}
}

// Review item 12: an unconditional clone allow is equivalent to unshare.
func TestUnconditionalCloneIsHighRisk(t *testing.T) {
	risk, _ := diff.ClassifySyscallRule("clone", false)
	if risk != diff.RiskHigh {
		t.Fatalf("unconditional clone must be high risk, got %s", risk)
	}
	risk, _ = diff.ClassifySyscallRule("clone", true)
	if risk != diff.RiskMedium {
		t.Fatalf("arg-constrained clone must stay medium, got %s", risk)
	}
	risk, _ = diff.ClassifySyscallRule("clone3", false)
	if risk != diff.RiskHigh {
		t.Fatalf("unconditional clone3 must be high risk, got %s", risk)
	}
}

// Review item 12: new mount API, io_uring, clock and process introspection
// syscalls must be classified as high risk.
func TestExpandedHighRiskList(t *testing.T) {
	for _, name := range []string{
		"fsopen", "fsmount", "fsconfig", "fspick", "move_mount", "open_tree",
		"mount_setattr", "pidfd_getfd", "process_madvise", "kcmp",
		"io_uring_setup", "io_uring_enter", "io_uring_register",
		"clock_settime", "settimeofday", "adjtimex", "sethostname",
		"personality", "fanotify_init", "move_pages", "migrate_pages",
		"uselib", "vhangup",
	} {
		if risk, _ := diff.ClassifySyscall(name); risk != diff.RiskHigh {
			t.Fatalf("expected %q to be high risk, got %s", name, risk)
		}
	}
}

// Review item 14: 32-bit compat observation fails the gate with a clear
// reason because compat syscalls are not profiled.
func TestCompatObservationFailsGate(t *testing.T) {
	committed := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls:      []profile.OCISyscallRule{{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"}},
	}
	current := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls:      []profile.OCISyscallRule{{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"}},
	}
	raw := &profile.RawProfileV1{
		Target: profile.RawTargetInfo{Name: "api", CompatSyscallCount: 7},
	}
	td, err := diff.Compare("api", committed, current, raw, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	passed, reason, err := diff.EvaluateGate([]*diff.TargetDiff{td}, "report", "high-risk")
	if err != nil {
		t.Fatal(err)
	}
	if passed || !strings.Contains(reason, "32-bit") {
		t.Fatalf("expected compat gate failure, passed=%v reason=%s", passed, reason)
	}
	// fail-on=none keeps the run green while still surfacing the warning.
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{td}, "report", "none"); err != nil || !passed {
		t.Fatalf("expected fail-on=none to pass, passed=%v err=%v", passed, err)
	}
}

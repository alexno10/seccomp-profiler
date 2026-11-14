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

	// UTF-8 BOM and unquoted apostrophe before # inline comment must work.
	bomAndApostrophe := "\xef\xbb\xbfversion: 1\naccepted:\n  - target: api\n    syscall: bpf\n    reason: app's debug probe # inline comment\n    expires: 2027-01-01\n"
	if entries, err := diff.LoadApprovals(write(bomAndApostrophe)); err != nil || len(entries) != 1 || entries[0].Reason != "app's debug probe" {
		t.Fatalf("expected BOM + apostrophe + inline comment to parse cleanly, got entries=%+v err=%v", entries, err)
	}

	// JSON accepted.yml with unknown fields must be rejected.
	if _, err := diff.LoadApprovals(write(`{"version": 1, "accepted": [{"target": "api", "syscall": "bpf", "expiry": "2020-01-01"}]}`)); err == nil {
		t.Fatal("expected JSON accepted.yml with unknown field 'expiry' to be rejected")
	}

	// JSON trailing garbage after root object must be rejected.
	if _, err := diff.LoadApprovals(write(`{"version": 1, "accepted": []} trailing`)); err == nil {
		t.Fatal("expected JSON accepted.yml with trailing tokens to be rejected")
	}

	// YAML entries missing target or syscall must be rejected.
	if _, err := diff.LoadApprovals(write("accepted:\n  - target: api\n    reason: missing syscall\n")); err == nil {
		t.Fatal("expected YAML entry missing syscall to be rejected")
	}
	if _, err := diff.LoadApprovals(write("accepted:\n  - syscall: bpf\n    reason: missing target\n")); err == nil {
		t.Fatal("expected YAML entry missing target to be rejected")
	}
	if _, err := diff.LoadApprovals(write("accepted:\n  - reason: missing both\n")); err == nil {
		t.Fatal("expected YAML entry missing target and syscall to be rejected")
	}

	// Non-KV garbage line inside accepted: must be rejected.
	if _, err := diff.LoadApprovals(write("accepted:\n  - target: api\n    syscall: bpf\n    not_a_kv_line\n")); err == nil {
		t.Fatal("expected non-KV garbage line inside accepted: to be rejected")
	}

	// Stray key before first list item inside accepted: must be rejected.
	if _, err := diff.LoadApprovals(write("accepted:\n  target: api\n")); err == nil {
		t.Fatal("expected stray KV before first '-' list item to be rejected")
	}

	// Unknown top-level key must be rejected.
	if _, err := diff.LoadApprovals(write("typo_top: 1\n")); err == nil {
		t.Fatal("expected unknown top-level key to be rejected")
	}

	// Invalid expires date format in YAML and JSON must be rejected.
	if _, err := diff.LoadApprovals(write("accepted:\n  - target: api\n    syscall: bpf\n    expires: not-a-date\n")); err == nil {
		t.Fatal("expected invalid YAML expires format to be rejected")
	}
	if _, err := diff.LoadApprovals(write(`{"version": 1, "accepted": [{"target": "api", "syscall": "bpf", "expires": "not-a-date"}]}`)); err == nil {
		t.Fatal("expected invalid JSON expires format to be rejected")
	}

	// Duplicate (target, syscall) entries must be rejected.
	if _, err := diff.LoadApprovals(write("accepted:\n  - target: api\n    syscall: bpf\n  - target: api\n    syscall: bpf\n")); err == nil {
		t.Fatal("expected duplicate (target, syscall) entry to be rejected")
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
		"quotactl_fd", "clock_adjtime", "modify_ldt", "lsm_set_self_attr",
	} {
		if risk, _ := diff.ClassifySyscall(name); risk != diff.RiskHigh {
			t.Fatalf("expected %q to be high risk, got %s", name, risk)
		}
	}
	for _, name := range []string{
		"setgroups", "setfsuid", "setfsgid", "fchmodat2",
	} {
		if risk, _ := diff.ClassifySyscall(name); risk != diff.RiskMedium {
			t.Fatalf("expected %q to be medium risk, got %s", name, risk)
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

func TestConditionalAddedSyscallAndVacuousCloneTriggerGate(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	committed := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls:      []profile.OCISyscallRule{{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"}},
	}

	// Conditional high-risk syscall (ptrace with args) must still fail high-risk gate.
	condPtrace := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"ptrace"}, Action: "SCMP_ACT_ALLOW", Args: []profile.OCISyscallArg{{Index: 0, Value: 0, Op: "SCMP_CMP_GE"}}},
		},
	}
	tdPtrace, err := diff.Compare("api", committed, condPtrace, nil, nil, now)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	if len(tdPtrace.Added) != 1 || tdPtrace.Added[0].Name != "ptrace" || tdPtrace.Added[0].Risk != diff.RiskHigh {
		t.Fatalf("expected Added=[ptrace high], got %+v", tdPtrace.Added)
	}
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{tdPtrace}, "report", "high-risk"); err != nil || passed {
		t.Fatalf("expected conditional ptrace to fail high-risk gate, passed=%v err=%v", passed, err)
	}

	// Vacuous args on newly added clone must NOT downgrade clone below RiskHigh.
	vacuousClone := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"clone"}, Action: "SCMP_ACT_ALLOW", Args: []profile.OCISyscallArg{{Index: 0, Value: 0, Op: "SCMP_CMP_GE"}}},
		},
	}
	tdVacuousClone, err := diff.Compare("api", committed, vacuousClone, nil, nil, now)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	if len(tdVacuousClone.Added) != 1 || tdVacuousClone.Added[0].Name != "clone" || tdVacuousClone.Added[0].Risk != diff.RiskHigh {
		t.Fatalf("expected vacuous conditional clone to be Added RiskHigh, got %+v", tdVacuousClone.Added)
	}
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{tdVacuousClone}, "report", "high-risk"); err != nil || passed {
		t.Fatalf("expected vacuous conditional clone to fail high-risk gate, passed=%v err=%v", passed, err)
	}

	// Proper CLONE_NEW* masked clone stays RiskMedium when added.
	maskedClone := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"clone"}, Action: "SCMP_ACT_ALLOW", Args: []profile.OCISyscallArg{{Index: 0, Value: 2114060288, ValueTwo: 0, Op: "SCMP_CMP_MASKED_EQ"}}},
		},
	}
	tdMaskedClone, err := diff.Compare("api", committed, maskedClone, nil, nil, now)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	if len(tdMaskedClone.Added) != 1 || tdMaskedClone.Added[0].Name != "clone" || tdMaskedClone.Added[0].Risk != diff.RiskMedium {
		t.Fatalf("expected CLONE_NEW*-masked clone to be Added RiskMedium, got %+v", tdMaskedClone.Added)
	}
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{tdMaskedClone}, "report", "high-risk"); err != nil || !passed {
		t.Fatalf("expected CLONE_NEW*-masked clone to pass high-risk gate, passed=%v err=%v", passed, err)
	}
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{tdMaskedClone}, "report", "any-new"); err != nil || passed {
		t.Fatalf("expected CLONE_NEW*-masked clone to fail any-new gate, passed=%v err=%v", passed, err)
	}
}

func TestMultipleConditionalRulesNotOverwritten(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	argA := []profile.OCISyscallArg{{Index: 2, Value: 0, Op: "SCMP_CMP_EQ"}}
	argB := []profile.OCISyscallArg{{Index: 1, Value: 1, Op: "SCMP_CMP_MASKED_EQ"}}
	committed := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"openat"}, Action: "SCMP_ACT_ALLOW", Args: argA},
		},
	}
	// Put argB first, argA second so single-slot overwrite would match committed argA.
	current := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"openat"}, Action: "SCMP_ACT_ALLOW", Args: argB},
			{Names: []string{"openat"}, Action: "SCMP_ACT_ALLOW", Args: argA},
		},
	}
	td, err := diff.Compare("api", committed, current, nil, nil, now)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	if len(td.ArgsChanged) != 1 || td.ArgsChanged[0] != "openat" {
		t.Fatalf("expected ArgsChanged=[openat], got %+v", td.ArgsChanged)
	}
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{td}, "report", "any-new"); err != nil || passed {
		t.Fatalf("expected unapproved ArgsChanged on openat to fail any-new gate, passed=%v err=%v", passed, err)
	}

	// Multiple conditional rules on newly added clone where one lacks CLONE_NEW* mask -> RiskHigh.
	vacuousThenMasked := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"openat"}, Action: "SCMP_ACT_ALLOW", Args: argA},
			{Names: []string{"clone"}, Action: "SCMP_ACT_ALLOW", Args: []profile.OCISyscallArg{{Index: 0, Value: 0, Op: "SCMP_CMP_GE"}}},
			{Names: []string{"clone"}, Action: "SCMP_ACT_ALLOW", Args: []profile.OCISyscallArg{{Index: 0, Value: 2114060288, ValueTwo: 0, Op: "SCMP_CMP_MASKED_EQ"}}},
		},
	}
	tdClone, err := diff.Compare("api", committed, vacuousThenMasked, nil, nil, now)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	if len(tdClone.Added) != 1 || tdClone.Added[0].Name != "clone" || tdClone.Added[0].Risk != diff.RiskHigh {
		t.Fatalf("expected dual-rule clone with vacuous rule to be RiskHigh, got %+v", tdClone.Added)
	}
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{tdClone}, "report", "high-risk"); err != nil || passed {
		t.Fatalf("expected dual-rule clone with vacuous rule to fail high-risk gate, passed=%v err=%v", passed, err)
	}
}

func TestPermissiveActionsAndEmptyActionValidation(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	committed := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls:      []profile.OCISyscallRule{{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"}},
	}

	for _, action := range []string{"SCMP_ACT_LOG", "SCMP_ACT_TRACE", "SCMP_ACT_NOTIFY"} {
		curr := &profile.OCISeccompProfile{
			DefaultAction: "SCMP_ACT_ERRNO",
			Architectures: []string{"SCMP_ARCH_X86_64"},
			Syscalls: []profile.OCISyscallRule{
				{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"},
				{Names: []string{"ptrace"}, Action: action},
			},
		}
		td, err := diff.Compare("api", committed, curr, nil, nil, now)
		if err != nil {
			t.Fatalf("%s Compare failed: %v", action, err)
		}
		if len(td.Added) != 1 || td.Added[0].Name != "ptrace" || td.Added[0].Risk != diff.RiskHigh {
			t.Fatalf("%s expected Added=[ptrace high], got %+v", action, td.Added)
		}
		if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{td}, "report", "high-risk"); err != nil || passed {
			t.Fatalf("%s ptrace must fail high-risk gate, passed=%v err=%v", action, passed, err)
		}
	}

	emptyCurr := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls:      []profile.OCISyscallRule{{Names: []string{"ptrace"}, Action: ""}},
	}
	if _, err := diff.Compare("api", committed, emptyCurr, nil, nil, now); err == nil {
		t.Fatal("expected empty rule Action in current profile to return error")
	}
	if _, err := diff.Compare("api", emptyCurr, committed, nil, nil, now); err == nil {
		t.Fatal("expected empty rule Action in committed profile to return error")
	}
}

func TestArgsChangedDefaultActionAndArchitecturesGate(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	masked := []profile.OCISyscallArg{{Index: 0, Value: 2114060288, ValueTwo: 0, Op: "SCMP_CMP_MASKED_EQ"}}
	committed := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"clone"}, Action: "SCMP_ACT_ALLOW", Args: masked},
		},
	}

	// Loosening clone args without approval must preserve ArgsChanged=["clone"], Escalated=0, and fail high-risk gate.
	loosened := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"clone"}, Action: "SCMP_ACT_ALLOW", Args: []profile.OCISyscallArg{{Index: 0, Value: 0, Op: "SCMP_CMP_GE"}}},
		},
	}
	tdLoose, err := diff.Compare("api", committed, loosened, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(tdLoose.Escalated) != 0 || len(tdLoose.ArgsChanged) != 1 || tdLoose.ArgsChanged[0] != "clone" {
		t.Fatalf("expected Escalated=0 ArgsChanged=[clone], got Esc=%+v Args=%+v", tdLoose.Escalated, tdLoose.ArgsChanged)
	}
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{tdLoose}, "report", "high-risk"); err != nil || passed {
		t.Fatalf("expected unapproved clone ArgsChanged losing CLONE_NEW* mask to fail high-risk gate, passed=%v err=%v", passed, err)
	}

	// Explicit approval in accepted.yml allows the ArgsChanged.
	approvals := []diff.ApprovalEntry{{Target: "api", Syscall: "clone", Reason: "intentional clone args update", Expires: "2027-01-01"}}
	tdLooseApproved, err := diff.Compare("api", committed, loosened, nil, approvals, now)
	if err != nil {
		t.Fatal(err)
	}
	if passed, reason, err := diff.EvaluateGate([]*diff.TargetDiff{tdLooseApproved}, "report", "high-risk"); err != nil || !passed {
		t.Fatalf("expected approved clone ArgsChanged to pass high-risk gate, passed=%v reason=%s err=%v", passed, reason, err)
	}

	// Widening DefaultAction fails high-risk gate.
	for _, da := range []string{"SCMP_ACT_ALLOW", "SCMP_ACT_LOG", ""} {
		wideDA := &profile.OCISeccompProfile{
			DefaultAction: da,
			Architectures: []string{"SCMP_ARCH_X86_64"},
			Syscalls:      committed.Syscalls,
		}
		tdDA, err := diff.Compare("api", committed, wideDA, nil, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{tdDA}, "report", "high-risk"); err != nil || passed {
			t.Fatalf("expected permissive DefaultAction %q to fail high-risk gate, passed=%v err=%v", da, passed, err)
		}
	}

	// Adding extra architecture fails high-risk gate.
	extraArch := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86"},
		Syscalls:      committed.Syscalls,
	}
	tdArch, err := diff.Compare("api", committed, extraArch, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if passed, _, err := diff.EvaluateGate([]*diff.TargetDiff{tdArch}, "report", "high-risk"); err != nil || passed {
		t.Fatalf("expected extra Architecture to fail high-risk gate, passed=%v err=%v", passed, err)
	}
}

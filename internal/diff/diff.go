package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/profile"
)

type AddedSyscall struct {
	Name            string
	Risk            RiskLevel
	RiskReason      string
	Sources         []string
	TotalCalls      uint64
	ContainersSeen  int
	ContainerTotal  int
	Approved        bool
	ApprovalReason  string
	ApprovalExpires string
	ApprovalExpired bool
}

// EscalatedSyscall reports a syscall that was previously only allowed under
// argument constraints in the committed profile but now appears as an
// unconditional allow. This is treated as high-risk drift: dropping the
// constraint silently widens the rule (e.g. clone without the CLONE_NEW* mask
// is equivalent to unshare).
type EscalatedSyscall struct {
	Name            string
	Risk            RiskLevel
	RiskReason      string
	CommittedArgs   string
	Approved        bool
	ApprovalReason  string
	ApprovalExpires string
	ApprovalExpired bool
}

type TargetDiff struct {
	TargetName           string
	HasCommittedBaseline bool
	Added                []AddedSyscall
	Escalated            []EscalatedSyscall
	ArgsChanged          []string
	Removed              []string
	DefaultActionChanged bool
	OldDefaultAction     string
	NewDefaultAction     string
	PreservedArgRules    int
	CompatObserved       bool
	CompatHits           uint32
}

func ResolveCommittedProfilePath(pattern string, targetName string, totalTargets int) string {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return ""
	}
	if strings.Contains(p, "{name}") {
		return strings.ReplaceAll(p, "{name}", targetName)
	}
	if info, err := os.Stat(p); err == nil && info.IsDir() {
		return filepath.Join(p, targetName+".json")
	}
	if !strings.HasSuffix(strings.ToLower(p), ".json") {
		return filepath.Join(p, targetName+".json")
	}
	if totalTargets > 1 {
		return filepath.Join(filepath.Dir(p), targetName+".json")
	}
	return p
}

// argsKey returns a canonical JSON encoding of a rule's argument constraints so
// that conditional rules can be compared structurally (ignoring ordering).
func argsKey(rule profile.OCISyscallRule) string {
	if len(rule.Args) == 0 {
		return ""
	}
	b, err := json.Marshal(rule.Args)
	if err != nil {
		return fmt.Sprintf("len:%d", len(rule.Args))
	}
	return string(b)
}

func allowRuleSets(profiles []*profile.OCISeccompProfile) (uncond map[string]bool, cond map[string]string) {
	uncond = make(map[string]bool)
	cond = make(map[string]string)
	for _, p := range profiles {
		if p == nil {
			continue
		}
		for _, r := range p.Syscalls {
			if r.Action != "SCMP_ACT_ALLOW" && r.Action != "" {
				continue
			}
			if len(r.Args) > 0 {
				key := argsKey(r)
				for _, name := range r.Names {
					if _, ok := cond[name]; !ok || key != "" {
						cond[name] = key
					}
				}
				continue
			}
			for _, name := range r.Names {
				uncond[name] = true
			}
		}
	}
	return uncond, cond
}

func Compare(
	targetName string,
	committed *profile.OCISeccompProfile,
	current *profile.OCISeccompProfile,
	raw *profile.RawProfileV1,
	approvals []ApprovalEntry,
	now time.Time,
) (*TargetDiff, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	td := &TargetDiff{
		TargetName:           targetName,
		HasCommittedBaseline: committed != nil,
	}

	if committed != nil && current != nil && committed.DefaultAction != current.DefaultAction {
		td.DefaultActionChanged = true
		td.OldDefaultAction = committed.DefaultAction
		td.NewDefaultAction = current.DefaultAction
	}

	committedUncond, committedCond := allowRuleSets([]*profile.OCISeccompProfile{committed})
	if committed != nil {
		for _, r := range committed.Syscalls {
			if len(r.Args) > 0 {
				td.PreservedArgRules++
			}
		}
	}
	currentUncond, currentCond := allowRuleSets([]*profile.OCISeccompProfile{current})

	var addedNames []string
	for name := range currentUncond {
		if committedUncond[name] {
			continue
		}
		if _, wasCond := committedCond[name]; wasCond {
			continue
		}
		addedNames = append(addedNames, name)
	}
	sort.Strings(addedNames)

	// Conditional -> unconditional escalation: the name existed only under arg
	// constraints before, and is now allowed without any constraint.
	var escalatedNames []string
	for name := range currentUncond {
		if _, wasCond := committedCond[name]; wasCond && !committedUncond[name] {
			escalatedNames = append(escalatedNames, name)
		}
	}
	sort.Strings(escalatedNames)

	// Constraint loosening within conditional rules (informational).
	for name, currKey := range currentCond {
		if prevKey, ok := committedCond[name]; ok && prevKey != currKey && prevKey != "" {
			td.ArgsChanged = append(td.ArgsChanged, name)
		}
	}
	sort.Strings(td.ArgsChanged)

	var removedNames []string
	for name := range committedUncond {
		if !currentUncond[name] && !hasCond(currentCond, name) {
			removedNames = append(removedNames, name)
		}
	}
	for name := range committedCond {
		if !currentUncond[name] && !hasCond(currentCond, name) {
			removedNames = append(removedNames, name)
		}
	}
	sort.Strings(removedNames)
	td.Removed = dedup(removedNames)

	containerTotal := 0
	if raw != nil {
		containerTotal = raw.Target.ContainerCount
		if raw.Target.CompatSyscallCount > 0 {
			td.CompatObserved = true
			td.CompatHits = raw.Target.CompatSyscallCount
		}
	}

	for _, name := range addedNames {
		risk, reason := ClassifySyscallRule(name, false)
		item := AddedSyscall{
			Name:           name,
			Risk:           risk,
			RiskReason:     reason,
			ContainerTotal: containerTotal,
		}
		if raw != nil {
			if meta, ok := raw.Syscalls[name]; ok {
				item.Sources = meta.Sources
				item.TotalCalls = meta.TotalCalls
				item.ContainersSeen = meta.ContainersSeen
			}
		}
		applyApproval(&item.Approved, &item.ApprovalReason, &item.ApprovalExpires,
			&item.ApprovalExpired, approvals, targetName, name, now)
		td.Added = append(td.Added, item)
	}

	for _, name := range escalatedNames {
		risk, reason := ClassifySyscallRule(name, false)
		item := EscalatedSyscall{
			Name:          name,
			Risk:          risk,
			RiskReason:    reason,
			CommittedArgs: committedCond[name],
		}
		approved := false
		var aReason, aExpires string
		var aExpired bool
		applyApproval(&approved, &aReason, &aExpires, &aExpired, approvals, targetName, name, now)
		item.Approved = approved
		item.ApprovalReason = aReason
		item.ApprovalExpires = aExpires
		item.ApprovalExpired = aExpired
		td.Escalated = append(td.Escalated, item)
	}

	return td, nil
}

func hasCond(cond map[string]string, name string) bool {
	_, ok := cond[name]
	return ok
}

func dedup(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func applyApproval(approved *bool, reason, expires *string, expired *bool,
	approvals []ApprovalEntry, target, syscall string, now time.Time) {
	if app, ok := findApproval(approvals, target, syscall); ok {
		*reason = app.Reason
		*expires = app.Expires
		if isExpired(app.Expires, now) {
			*expired = true
			*approved = false
		} else {
			*approved = true
		}
	}
}

// EvaluateGate validates the policy inputs and decides whether the run passes.
// on-change: update-pr is treated like report at the gate level (the profiles
// are written to the committed location for the PR author to commit).
func EvaluateGate(diffs []*TargetDiff, onChange string, failOn string) (bool, string, error) {
	oc := strings.ToLower(strings.TrimSpace(onChange))
	if oc == "" {
		oc = "report"
	}
	if oc != "report" && oc != "fail" && oc != "update-pr" {
		return false, "", fmt.Errorf("invalid on-change value %q: must be \"report\", \"fail\", or \"update-pr\"", onChange)
	}

	fo := strings.ToLower(strings.TrimSpace(failOn))
	if fo == "" {
		fo = "high-risk"
	}
	if fo != "none" && fo != "high-risk" && fo != "any-new" {
		return false, "", fmt.Errorf("invalid fail-on value %q: must be \"none\", \"high-risk\", or \"any-new\"", failOn)
	}

	var unapprovedHigh []string
	var unapprovedAny []string
	var expiredApprovals []string

	for _, d := range diffs {
		for _, a := range d.Added {
			if a.ApprovalExpired {
				expiredApprovals = append(expiredApprovals, fmt.Sprintf("%s:%s (expired %s)", d.TargetName, a.Name, a.ApprovalExpires))
			}
			if a.Approved {
				continue
			}
			unapprovedAny = append(unapprovedAny, fmt.Sprintf("%s:%s", d.TargetName, a.Name))
			if a.Risk == RiskHigh {
				unapprovedHigh = append(unapprovedHigh, fmt.Sprintf("%s:%s", d.TargetName, a.Name))
			}
		}
		for _, e := range d.Escalated {
			if e.ApprovalExpired {
				expiredApprovals = append(expiredApprovals, fmt.Sprintf("%s:%s (expired %s)", d.TargetName, e.Name, e.ApprovalExpires))
			}
			if e.Approved {
				continue
			}
			unapprovedAny = append(unapprovedAny, fmt.Sprintf("%s:%s (constraint dropped)", d.TargetName, e.Name))
			unapprovedHigh = append(unapprovedHigh, fmt.Sprintf("%s:%s (constraint dropped)", d.TargetName, e.Name))
		}
	}

	if fo == "high-risk" && len(unapprovedHigh) > 0 {
		return false, fmt.Sprintf("unapproved high-risk syscalls detected: %s", strings.Join(unapprovedHigh, ", ")), nil
	}
	if (fo == "any-new" || oc == "fail") && len(unapprovedAny) > 0 {
		return false, fmt.Sprintf("unapproved new syscalls detected: %s", strings.Join(unapprovedAny, ", ")), nil
	}
	if len(expiredApprovals) > 0 && fo != "none" {
		return false, fmt.Sprintf("expired syscall approvals in accepted.yml: %s", strings.Join(expiredApprovals, ", ")), nil
	}
	if fo != "none" {
		for _, d := range diffs {
			if d.CompatObserved {
				return false, fmt.Sprintf("target %q observed 32-bit compatibility syscalls (%d calls): 32-bit compat is unsupported by seccomp-profiler; the generated profile only covers native 64-bit syscalls. Rebuild the workload as 64-bit or exclude the target", d.TargetName, d.CompatHits), nil
			}
		}
	}
	return true, "all security gate checks passed", nil
}

func findApproval(approvals []ApprovalEntry, target, syscall string) (ApprovalEntry, bool) {
	for _, a := range approvals {
		if (a.Target == target || a.Target == "*") && a.Syscall == syscall {
			return a, true
		}
	}
	return ApprovalEntry{}, false
}

func isExpired(expires string, now time.Time) bool {
	s := strings.TrimSpace(expires)
	if s == "" {
		return false
	}
	expTime, err := time.Parse("2006-01-02", s)
	if err != nil {
		expTime, err = time.Parse(time.RFC3339, s)
		if err != nil {
			return true
		}
	}
	nowDate := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return expTime.UTC().Before(nowDate)
}

// FileChanged reports whether the two files' SHA-256 digests differ. Missing
// files are compared by existence so that "baseline has file, working tree
// does not" is also detected as a change.
func FileChanged(aPath, bPath string) bool {
	ab, aErr := os.ReadFile(aPath)
	bb, bErr := os.ReadFile(bPath)
	if aErr != nil || bErr != nil {
		return aErr != bErr
	}
	ha := sha256.Sum256(ab)
	hb := sha256.Sum256(bb)
	return hex.EncodeToString(ha[:]) != hex.EncodeToString(hb[:])
}

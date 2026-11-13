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

// ArgsChange reports a change in argument constraints for a conditionally
// allowed syscall compared to the committed profile.
type ArgsChange struct {
	Name            string
	Risk            RiskLevel
	RiskReason      string
	CommittedArgs   string
	CurrentArgs     string
	Approved        bool
	ApprovalReason  string
	ApprovalExpires string
	ApprovalExpired bool
}

type TargetDiff struct {
	TargetName              string
	HasCommittedBaseline    bool
	Added                   []AddedSyscall
	Escalated               []EscalatedSyscall
	ArgsChanged             []string
	ArgsChangeDetails       []ArgsChange
	Removed                 []string
	DefaultActionChanged    bool
	PermissiveDefaultAction bool
	OldDefaultAction        string
	NewDefaultAction        string
	AddedArchitectures      []string
	DefaultErrnoRetChanged  bool
	PreservedArgRules       int
	CompatObserved          bool
	CompatHits              uint32
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
const cloneNewNamespaceMask uint64 = 2114060288

type condRuleEntry struct {
	Key  string
	Args []profile.OCISyscallArg
}

func isPermittingAction(action string) (bool, error) {
	a := strings.TrimSpace(action)
	if a == "" {
		return false, fmt.Errorf("empty seccomp rule action")
	}
	switch a {
	case "SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_TRACE", "SCMP_ACT_NOTIFY":
		return true, nil
	case "SCMP_ACT_ERRNO", "SCMP_ACT_TRAP", "SCMP_ACT_KILL", "SCMP_ACT_KILL_THREAD", "SCMP_ACT_KILL_PROCESS":
		return false, nil
	default:
		return false, fmt.Errorf("unsupported seccomp rule action %q", action)
	}
}

func isPermittingDefaultAction(action string) bool {
	switch strings.TrimSpace(action) {
	case "SCMP_ACT_ERRNO", "SCMP_ACT_TRAP", "SCMP_ACT_KILL", "SCMP_ACT_KILL_THREAD", "SCMP_ACT_KILL_PROCESS":
		return false
	default:
		return true
	}
}

func hasCloneNamespaceMask(args []profile.OCISyscallArg) bool {
	for _, a := range args {
		if a.Index == 0 && a.Op == "SCMP_CMP_MASKED_EQ" &&
			(a.Value&cloneNewNamespaceMask) == cloneNewNamespaceMask && a.ValueTwo == 0 {
			return true
		}
	}
	return false
}

func effectiveHasArgs(name string, entries []condRuleEntry) bool {
	if len(entries) == 0 {
		return false
	}
	if name == "clone" {
		for _, e := range entries {
			if !hasCloneNamespaceMask(e.Args) {
				return false
			}
		}
		return true
	}
	if name == "clone3" {
		// clone3 passes flags inside struct clone_args*; seccomp BPF cannot
		// dereference user pointers to mask CLONE_NEW* bits.
		return false
	}
	return true
}

func canonicalArgsKey(rule profile.OCISyscallRule) string {
	if len(rule.Args) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rule.Args))
	for _, a := range rule.Args {
		b, err := json.Marshal(a)
		if err != nil {
			parts = append(parts, fmt.Sprintf("%+v", a))
		} else {
			parts = append(parts, string(b))
		}
	}
	sort.Strings(parts)
	key := "[" + strings.Join(parts, ",") + "]"
	if rule.Action != "" && rule.Action != "SCMP_ACT_ALLOW" {
		return rule.Action + ":" + key
	}
	return key
}

func joinedCondKey(entries []condRuleEntry) string {
	if len(entries) == 0 {
		return ""
	}
	seen := make(map[string]bool)
	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		if seen[e.Key] {
			continue
		}
		seen[e.Key] = true
		keys = append(keys, e.Key)
	}
	sort.Strings(keys)
	return strings.Join(keys, "|")
}

func allowRuleSets(profiles []*profile.OCISeccompProfile) (uncond map[string]bool, cond map[string][]condRuleEntry, err error) {
	uncond = make(map[string]bool)
	cond = make(map[string][]condRuleEntry)
	for _, p := range profiles {
		if p == nil {
			continue
		}
		for i, r := range p.Syscalls {
			permitting, aErr := isPermittingAction(r.Action)
			if aErr != nil {
				return nil, nil, fmt.Errorf("syscalls[%d]: %w", i, aErr)
			}
			if !permitting {
				continue
			}
			if len(r.Args) > 0 {
				entry := condRuleEntry{
					Key:  canonicalArgsKey(r),
					Args: r.Args,
				}
				for _, name := range r.Names {
					cond[name] = append(cond[name], entry)
				}
				continue
			}
			for _, name := range r.Names {
				uncond[name] = true
			}
		}
	}
	return uncond, cond, nil
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

	if current != nil {
		td.NewDefaultAction = current.DefaultAction
		td.PermissiveDefaultAction = isPermittingDefaultAction(current.DefaultAction)
	}
	if committed != nil && current != nil {
		if committed.DefaultAction != current.DefaultAction {
			td.DefaultActionChanged = true
			td.OldDefaultAction = committed.DefaultAction
			td.NewDefaultAction = current.DefaultAction
		}
		if (committed.DefaultErrnoRet == nil) != (current.DefaultErrnoRet == nil) ||
			(committed.DefaultErrnoRet != nil && current.DefaultErrnoRet != nil && *committed.DefaultErrnoRet != *current.DefaultErrnoRet) {
			td.DefaultErrnoRetChanged = true
		}
		if len(committed.Architectures) > 0 {
			commArch := make(map[string]bool, len(committed.Architectures))
			for _, a := range committed.Architectures {
				commArch[a] = true
			}
			seenExtra := make(map[string]bool)
			for _, a := range current.Architectures {
				if !commArch[a] && !seenExtra[a] {
					seenExtra[a] = true
					td.AddedArchitectures = append(td.AddedArchitectures, a)
				}
			}
			sort.Strings(td.AddedArchitectures)
		}
	}

	committedUncond, committedCond, err := allowRuleSets([]*profile.OCISeccompProfile{committed})
	if err != nil {
		return nil, fmt.Errorf("invalid committed profile for target %q: %w", targetName, err)
	}
	if committed != nil {
		for _, r := range committed.Syscalls {
			if len(r.Args) > 0 {
				td.PreservedArgRules++
			}
		}
	}
	currentUncond, currentCond, err := allowRuleSets([]*profile.OCISeccompProfile{current})
	if err != nil {
		return nil, fmt.Errorf("invalid current profile for target %q: %w", targetName, err)
	}

	type addedCandidate struct {
		name    string
		hasArgs bool
	}
	var addedList []addedCandidate
	seenAdded := make(map[string]bool)
	for name := range currentUncond {
		if committedUncond[name] || len(committedCond[name]) > 0 {
			continue
		}
		seenAdded[name] = true
		addedList = append(addedList, addedCandidate{name: name, hasArgs: false})
	}
	for name, entries := range currentCond {
		if seenAdded[name] || currentUncond[name] || committedUncond[name] || len(committedCond[name]) > 0 {
			continue
		}
		seenAdded[name] = true
		addedList = append(addedList, addedCandidate{
			name:    name,
			hasArgs: effectiveHasArgs(name, entries),
		})
	}
	sort.Slice(addedList, func(i, j int) bool {
		return addedList[i].name < addedList[j].name
	})

	// Conditional -> unconditional escalation: the name existed only under arg
	// constraints before, and is now allowed without any constraint.
	var escalatedNames []string
	for name := range currentUncond {
		if len(committedCond[name]) > 0 && !committedUncond[name] {
			escalatedNames = append(escalatedNames, name)
		}
	}
	sort.Strings(escalatedNames)

	// Constraint changes within conditional rules (excluding syscalls that also became unconditional).
	for name, currEntries := range currentCond {
		if currentUncond[name] {
			continue
		}
		prevEntries, ok := committedCond[name]
		if !ok || len(prevEntries) == 0 {
			continue
		}
		prevKey := joinedCondKey(prevEntries)
		currKey := joinedCondKey(currEntries)
		if prevKey != currKey {
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

	for _, cand := range addedList {
		risk, reason := ClassifySyscallRule(cand.name, cand.hasArgs)
		item := AddedSyscall{
			Name:           cand.name,
			Risk:           risk,
			RiskReason:     reason,
			ContainerTotal: containerTotal,
		}
		if raw != nil {
			if meta, ok := raw.Syscalls[cand.name]; ok {
				item.Sources = meta.Sources
				item.TotalCalls = meta.TotalCalls
				item.ContainersSeen = meta.ContainersSeen
			}
		}
		applyApproval(&item.Approved, &item.ApprovalReason, &item.ApprovalExpires,
			&item.ApprovalExpired, approvals, targetName, cand.name, now)
		td.Added = append(td.Added, item)
	}

	for _, name := range escalatedNames {
		risk, reason := ClassifySyscallRule(name, false)
		item := EscalatedSyscall{
			Name:          name,
			Risk:          risk,
			RiskReason:    reason,
			CommittedArgs: joinedCondKey(committedCond[name]),
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

	for _, name := range td.ArgsChanged {
		risk, reason := ClassifySyscallRule(name, effectiveHasArgs(name, currentCond[name]))
		ac := ArgsChange{
			Name:          name,
			Risk:          risk,
			RiskReason:    reason,
			CommittedArgs: joinedCondKey(committedCond[name]),
			CurrentArgs:   joinedCondKey(currentCond[name]),
		}
		applyApproval(&ac.Approved, &ac.ApprovalReason, &ac.ApprovalExpires, &ac.ApprovalExpired,
			approvals, targetName, name, now)
		td.ArgsChangeDetails = append(td.ArgsChangeDetails, ac)
	}

	return td, nil
}

func hasCond(cond map[string][]condRuleEntry, name string) bool {
	return len(cond[name]) > 0
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
		for _, ac := range d.ArgsChangeDetails {
			if ac.ApprovalExpired {
				expiredApprovals = append(expiredApprovals, fmt.Sprintf("%s:%s (expired %s)", d.TargetName, ac.Name, ac.ApprovalExpires))
			}
			if ac.Approved {
				continue
			}
			msg := fmt.Sprintf("%s:%s (args changed)", d.TargetName, ac.Name)
			unapprovedAny = append(unapprovedAny, msg)
			if ac.Risk == RiskHigh {
				unapprovedHigh = append(unapprovedHigh, msg)
			}
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
			if d.PermissiveDefaultAction {
				return false, fmt.Sprintf("target %q sets permissive defaultAction %q", d.TargetName, d.NewDefaultAction), nil
			}
			if len(d.AddedArchitectures) > 0 {
				return false, fmt.Sprintf("target %q added unprofiled architecture(s): %s", d.TargetName, strings.Join(d.AddedArchitectures, ", ")), nil
			}
			if (fo == "any-new" || oc == "fail") && d.DefaultActionChanged {
				return false, fmt.Sprintf("target %q changed defaultAction (%q -> %q)", d.TargetName, d.OldDefaultAction, d.NewDefaultAction), nil
			}
			if (fo == "any-new" || oc == "fail") && d.DefaultErrnoRetChanged {
				return false, fmt.Sprintf("target %q changed defaultErrnoRet", d.TargetName), nil
			}
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

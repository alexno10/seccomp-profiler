package diff

import (
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

type TargetDiff struct {
	TargetName           string
	HasCommittedBaseline bool
	Added                []AddedSyscall
	Removed              []string
	DefaultActionChanged bool
	OldDefaultAction     string
	NewDefaultAction     string
	PreservedArgRules    int
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

	committedSet := make(map[string]bool)
	if committed != nil {
		if committed.DefaultAction != current.DefaultAction {
			td.DefaultActionChanged = true
			td.OldDefaultAction = committed.DefaultAction
			td.NewDefaultAction = current.DefaultAction
		}
		for _, r := range committed.Syscalls {
			if len(r.Args) > 0 {
				td.PreservedArgRules++
			}
			if r.Action == "SCMP_ACT_ALLOW" || r.Action == "" {
				for _, name := range r.Names {
					committedSet[name] = true
				}
			}
		}
	}

	currentSet := make(map[string]bool)
	if current != nil {
		for _, r := range current.Syscalls {
			if r.Action == "SCMP_ACT_ALLOW" || r.Action == "" {
				for _, name := range r.Names {
					currentSet[name] = true
				}
			}
		}
	}

	var addedNames []string
	for name := range currentSet {
		if !committedSet[name] {
			addedNames = append(addedNames, name)
		}
	}
	sort.Strings(addedNames)

	var removedNames []string
	for name := range committedSet {
		if !currentSet[name] {
			removedNames = append(removedNames, name)
		}
	}
	sort.Strings(removedNames)
	td.Removed = removedNames

	containerTotal := 0
	if raw != nil {
		containerTotal = raw.Target.ContainerCount
	}

	for _, name := range addedNames {
		risk, reason := ClassifySyscall(name)
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
		if app, ok := findApproval(approvals, targetName, name); ok {
			item.ApprovalReason = app.Reason
			item.ApprovalExpires = app.Expires
			if isExpired(app.Expires, now) {
				item.ApprovalExpired = true
				item.Approved = false
			} else {
				item.Approved = true
			}
		}
		td.Added = append(td.Added, item)
	}

	return td, nil
}

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

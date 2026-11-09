package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/alexno10/seccomp-profiler/internal/diff"
	"github.com/alexno10/seccomp-profiler/internal/profile"
	"github.com/alexno10/seccomp-profiler/internal/selector"
)

type SummaryInput struct {
	Profiles     []*profile.BuiltProfile
	WriteResults []profile.WriteResult
	Diffs        []*diff.TargetDiff
	Skipped      []selector.SkippedContainer
	GatePassed   bool
	GateReason   string
}

func RenderMarkdown(in SummaryInput) string {
	var b strings.Builder

	totalAdded := 0
	totalHighRisk := 0
	totalRemoved := 0
	unapprovedCount := 0

	diffByTarget := make(map[string]*diff.TargetDiff)
	for _, d := range in.Diffs {
		diffByTarget[d.TargetName] = d
		totalAdded += len(d.Added)
		totalRemoved += len(d.Removed)
		for _, a := range d.Added {
			if a.Risk == diff.RiskHigh {
				totalHighRisk++
			}
			if !a.Approved {
				unapprovedCount++
			}
		}
	}

	writeByTarget := make(map[string]profile.WriteResult)
	for _, w := range in.WriteResults {
		writeByTarget[w.TargetName] = w
	}

	gateBadge := "PASSED"
	if !in.GatePassed {
		gateBadge = "FAILED"
	}

	fmt.Fprintf(&b, "## eBPF Seccomp Profiler Summary (%s)\n\n", gateBadge)
	fmt.Fprintf(&b, "**+%d new syscalls (%d high-risk)  -%d removed (informational)**\n\n", totalAdded, totalHighRisk, totalRemoved)
	if in.GateReason != "" {
		fmt.Fprintf(&b, "- **Security Gate:** `%s` — %s\n\n", gateBadge, in.GateReason)
	}

	for _, p := range in.Profiles {
		tName := p.TargetName
		fmt.Fprintf(&b, "### Target: `%s`\n\n", tName)
		fmt.Fprintf(&b, "- **Group By:** `%s` | **Containers Merged:** `%d` | **Detected Runtimes:** `%s`\n",
			p.Raw.Target.GroupBy,
			p.Raw.Target.ContainerCount,
			strings.Join(p.Raw.Target.DetectedRuntimes, ", "),
		)
		if wr, ok := writeByTarget[tName]; ok {
			if wr.ProtectedManualEdit {
				fmt.Fprintf(&b, "- **Protected Hand-Edited Profile:** kept `%s` untouched; wrote suggested profile to `%s`\n", wr.ProfilePath, wr.SuggestedPath)
			} else {
				fmt.Fprintf(&b, "- **Profile Output:** `%s` (raw: `%s`)\n", wr.ProfilePath, wr.RawPath)
			}
		}
		fmt.Fprintln(&b)

		if p.Raw.Target.CompatSyscallCount > 0 {
			fmt.Fprintf(&b, "> [!WARNING]\n> 32-bit compatibility (TS_COMPAT) syscalls detected (%d calls) in target `%s`. Verify whether 32-bit binaries are intentional.\n\n",
				p.Raw.Target.CompatSyscallCount, tName)
		}

		sourceCounts := make(map[string]int)
		var neverObserved []string
		var lowCoverage []string
		containerCount := p.Raw.Target.ContainerCount

		var allSyscalls []string
		for sc := range p.Raw.Syscalls {
			allSyscalls = append(allSyscalls, sc)
		}
		sort.Strings(allSyscalls)

		for _, sc := range allSyscalls {
			meta := p.Raw.Syscalls[sc]
			for _, src := range meta.Sources {
				sourceCounts[src]++
			}
			if meta.ContainersSeen == 0 {
				neverObserved = append(neverObserved, sc)
			} else if containerCount > 1 && meta.ContainersSeen < containerCount {
				lowCoverage = append(lowCoverage, fmt.Sprintf("%s (%d/%d)", sc, meta.ContainersSeen, containerCount))
			}
		}

		var srcKeys []string
		for k := range sourceCounts {
			srcKeys = append(srcKeys, k)
		}
		sort.Strings(srcKeys)

		fmt.Fprintf(&b, "#### Layer Provenance Breakdown\n\n")
		fmt.Fprintf(&b, "| Source Layer | Syscall Count |\n|---|---|\n")
		for _, k := range srcKeys {
			fmt.Fprintf(&b, "| `%s` | %d |\n", k, sourceCounts[k])
		}
		fmt.Fprintln(&b)

		if len(neverObserved) > 0 {
			fmt.Fprintf(&b, "- **Baseline syscalls never observed at runtime:** `%s`\n", strings.Join(neverObserved, "`, `"))
		}
		if len(lowCoverage) > 0 {
			fmt.Fprintf(&b, "- **Low-coverage observed syscalls:** `%s`\n", strings.Join(lowCoverage, "`, `"))
		}
		fmt.Fprintln(&b)

		if td, ok := diffByTarget[tName]; ok {
			if len(td.Added) > 0 {
				fmt.Fprintf(&b, "#### Newly Added Syscalls\n\n")
				fmt.Fprintf(&b, "| Syscall | Risk | Sources | Containers Seen | Approval Status | Security Rationale |\n|---|---|---|---|---|---|\n")
				for _, a := range td.Added {
					status := "Unapproved"
					if a.Approved {
						status = fmt.Sprintf("Approved (%s)", a.ApprovalReason)
					} else if a.ApprovalExpired {
						status = fmt.Sprintf("Expired (%s)", a.ApprovalExpires)
					}
					fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%d/%d` | %s | %s |\n",
						a.Name,
						a.Risk,
						strings.Join(a.Sources, ", "),
						a.ContainersSeen,
						a.ContainerTotal,
						status,
						a.RiskReason,
					)
				}
				fmt.Fprintln(&b)
			}
			if len(td.Removed) > 0 {
				fmt.Fprintf(&b, "- **Removed syscalls (informational only — not auto-removed):** `%s`\n\n", strings.Join(td.Removed, "`, `"))
			}
		}
	}

	if len(in.Skipped) > 0 {
		fmt.Fprintf(&b, "### Skipped / Unmatched Containers\n\n")
		fmt.Fprintf(&b, "| Container ID | Image | Labels | Reason |\n|---|---|---|---|\n")
		for _, s := range in.Skipped {
			var kv []string
			for k, v := range s.Labels {
				kv = append(kv, fmt.Sprintf("%s=%s", k, v))
			}
			sort.Strings(kv)
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` |\n",
				s.ID, s.Image, strings.Join(kv, ","), s.Reason)
		}
		fmt.Fprintln(&b)
	}

	if unapprovedCount > 0 {
		fmt.Fprintf(&b, "### Auditing & Approval Guidance\n\n")
		fmt.Fprintf(&b, "To approve intentional new syscalls, add an entry to `.seccomp-profiler/accepted.yml` with a rationale and optional expiration date. ")
		fmt.Fprintf(&b, "Protect `.seccomp-profiler/` and committed seccomp profiles in `.github/CODEOWNERS` so security-sensitive approvals require security team review.\n")
	}

	return b.String()
}

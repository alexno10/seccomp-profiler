package profile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestMergeCommittedIntoOCI_DedupsExtraRulesAndResolvesAllowDenyConflict(t *testing.T) {
	masked := []OCISyscallArg{{Index: 0, Value: cloneNewNamespaceMask, Op: "SCMP_CMP_MASKED_EQ"}}
	errno38 := uint32(38)

	curr := &OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Syscalls: []OCISyscallRule{
			{Names: []string{"read", "clone3"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"clone"}, Action: "SCMP_ACT_ALLOW", Args: masked},
			{Names: []string{"ptrace"}, Action: "SCMP_ACT_ERRNO", ErrnoRet: &errno38},
		},
	}
	committed := &OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Syscalls: []OCISyscallRule{
			{Names: []string{"write"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"clone"}, Action: "SCMP_ACT_ALLOW", Args: masked},
			{Names: []string{"clone3", "ptrace"}, Action: "SCMP_ACT_ERRNO", ErrnoRet: &errno38},
		},
	}

	MergeCommittedIntoOCI(curr, committed)

	// Count rule occurrences per syscall name.
	cloneCount := 0
	clone3Rules := []OCISyscallRule{}
	ptraceCount := 0
	for _, r := range curr.Syscalls {
		for _, n := range r.Names {
			switch n {
			case "clone":
				cloneCount++
			case "clone3":
				clone3Rules = append(clone3Rules, r)
			case "ptrace":
				ptraceCount++
			}
		}
	}
	if cloneCount != 1 {
		t.Fatalf("expected clone in exactly 1 rule after dedup, got %d (%+v)", cloneCount, curr.Syscalls)
	}
	if ptraceCount != 1 {
		t.Fatalf("expected ptrace in exactly 1 deny rule after dedup, got %d (%+v)", ptraceCount, curr.Syscalls)
	}
	if len(clone3Rules) != 1 || clone3Rules[0].Action != "SCMP_ACT_ALLOW" {
		t.Fatalf("expected unconditional allow clone3 to resolve committed errno conflict without duplicate rule, got %+v", clone3Rules)
	}
}

func TestMergeRawProfiles_RejectsMismatchedArchAndCountsSummaryShards(t *testing.T) {
	amd := &RawProfileV1{
		SchemaVersion: "v1",
		Host:          RawHostInfo{Arch: "amd64"},
		Target:        RawTargetInfo{Name: "api", ContainerCount: 1, Containers: []RawContainerInfo{{ID: "c1"}}},
		Syscalls:      map[string]RawSyscallEntry{"read": {Sources: []string{"observed"}, TotalCalls: 1, ContainersSeen: 1}},
	}
	arm := &RawProfileV1{
		SchemaVersion: "v1",
		Host:          RawHostInfo{Arch: "arm64"},
		Target:        RawTargetInfo{Name: "api", ContainerCount: 1, Containers: []RawContainerInfo{{ID: "c2"}}},
		Syscalls:      map[string]RawSyscallEntry{"read": {Sources: []string{"observed"}, TotalCalls: 1, ContainersSeen: 1}},
	}
	if _, err := MergeRawProfiles([]*RawProfileV1{amd, arm}, time.Now().UTC(), "test"); err == nil {
		t.Fatal("expected error when merging shards from different architectures")
	}

	summaryShard := &RawProfileV1{
		SchemaVersion: "v1",
		Host:          RawHostInfo{Arch: "amd64"},
		Target:        RawTargetInfo{Name: "api", ContainerCount: 2}, // Containers slice empty
		Syscalls: map[string]RawSyscallEntry{
			"read":   {Sources: []string{"observed"}, TotalCalls: 5, ContainersSeen: 2},
			"clone3": {Sources: []string{"observed", "extra-allow"}, TotalCalls: 1, ContainersSeen: 1},
		},
	}
	merged, err := MergeRawProfiles([]*RawProfileV1{amd, summaryShard}, time.Now().UTC(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if merged[0].Raw.Target.ContainerCount != 3 {
		t.Fatalf("expected ContainerCount 3 (1 container info + 2 summary), got %d", merged[0].Raw.Target.ContainerCount)
	}
	// extra-allow provenance on clone3 must stay unconditional allow in OCI.
	foundClone3Allow := false
	for _, r := range merged[0].OCI.Syscalls {
		if r.Action == "SCMP_ACT_ALLOW" {
			for _, n := range r.Names {
				if n == "clone3" {
					foundClone3Allow = true
				}
			}
		}
	}
	if !foundClone3Allow {
		t.Fatalf("expected extra-allow clone3 in MergeRawProfiles to stay SCMP_ACT_ALLOW, got %+v", merged[0].OCI.Syscalls)
	}
}

func TestWriteFileAtomic_RejectsSymlinkDestination(t *testing.T) {
	if runtime.GOOS == "windows" {
		// os.Symlink on Windows may require SeCreateSymbolicLinkPrivilege; skip symlink setup if denied.
		tmp := t.TempDir()
		realTarget := filepath.Join(tmp, "real.txt")
		_ = os.WriteFile(realTarget, []byte("orig"), 0o644)
		linkPath := filepath.Join(tmp, "link.txt")
		if err := os.Symlink(realTarget, linkPath); err != nil {
			t.Skipf("symlink creation not permitted on Windows: %v", err)
		}
		if err := writeFileAtomic(linkPath, []byte("overwritten")); err == nil {
			t.Fatal("expected writeFileAtomic to reject symlink destination")
		}
		return
	}
	tmp := t.TempDir()
	realTarget := filepath.Join(tmp, "real.txt")
	if err := os.WriteFile(realTarget, []byte("orig"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(tmp, "link.txt")
	if err := os.Symlink(realTarget, linkPath); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(linkPath, []byte("overwritten")); err == nil {
		t.Fatal("expected writeFileAtomic to reject symlink destination")
	}
}

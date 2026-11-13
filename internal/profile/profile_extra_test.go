package profile_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/baseline"
	"github.com/alexno10/seccomp-profiler/internal/profile"
	"github.com/alexno10/seccomp-profiler/internal/selector"
	"github.com/alexno10/seccomp-profiler/internal/syscalls"
)

func buildTarget(t *testing.T, hits map[int]uint32, extra []string, arch syscalls.Arch) *profile.BuiltProfile {
	t.Helper()
	target := selector.MatchedTarget{
		Name:                 "api",
		GroupBy:              "image",
		Containers:           []selector.ContainerRecord{{ID: "c1", Image: "myorg/api:v1"}},
		MergedHits:           hits,
		ContainersPerSyscall: map[int]int{},
	}
	for nr := range hits {
		target.ContainersPerSyscall[nr] = 1
	}
	built, err := profile.Build(target, profile.BuildOptions{
		Arch:         arch,
		BaselineMode: baseline.ModeNone,
		RuntimeMode:  "none",
		ExtraAllow:   extra,
	})
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	return built
}

func findRule(r profile.OCISeccompProfile, name string) *profile.OCISyscallRule {
	for i := range r.Syscalls {
		for _, n := range r.Syscalls[i].Names {
			if n == name {
				return &r.Syscalls[i]
			}
		}
	}
	return nil
}

// Review item 12: clone stays arg-constrained (CLONE_NEW* masked out, like
// Docker's default profile) and clone3 answers ENOSYS so libcs fall back.
func TestBuildConstrainsCloneNamespaceCreation(t *testing.T) {
	// amd64: clone=56, clone3=435
	built := buildTarget(t, map[int]uint32{56: 10, 435: 5}, nil, syscalls.ArchAMD64)

	if built.OCI.DefaultErrnoRet == nil || *built.OCI.DefaultErrnoRet != 38 {
		t.Fatalf("expected defaultErrnoRet=38 (ENOSYS), got %+v", built.OCI.DefaultErrnoRet)
	}

	cloneRule := findRule(built.OCI, "clone")
	if cloneRule == nil {
		t.Fatal("expected clone rule")
	}
	if len(cloneRule.Args) != 1 || cloneRule.Args[0].Op != "SCMP_CMP_MASKED_EQ" ||
		cloneRule.Args[0].Value != 2114060288 || cloneRule.Args[0].Index != 0 {
		t.Fatalf("expected CLONE_NEW* masked arg constraint, got %+v", cloneRule.Args)
	}

	clone3 := findRule(built.OCI, "clone3")
	if clone3 == nil {
		t.Fatal("expected clone3 rule")
	}
	if clone3.Action != "SCMP_ACT_ERRNO" || clone3.ErrnoRet == nil || *clone3.ErrnoRet != 38 {
		t.Fatalf("expected clone3 ERRNO/ENOSYS rule, got %+v", *clone3)
	}
}

// Explicit extra-allow wins: the user consciously asked for an unconditional
// clone allow.
func TestBuildExtraAllowUnconditionalClone(t *testing.T) {
	built := buildTarget(t, map[int]uint32{56: 10}, []string{"clone"}, syscalls.ArchAMD64)
	rule := findRule(built.OCI, "clone")
	if rule == nil || len(rule.Args) != 0 {
		t.Fatalf("expected extra-allowed clone to stay unconditional, got %+v", rule)
	}
}

// Review Low: baseline syscalls that do not exist on the target architecture
// (access/dup2/arch_prctl on arm64) must be filtered out.
func TestBuildFiltersBaselineNamesByArch(t *testing.T) {
	target := selector.MatchedTarget{
		Name:       "api",
		GroupBy:    "image",
		Containers: []selector.ContainerRecord{{ID: "c1", Image: "myorg/api:v1"}},
	}
	built, err := profile.Build(target, profile.BuildOptions{
		Arch:         syscalls.ArchARM64,
		BaselineMode: baseline.ModeStandard,
		RuntimeMode:  "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, missingOnArm64 := range []string{"access", "dup2", "arch_prctl"} {
		if findRule(built.OCI, missingOnArm64) != nil {
			t.Fatalf("syscall %q does not exist on arm64 but leaked into the profile", missingOnArm64)
		}
	}
	if findRule(built.OCI, "exit_group") == nil {
		t.Fatal("expected lifecycle syscalls to survive arm64 filtering")
	}
}

// Review item 2/merge invariant: arg-constrained rules from the generated
// profile must survive MergeCommittedIntoOCI, and committed conditional rules
// must never widen generated unconditional ones.
func TestMergePreservesArgRulesBothDirections(t *testing.T) {
	masked := []profile.OCISyscallArg{{Index: 0, Value: 2114060288, Op: "SCMP_CMP_MASKED_EQ"}}
	curr := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"clone"}, Action: "SCMP_ACT_ALLOW", Args: masked},
		},
	}
	committed := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"chmod"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"ioctl"}, Action: "SCMP_ACT_ALLOW", Args: masked},
		},
	}

	profile.MergeCommittedIntoOCI(curr, committed)

	cloneRule := findRule(*curr, "clone")
	if cloneRule == nil || len(cloneRule.Args) == 0 {
		t.Fatalf("generated clone arg constraint must survive merge, got %+v", curr.Syscalls)
	}
	ioctlRule := findRule(*curr, "ioctl")
	if ioctlRule == nil || len(ioctlRule.Args) == 0 {
		t.Fatalf("committed ioctl arg rule must survive merge, got %+v", curr.Syscalls)
	}
	if findRule(*curr, "chmod") == nil {
		t.Fatal("committed unconditional allows must be merged in")
	}
}

// Review item 5: target names come from labels and must not traverse paths.
func TestValidateTargetName(t *testing.T) {
	for _, bad := range []string{"../etc/evil", "..", ".", "a/b", "a\\b", "", strings.Repeat("x", 101)} {
		if err := profile.ValidateTargetName(bad); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
	for _, good := range []string{"api", "payment-api", "web_2", "svc.name"} {
		if err := profile.ValidateTargetName(good); err != nil {
			t.Fatalf("expected %q to be accepted: %v", good, err)
		}
	}
}

// Review item 20: pre-existing containers are flagged as partial in raw.
func TestRawMarksPreexistingContainers(t *testing.T) {
	target := selector.MatchedTarget{
		Name:       "api",
		GroupBy:    "image",
		Containers: []selector.ContainerRecord{{ID: "c1", Image: "img", Preexisting: true}},
	}
	built, err := profile.Build(target, profile.BuildOptions{BaselineMode: baseline.ModeNone, RuntimeMode: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if !built.Raw.Target.Containers[0].Preexisting {
		t.Fatal("expected preexisting flag in raw artifact")
	}
	blob, _ := json.Marshal(built.Raw.Target.Containers[0])
	if string(blob) == "" {
		t.Fatal("marshal failed")
	}
}

// MergeRawProfiles applies the same clone constraint and native-only archs.
func TestMergeRawProfilesConstrainsClone(t *testing.T) {
	shard := &profile.RawProfileV1{
		SchemaVersion: "v1",
		Host:          profile.RawHostInfo{Arch: "amd64"},
		Target:        profile.RawTargetInfo{Name: "api", ContainerCount: 1},
		Syscalls: map[string]profile.RawSyscallEntry{
			"clone":  {Sources: []string{"observed"}, TotalCalls: 3, ContainersSeen: 1},
			"clone3": {Sources: []string{"observed"}, TotalCalls: 1, ContainersSeen: 1},
		},
	}
	merged, err := profile.MergeRawProfiles([]*profile.RawProfileV1{shard}, time.Now().UTC(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 1 {
		t.Fatal("expected one merged target")
	}
	cloneRule := findRule(merged[0].OCI, "clone")
	if cloneRule == nil || len(cloneRule.Args) != 1 {
		t.Fatalf("merged profile must constrain clone, got %+v", merged[0].OCI.Syscalls)
	}
	clone3 := findRule(merged[0].OCI, "clone3")
	if clone3 == nil || clone3.Action != "SCMP_ACT_ERRNO" {
		t.Fatalf("merged profile must ENOSYS clone3, got %+v", merged[0].OCI.Syscalls)
	}
	if !reflect.DeepEqual(merged[0].OCI.Architectures, []string{"SCMP_ARCH_X86_64"}) {
		t.Fatalf("expected native-only arch list, got %v", merged[0].OCI.Architectures)
	}
}

func TestMergeCommittedIntoOCIDoesNotTreatEmptyActionAsAllow(t *testing.T) {
	curr := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"mount"}, Action: ""},
		},
	}
	committed := &profile.OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []profile.OCISyscallRule{
			{Names: []string{"write"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"ptrace"}, Action: ""},
		},
	}
	profile.MergeCommittedIntoOCI(curr, committed)
	for _, r := range curr.Syscalls {
		if r.Action == "SCMP_ACT_ALLOW" {
			for _, name := range r.Names {
				if name == "ptrace" || name == "mount" {
					t.Fatalf("empty-action rule %q must not be promoted to SCMP_ACT_ALLOW: %+v", name, curr.Syscalls)
				}
			}
		}
	}
	allowRule := findRule(*curr, "write")
	if allowRule == nil || allowRule.Action != "SCMP_ACT_ALLOW" {
		t.Fatalf("expected write to remain allowed, got %+v", curr.Syscalls)
	}
}

func TestUpdateCommittedProfilesLockProtectionAndMultiTarget(t *testing.T) {
	tmp := t.TempDir()
	built := buildTarget(t, map[int]uint32{0: 1}, nil, syscalls.ArchAMD64)
	handwritten := []byte("{\n  \"defaultAction\": \"SCMP_ACT_ERRNO\",\n  \"comment\": \"manual edit\"\n}\n")

	// 1. Missing lock.json must protect existing profile and write .suggested.json instead.
	commDir := filepath.Join(tmp, "comm-nolock")
	if err := os.MkdirAll(commDir, 0o755); err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(commDir, "api.json")
	if err := os.WriteFile(targetPath, handwritten, 0o644); err != nil {
		t.Fatal(err)
	}
	updated, err := profile.UpdateCommittedProfiles(filepath.Join(commDir, "{name}.json"), filepath.Join(tmp, "missing-lock.json"), []*profile.BuiltProfile{built})
	if err != nil {
		t.Fatalf("UpdateCommittedProfiles failed: %v", err)
	}
	got, _ := os.ReadFile(targetPath)
	if !reflect.DeepEqual(got, handwritten) {
		t.Fatalf("existing committed profile was overwritten without lock.json")
	}
	suggestedPath := filepath.Join(commDir, "api.suggested.json")
	if _, statErr := os.Stat(suggestedPath); statErr != nil {
		t.Fatalf("expected api.suggested.json when lock.json is missing: %v", statErr)
	}
	if len(updated) != 1 || updated[0] != suggestedPath {
		t.Fatalf("expected updated=[%s], got %v", suggestedPath, updated)
	}

	// 2. Lock file present without target key must also protect existing profile.
	partialLock := filepath.Join(tmp, "partial-lock.json")
	if err := os.WriteFile(partialLock, []byte(`{"files":{"other":"deadbeef"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	commDir2 := filepath.Join(tmp, "comm-nokey")
	if err := os.MkdirAll(commDir2, 0o755); err != nil {
		t.Fatal(err)
	}
	targetPath2 := filepath.Join(commDir2, "api.json")
	if err := os.WriteFile(targetPath2, handwritten, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.UpdateCommittedProfiles(filepath.Join(commDir2, "{name}.json"), partialLock, []*profile.BuiltProfile{built}); err != nil {
		t.Fatalf("UpdateCommittedProfiles nokey failed: %v", err)
	}
	got2, _ := os.ReadFile(targetPath2)
	if !reflect.DeepEqual(got2, handwritten) {
		t.Fatalf("existing committed profile was overwritten when key absent from lock.json")
	}

	// 3. Corrupt lock.json must fail closed in both WriteTargetFiles and UpdateCommittedProfiles.
	corruptLock := filepath.Join(tmp, "corrupt-lock.json")
	if err := os.WriteFile(corruptLock, []byte(`{not-json`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.WriteTargetFiles(filepath.Join(tmp, "out-c"), filepath.Join(tmp, "raw-c"), corruptLock, []*profile.BuiltProfile{built}); err == nil {
		t.Fatal("expected WriteTargetFiles to fail closed on corrupt lock.json")
	}
	if _, err := profile.UpdateCommittedProfiles(filepath.Join(commDir2, "{name}.json"), corruptLock, []*profile.BuiltProfile{built}); err == nil {
		t.Fatal("expected UpdateCommittedProfiles to fail closed on corrupt lock.json")
	}

	// 4. Multi-target parity with diff.ResolveCommittedProfilePath when pattern ends in .json without {name}.
	multiDir := filepath.Join(tmp, "multi")
	worker := buildTarget(t, map[int]uint32{1: 1}, nil, syscalls.ArchAMD64)
	worker.TargetName = "worker"
	worker.Raw.Target.Name = "worker"
	if _, err := profile.UpdateCommittedProfiles(filepath.Join(multiDir, "profile.json"), filepath.Join(tmp, "multi-lock.json"), []*profile.BuiltProfile{built, worker}); err != nil {
		t.Fatalf("multi-target UpdateCommittedProfiles failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(multiDir, "api.json")); err != nil {
		t.Fatalf("expected multi-target api.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(multiDir, "worker.json")); err != nil {
		t.Fatalf("expected multi-target worker.json: %v", err)
	}
}

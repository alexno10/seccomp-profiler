package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/baseline"
	"github.com/alexno10/seccomp-profiler/internal/selector"
	"github.com/alexno10/seccomp-profiler/internal/syscalls"
)

// cloneNewNamespaceMask is the OR of CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|
// CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET (0x7E020000), matching
// the arg constraint Docker's default seccomp profile applies to clone().
const cloneNewNamespaceMask = 2114060288

// errnoRetENOSYS makes unknown/blocked syscalls return -ENOSYS so glibc and
// musl fall back to older syscall paths (clone3->clone, faccessat2, statx...).
const errnoRetENOSYS uint32 = 38

type OCISeccompProfile struct {
	DefaultAction   string           `json:"defaultAction"`
	DefaultErrnoRet *uint32          `json:"defaultErrnoRet,omitempty"`
	Architectures   []string         `json:"architectures"`
	Syscalls        []OCISyscallRule `json:"syscalls"`
}

type OCISyscallRule struct {
	Names    []string        `json:"names"`
	Action   string          `json:"action"`
	ErrnoRet *uint32         `json:"errnoRet,omitempty"`
	Args     []OCISyscallArg `json:"args,omitempty"`
}

type OCISyscallArg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo,omitempty"`
	Op       string `json:"op"`
}

type RawHostInfo struct {
	Arch        string `json:"arch"`
	SeccompArch string `json:"seccompArch"`
	Kernel      string `json:"kernel"`
}

type RawContainerInfo struct {
	ID          string            `json:"id"`
	Image       string            `json:"image"`
	Labels      map[string]string `json:"labels,omitempty"`
	DurationMs  int64             `json:"durationMs"`
	Preexisting bool              `json:"preexisting,omitempty"`
}

type RawTargetInfo struct {
	Name               string             `json:"name"`
	GroupBy            string             `json:"groupBy"`
	ContainerCount     int                `json:"containerCount"`
	DetectedRuntimes   []string           `json:"detectedRuntimes"`
	CompatSyscallCount uint32             `json:"compatSyscallCount"`
	Containers         []RawContainerInfo `json:"containers"`
}

type RawSyscallEntry struct {
	Sources        []string `json:"sources"`
	TotalCalls     uint64   `json:"totalCalls"`
	ContainersSeen int      `json:"containersSeen"`
}

type RawProfileV1 struct {
	SchemaVersion    string                     `json:"schemaVersion"`
	GeneratedAt      string                     `json:"generatedAt"`
	GeneratorVersion string                     `json:"generatorVersion"`
	Host             RawHostInfo                `json:"host"`
	Target           RawTargetInfo              `json:"target"`
	Syscalls         map[string]RawSyscallEntry `json:"syscalls"`
}

type BuildOptions struct {
	Arch             syscalls.Arch
	Kernel           string
	GeneratorVersion string
	GeneratedAt      time.Time
	BaselineMode     baseline.Mode
	RuntimeMode      string
	ExtraAllow       []string
}

type BuiltProfile struct {
	TargetName string
	OCI        OCISeccompProfile
	Raw        RawProfileV1
}

type WriteResult struct {
	TargetName          string
	ProfilePath         string
	SuggestedPath       string
	RawPath             string
	ProtectedManualEdit bool
}

type lockFileSchema struct {
	Files map[string]string `json:"files"`
}

func Build(target selector.MatchedTarget, opts BuildOptions) (*BuiltProfile, error) {
	arch := opts.Arch
	if arch == "" {
		arch = syscalls.ArchAMD64
	}
	genAt := opts.GeneratedAt
	if genAt.IsZero() {
		genAt = time.Now().UTC()
	}
	ver := opts.GeneratorVersion
	if ver == "" {
		ver = "1.1.1"
	}

	// 32-bit compat syscalls are reported but deliberately not profiled:
	// the profile stays native-only and the diff gate fails on compat hits.
	seccompArchs := syscalls.SeccompArchitectures(arch, false)
	primarySeccompArch := seccompArchs[0]

	var detectedRuntimes []string
	rtMode := strings.ToLower(strings.TrimSpace(opts.RuntimeMode))
	switch rtMode {
	case "", "auto":
		var firstImage string
		if len(target.Containers) > 0 {
			firstImage = target.Containers[0].Image
		}
		detectedRuntimes = baseline.DetectRuntimes(target.ExecutedBins, firstImage)
	case "none":
		detectedRuntimes = []string{}
	default:
		detectedRuntimes = []string{rtMode}
	}

	entries := make(map[string]*RawSyscallEntry)
	addSource := func(name, src string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		e, ok := entries[name]
		if !ok {
			e = &RawSyscallEntry{}
			entries[name] = e
		}
		for _, existing := range e.Sources {
			if existing == src {
				return
			}
		}
		e.Sources = append(e.Sources, src)
	}
	// nameKnownToArch filters baseline layer names that do not exist on the
	// target architecture (e.g. access/dup2/arch_prctl on arm64).
	nameKnownToArch := func(name string) bool {
		_, ok := syscalls.NumberByName(arch, name)
		return ok
	}
	addBaselineSource := func(name, src string) {
		if !nameKnownToArch(name) {
			return
		}
		addSource(name, src)
	}

	for nr, count := range target.MergedHits {
		if count == 0 {
			continue
		}
		name, ok := syscalls.NameByNumber(arch, nr)
		if !ok {
			continue
		}
		addSource(name, baseline.SourceObserved)
		entries[name].TotalCalls += uint64(count)
		entries[name].ContainersSeen = target.ContainersPerSyscall[nr]
	}

	baseLayers := baseline.LayerSyscalls(opts.BaselineMode, "")
	for _, name := range baseLayers[baseline.SourceRuntime] {
		addBaselineSource(name, baseline.SourceRuntime)
	}
	for _, name := range baseLayers[baseline.SourceLifecycle] {
		addBaselineSource(name, baseline.SourceLifecycle)
	}
	for _, rt := range detectedRuntimes {
		rtLayers := baseline.LayerSyscalls(baseline.ModeNone, rt)
		src := baseline.LangSource(rt)
		for _, name := range rtLayers[src] {
			addBaselineSource(name, src)
		}
	}
	extraAllowed := make(map[string]bool)
	for _, extra := range opts.ExtraAllow {
		for _, tok := range strings.FieldsFunc(extra, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
		}) {
			addSource(tok, baseline.SourceExtraAllow)
			extraAllowed[strings.TrimSpace(tok)] = true
		}
	}

	var allNames []string
	rawSyscalls := make(map[string]RawSyscallEntry, len(entries))
	for name, e := range entries {
		allNames = append(allNames, name)
		rawSyscalls[name] = *e
	}
	sort.Strings(allNames)

	var rawContainers []RawContainerInfo
	for _, c := range target.Containers {
		rawContainers = append(rawContainers, RawContainerInfo{
			ID:          c.ID,
			Image:       c.Image,
			Labels:      c.Labels,
			DurationMs:  c.DurationMs,
			Preexisting: c.Preexisting,
		})
	}
	if rawContainers == nil {
		rawContainers = []RawContainerInfo{}
	}
	if detectedRuntimes == nil {
		detectedRuntimes = []string{}
	}

	eni := errnoRetENOSYS
	oci := OCISeccompProfile{
		DefaultAction:   "SCMP_ACT_ERRNO",
		DefaultErrnoRet: &eni,
		Architectures:   seccompArchs,
	}

	// Partition the allow list: clone must stay arg-constrained (namespace
	// creation masked out, like Docker's default profile) and clone3 is
	// answered with ENOSYS so libcs fall back to clone. Syscalls that the
	// user explicitly requested via extra-allow are left unconditional.
	var plainNames []string
	var cloneNames []string
	for _, name := range allNames {
		if name == "clone" && !extraAllowed["clone"] {
			cloneNames = append(cloneNames, name)
			continue
		}
		if name == "clone3" && !extraAllowed["clone3"] {
			cloneNames = append(cloneNames, name)
			continue
		}
		plainNames = append(plainNames, name)
	}
	if len(plainNames) > 0 {
		oci.Syscalls = append(oci.Syscalls, OCISyscallRule{
			Names:  plainNames,
			Action: "SCMP_ACT_ALLOW",
		})
	}
	if len(cloneNames) > 0 {
		var cloneAllow, clone3Deny []string
		for _, name := range cloneNames {
			if name == "clone" {
				cloneAllow = append(cloneAllow, name)
			} else {
				clone3Deny = append(clone3Deny, name)
			}
		}
		if len(cloneAllow) > 0 {
			oci.Syscalls = append(oci.Syscalls, OCISyscallRule{
				Names:  cloneAllow,
				Action: "SCMP_ACT_ALLOW",
				Args: []OCISyscallArg{{
					Index:    0,
					Value:    cloneNewNamespaceMask,
					ValueTwo: 0,
					Op:       "SCMP_CMP_MASKED_EQ",
				}},
			})
		}
		if len(clone3Deny) > 0 {
			errno := errnoRetENOSYS
			oci.Syscalls = append(oci.Syscalls, OCISyscallRule{
				Names:    clone3Deny,
				Action:   "SCMP_ACT_ERRNO",
				ErrnoRet: &errno,
			})
		}
	}

	raw := RawProfileV1{
		SchemaVersion:    "v1",
		GeneratedAt:      genAt.UTC().Format(time.RFC3339),
		GeneratorVersion: ver,
		Host: RawHostInfo{
			Arch:        string(arch),
			SeccompArch: primarySeccompArch,
			Kernel:      opts.Kernel,
		},
		Target: RawTargetInfo{
			Name:               target.Name,
			GroupBy:            target.GroupBy,
			ContainerCount:     len(target.Containers),
			DetectedRuntimes:   detectedRuntimes,
			CompatSyscallCount: target.CompatHits,
			Containers:         rawContainers,
		},
		Syscalls: rawSyscalls,
	}

	return &BuiltProfile{
		TargetName: target.Name,
		OCI:        oci,
		Raw:        raw,
	}, nil
}

func loadLockFile(lockFile string) (lockFileSchema, error) {
	lock := lockFileSchema{Files: make(map[string]string)}
	if strings.TrimSpace(lockFile) == "" {
		return lock, nil
	}
	lockData, err := os.ReadFile(lockFile)
	if err != nil {
		if os.IsNotExist(err) {
			return lock, nil
		}
		return lockFileSchema{}, fmt.Errorf("read lock file %q: %w", lockFile, err)
	}
	if err := json.Unmarshal(lockData, &lock); err != nil {
		return lockFileSchema{}, fmt.Errorf("parse lock file %q: %w", lockFile, err)
	}
	if lock.Files == nil {
		lock.Files = make(map[string]string)
	}
	return lock, nil
}

func saveLockFile(lockFile string, lock lockFileSchema) error {
	if strings.TrimSpace(lockFile) == "" {
		return nil
	}
	if err := mkdirAllChown(filepath.Dir(lockFile), 0o755); err != nil {
		return err
	}
	lockBytes, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	lockBytes = append(lockBytes, '\n')
	if err := writeFileAtomic(lockFile, lockBytes); err != nil {
		return err
	}
	chownToSudoUser(lockFile)
	return nil
}

// LoadLockHashes loads a snapshot of existing target->sha256 entries from
// lockFile. Missing lockFile returns an empty map; corrupt lockFile fails.
func LoadLockHashes(lockFile string) (map[string]string, error) {
	lock, err := loadLockFile(lockFile)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(lock.Files))
	for k, v := range lock.Files {
		out[k] = v
	}
	return out, nil
}

func WriteTargetFiles(outDir, rawDir, lockFile string, built []*BuiltProfile) ([]WriteResult, error) {
	if err := mkdirAllChown(outDir, 0o755); err != nil {
		return nil, err
	}
	if err := mkdirAllChown(rawDir, 0o755); err != nil {
		return nil, err
	}

	lock, err := loadLockFile(lockFile)
	if err != nil {
		return nil, err
	}

	var results []WriteResult
	for _, b := range built {
		// Defense in depth against path traversal via target names derived
		// from container labels.
		if err := ValidateTargetName(b.TargetName); err != nil {
			return nil, err
		}
		ociBytes, err := json.MarshalIndent(b.OCI, "", "  ")
		if err != nil {
			return nil, err
		}
		ociBytes = append(ociBytes, '\n')

		rawBytes, err := json.MarshalIndent(b.Raw, "", "  ")
		if err != nil {
			return nil, err
		}
		rawBytes = append(rawBytes, '\n')

		profilePath := filepath.Join(outDir, b.TargetName+".json")
		rawPath := filepath.Join(rawDir, b.TargetName+".profile.v1.json")
		if err := writeFileAtomic(rawPath, rawBytes); err != nil {
			return nil, err
		}
		chownToSudoUser(rawPath)

		res := WriteResult{
			TargetName:  b.TargetName,
			ProfilePath: profilePath,
			RawPath:     rawPath,
		}

		if existingBytes, err := os.ReadFile(profilePath); err == nil {
			existingHash := sha256Hex(existingBytes)
			lockedHash, hasLock := lock.Files[b.TargetName]
			if !hasLock || lockedHash != existingHash {
				res.ProtectedManualEdit = true
				res.SuggestedPath = filepath.Join(outDir, b.TargetName+".suggested.json")
				if err := writeFileAtomic(res.SuggestedPath, ociBytes); err != nil {
					return nil, err
				}
				chownToSudoUser(res.SuggestedPath)
				results = append(results, res)
				continue
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}

		if err := writeFileAtomic(profilePath, ociBytes); err != nil {
			return nil, err
		}
		chownToSudoUser(profilePath)
		lock.Files[b.TargetName] = sha256Hex(ociBytes)
		results = append(results, res)
	}

	if err := saveLockFile(lockFile, lock); err != nil {
		return nil, err
	}

	return results, nil
}

// UpdateCommittedProfiles implements on-change: update-pr. It writes the newly
// generated profiles to the committed-profile location in the working tree so
// the PR author can commit them. Existing profiles without a matching lock
// entry (missing lock file, missing key, or hash mismatch) are never
// overwritten; a .suggested.json is written next to them instead.
func UpdateCommittedProfiles(committedPattern, lockFile string, built []*BuiltProfile) ([]string, error) {
	return SyncCommittedProfiles(committedPattern, "", lockFile, nil, nil, built)
}

// SyncCommittedProfiles updates committed profiles while honoring lock state
// snapshotted before WriteTargetFiles (preLock) and reusing WriteTargetFiles
// protection decisions when outDir and committedPattern resolve to the same file.
func SyncCommittedProfiles(
	committedPattern, outDir, lockFile string,
	writeResults []WriteResult, preLock map[string]string,
	built []*BuiltProfile,
) ([]string, error) {
	if strings.TrimSpace(committedPattern) == "" {
		return nil, nil
	}
	lock, err := loadLockFile(lockFile)
	if err != nil {
		return nil, err
	}
	baselineHashes := lock.Files
	if preLock != nil {
		baselineHashes = preLock
	}
	wrByTarget := make(map[string]WriteResult, len(writeResults))
	for _, w := range writeResults {
		wrByTarget[w.TargetName] = w
	}

	var updated []string
	lockDirty := false
	for _, b := range built {
		if err := ValidateTargetName(b.TargetName); err != nil {
			return nil, err
		}
		path := ResolveTargetProfilePathN(committedPattern, b.TargetName, len(built))
		if path == "" {
			continue
		}
		if outDir != "" {
			outPath := filepath.Join(outDir, b.TargetName+".json")
			if sameTargetPath(path, outPath) {
				if wr, ok := wrByTarget[b.TargetName]; ok {
					if wr.ProtectedManualEdit && wr.SuggestedPath != "" {
						updated = append(updated, wr.SuggestedPath)
					} else if wr.ProfilePath != "" {
						updated = append(updated, wr.ProfilePath)
					}
					continue
				}
			}
		}

		ociBytes, err := json.MarshalIndent(b.OCI, "", "  ")
		if err != nil {
			return nil, err
		}
		ociBytes = append(ociBytes, '\n')

		if existing, err := os.ReadFile(path); err == nil {
			locked, hasLock := baselineHashes[b.TargetName]
			if !hasLock || locked != sha256Hex(existing) {
				suggested := filepath.Join(filepath.Dir(path), b.TargetName+".suggested.json")
				if err := writeFileAtomic(suggested, ociBytes); err != nil {
					return nil, err
				}
				chownToSudoUser(suggested)
				updated = append(updated, suggested)
				continue
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		if err := mkdirAllChown(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if err := writeFileAtomic(path, ociBytes); err != nil {
			return nil, err
		}
		chownToSudoUser(path)
		lock.Files[b.TargetName] = sha256Hex(ociBytes)
		lockDirty = true
		updated = append(updated, path)
	}
	if lockDirty {
		if err := saveLockFile(lockFile, lock); err != nil {
			return nil, err
		}
	}
	return updated, nil
}

func sameTargetPath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA == nil && errB == nil {
		if runtime.GOOS == "windows" {
			return strings.EqualFold(filepath.Clean(absA), filepath.Clean(absB))
		}
		return filepath.Clean(absA) == filepath.Clean(absB)
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// ResolveTargetProfilePath mirrors diff.ResolveCommittedProfilePath for a single target.
func ResolveTargetProfilePath(pattern, targetName string) string {
	return ResolveTargetProfilePathN(pattern, targetName, 1)
}

// ResolveTargetProfilePathN mirrors diff.ResolveCommittedProfilePath without
// importing the diff package (avoids an import cycle).
func ResolveTargetProfilePathN(pattern, targetName string, totalTargets int) string {
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

// ValidateTargetName rejects target names that could escape the output
// directory (names come from container labels and image names).
func ValidateTargetName(name string) error {
	if name == "" || len(name) > 100 {
		return fmt.Errorf("invalid target name %q: must be 1-100 characters", name)
	}
	if name == "." || strings.HasPrefix(name, "..") {
		return fmt.Errorf("invalid target name %q: must not be a relative path component", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return fmt.Errorf("invalid target name %q: only [A-Za-z0-9._-] characters are allowed", name)
		}
	}
	return nil
}

func mkdirAllChown(dir string, perm os.FileMode) error {
	if strings.TrimSpace(dir) == "" || dir == "." {
		return nil
	}
	var missing []string
	cur := filepath.Clean(dir)
	for {
		if _, err := os.Lstat(cur); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return err
		}
		missing = append(missing, cur)
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	if err := os.MkdirAll(dir, perm); err != nil {
		return err
	}
	for i := len(missing) - 1; i >= 0; i-- {
		chownToSudoUser(missing[i])
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlink %s", path)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".seccomp-profiler-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	chownToSudoUser(tmpName)
	return os.Rename(tmpName, path)
}

// chownToSudoUser hands root-owned output files back to the CI runner user
// (sudo sets SUDO_UID/SUDO_GID for the daemon process).
func chownToSudoUser(paths ...string) {
	uidStr := os.Getenv("SUDO_UID")
	gidStr := os.Getenv("SUDO_GID")
	if uidStr == "" && gidStr == "" {
		return
	}
	uid := -1
	gid := -1
	if v, err := strconv.Atoi(uidStr); err == nil && v >= 0 {
		uid = v
	}
	if v, err := strconv.Atoi(gidStr); err == nil && v >= 0 {
		gid = v
	}
	if uid < 0 && gid < 0 {
		return
	}
	for _, p := range paths {
		_ = os.Chown(p, uid, gid)
	}
}

func LoadOCIProfile(path string) (*OCISeccompProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p OCISeccompProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func LoadRawProfileV1(path string) (*RawProfileV1, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw RawProfileV1
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw.SchemaVersion != "" && raw.SchemaVersion != "v1" {
		return nil, fmt.Errorf("unsupported raw profile schemaVersion %q in %q", raw.SchemaVersion, path)
	}
	return &raw, nil
}

func MergeRawProfiles(raws []*RawProfileV1, generatedAt time.Time, generatorVersion string) ([]*BuiltProfile, error) {
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	if generatorVersion == "" {
		generatorVersion = "1.1.1"
	}

	byTarget := make(map[string][]*RawProfileV1)
	var targetOrder []string
	for _, r := range raws {
		if r == nil || r.Target.Name == "" {
			continue
		}
		if err := ValidateTargetName(r.Target.Name); err != nil {
			return nil, fmt.Errorf("invalid target name in shard %q: %w", r.Target.Name, err)
		}
		name := r.Target.Name
		if _, exists := byTarget[name]; !exists {
			targetOrder = append(targetOrder, name)
		}
		byTarget[name] = append(byTarget[name], r)
	}
	sort.Strings(targetOrder)

	var out []*BuiltProfile
	for _, tName := range targetOrder {
		shards := byTarget[tName]
		first := shards[0]
		var resolvedArch syscalls.Arch
		for _, s := range shards {
			sArch, err := normalizeTargetArch(s.Host.Arch)
			if err != nil {
				return nil, fmt.Errorf("target %s: %w", tName, err)
			}
			if sArch != "" {
				if resolvedArch == "" {
					resolvedArch = sArch
				} else if resolvedArch != sArch {
					return nil, fmt.Errorf("cannot merge shards for target %s with mismatched architectures %q and %q", tName, resolvedArch, sArch)
				}
			}
		}
		arch := resolvedArch
		if arch == "" {
			arch = syscalls.ArchAMD64
		}

		containerIdx := make(map[string]int)
		var mergedContainers []RawContainerInfo
		summaryOnlyContainers := 0
		runtimeSet := make(map[string]bool)
		var compatCount uint32
		mergedSyscalls := make(map[string]*RawSyscallEntry)

		for _, s := range shards {
			compatCount += s.Target.CompatSyscallCount
			for _, rt := range s.Target.DetectedRuntimes {
				if rt != "" {
					runtimeSet[rt] = true
				}
			}
			if len(s.Target.Containers) == 0 && s.Target.ContainerCount > 0 {
				summaryOnlyContainers += s.Target.ContainerCount
			}
			for _, c := range s.Target.Containers {
				if c.ID != "" {
					if idx, ok := containerIdx[c.ID]; ok {
						if c.Preexisting {
							mergedContainers[idx].Preexisting = true
						}
						continue
					}
					containerIdx[c.ID] = len(mergedContainers)
				}
				mergedContainers = append(mergedContainers, c)
			}
			for scName, meta := range s.Syscalls {
				entry, ok := mergedSyscalls[scName]
				if !ok {
					entry = &RawSyscallEntry{}
					mergedSyscalls[scName] = entry
				}
				for _, src := range meta.Sources {
					hasSrc := false
					for _, ex := range entry.Sources {
						if ex == src {
							hasSrc = true
							break
						}
					}
					if !hasSrc {
						entry.Sources = append(entry.Sources, src)
					}
				}
				entry.TotalCalls += meta.TotalCalls
				entry.ContainersSeen += meta.ContainersSeen
			}
		}

		totalContainers := len(mergedContainers) + summaryOnlyContainers
		if mergedContainers == nil {
			mergedContainers = []RawContainerInfo{}
		}

		var runtimes []string
		for rt := range runtimeSet {
			runtimes = append(runtimes, rt)
		}
		sort.Strings(runtimes)
		if runtimes == nil {
			runtimes = []string{}
		}

		var allNames []string
		finalSyscalls := make(map[string]RawSyscallEntry, len(mergedSyscalls))
		for scName, entry := range mergedSyscalls {
			if totalContainers > 0 && entry.ContainersSeen > totalContainers {
				entry.ContainersSeen = totalContainers
			}
			allNames = append(allNames, scName)
			finalSyscalls[scName] = *entry
		}
		sort.Strings(allNames)

		eni := errnoRetENOSYS
		oci := OCISeccompProfile{
			DefaultAction:   "SCMP_ACT_ERRNO",
			DefaultErrnoRet: &eni,
			Architectures:   syscalls.SeccompArchitectures(arch, false),
		}
		// Apply the same clone/clone3 constraint as profile.Build unless explicitly
		// allowed unconditionally via extra-allow provenance.
		var plainNames, cloneNames []string
		for _, name := range allNames {
			entry := mergedSyscalls[name]
			if (name == "clone" || name == "clone3") && (entry == nil || !hasSource(entry.Sources, "extra-allow")) {
				cloneNames = append(cloneNames, name)
				continue
			}
			plainNames = append(plainNames, name)
		}
		if len(plainNames) > 0 {
			oci.Syscalls = append(oci.Syscalls, OCISyscallRule{Names: plainNames, Action: "SCMP_ACT_ALLOW"})
		}
		var cloneAllow, clone3Deny []string
		for _, name := range cloneNames {
			if name == "clone" {
				cloneAllow = append(cloneAllow, name)
			} else {
				clone3Deny = append(clone3Deny, name)
			}
		}
		if len(cloneAllow) > 0 {
			oci.Syscalls = append(oci.Syscalls, OCISyscallRule{
				Names:  cloneAllow,
				Action: "SCMP_ACT_ALLOW",
				Args: []OCISyscallArg{{
					Index:    0,
					Value:    cloneNewNamespaceMask,
					ValueTwo: 0,
					Op:       "SCMP_CMP_MASKED_EQ",
				}},
			})
		}
		if len(clone3Deny) > 0 {
			errno := errnoRetENOSYS
			oci.Syscalls = append(oci.Syscalls, OCISyscallRule{Names: clone3Deny, Action: "SCMP_ACT_ERRNO", ErrnoRet: &errno})
		}

		raw := RawProfileV1{
			SchemaVersion:    "v1",
			GeneratedAt:      generatedAt.UTC().Format(time.RFC3339),
			GeneratorVersion: generatorVersion,
			Host: RawHostInfo{
				Arch:        string(arch),
				SeccompArch: syscalls.SeccompArchitectures(arch, false)[0],
				Kernel:      first.Host.Kernel,
			},
			Target: RawTargetInfo{
				Name:               tName,
				GroupBy:            first.Target.GroupBy,
				ContainerCount:     totalContainers,
				DetectedRuntimes:   runtimes,
				CompatSyscallCount: compatCount,
				Containers:         mergedContainers,
			},
			Syscalls: finalSyscalls,
		}
		out = append(out, &BuiltProfile{
			TargetName: tName,
			OCI:        oci,
			Raw:        raw,
		})
	}
	return out, nil
}

// MergeCommittedIntoOCI folds the committed baseline into the newly generated
// profile. Capabilities are never auto-removed:
//   - unconditional allows from the committed profile are merged into the
//     generated unconditional allow rule;
//   - arg-constrained rules from BOTH profiles are preserved verbatim, so a
//     conditional allow can never silently become unconditional;
//   - non-allow rules (explicit denies) from the committed profile survive.
func hasSource(sources []string, want string) bool {
	for _, s := range sources {
		if s == want {
			return true
		}
	}
	return false
}

func normalizeTargetArch(raw string) (syscalls.Arch, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case "amd64", "x86_64":
		return syscalls.ArchAMD64, nil
	case "arm64", "aarch64":
		return syscalls.ArchARM64, nil
	default:
		return "", fmt.Errorf("unsupported host architecture %q", raw)
	}
}

func canonicalOCIArgs(args []OCISyscallArg) ([]OCISyscallArg, string) {
	if len(args) == 0 {
		return nil, "[]"
	}
	canon := append([]OCISyscallArg(nil), args...)
	sort.Slice(canon, func(i, j int) bool {
		if canon[i].Index != canon[j].Index {
			return canon[i].Index < canon[j].Index
		}
		if canon[i].Op != canon[j].Op {
			return canon[i].Op < canon[j].Op
		}
		if canon[i].Value != canon[j].Value {
			return canon[i].Value < canon[j].Value
		}
		ai, _ := json.Marshal(canon[i])
		bj, _ := json.Marshal(canon[j])
		return string(ai) < string(bj)
	})
	raw, _ := json.Marshal(canon)
	return canon, string(raw)
}

func MergeCommittedIntoOCI(curr *OCISeccompProfile, committed *OCISeccompProfile) {
	if curr == nil || committed == nil {
		return
	}
	allowSet := make(map[string]bool)
	allRules := make([]OCISyscallRule, 0, len(curr.Syscalls)+len(committed.Syscalls))
	allRules = append(allRules, curr.Syscalls...)
	allRules = append(allRules, committed.Syscalls...)

	for _, r := range allRules {
		if len(r.Args) == 0 && r.ErrnoRet == nil && r.Action == "SCMP_ACT_ALLOW" {
			for _, n := range r.Names {
				if n != "" {
					allowSet[n] = true
				}
			}
		}
	}

	type extraRuleBucket struct {
		action   string
		errnoRet *uint32
		args     []OCISyscallArg
		nameSet  map[string]bool
	}
	var extraOrder []string
	extraByKey := make(map[string]*extraRuleBucket)

	for _, r := range allRules {
		if r.Action == "" || (len(r.Args) == 0 && r.ErrnoRet == nil && r.Action == "SCMP_ACT_ALLOW") {
			continue
		}
		var kept []string
		for _, n := range r.Names {
			if n != "" && !allowSet[n] {
				kept = append(kept, n)
			}
		}
		if len(kept) == 0 {
			continue
		}
		canonArgs, argsKey := canonicalOCIArgs(r.Args)
		errnoKey := ""
		var errnoCopy *uint32
		if r.ErrnoRet != nil {
			v := *r.ErrnoRet
			errnoCopy = &v
			errnoKey = strconv.FormatUint(uint64(v), 10)
		}
		key := r.Action + "|" + errnoKey + "|" + argsKey
		bucket, ok := extraByKey[key]
		if !ok {
			bucket = &extraRuleBucket{
				action:   r.Action,
				errnoRet: errnoCopy,
				args:     canonArgs,
				nameSet:  make(map[string]bool),
			}
			extraByKey[key] = bucket
			extraOrder = append(extraOrder, key)
		}
		for _, n := range kept {
			bucket.nameSet[n] = true
		}
	}

	var names []string
	for n := range allowSet {
		names = append(names, n)
	}
	sort.Strings(names)

	merged := make([]OCISyscallRule, 0, 1+len(extraOrder))
	if len(names) > 0 {
		merged = append(merged, OCISyscallRule{Names: names, Action: "SCMP_ACT_ALLOW"})
	}
	for _, key := range extraOrder {
		bucket := extraByKey[key]
		extraNames := make([]string, 0, len(bucket.nameSet))
		for n := range bucket.nameSet {
			extraNames = append(extraNames, n)
		}
		sort.Strings(extraNames)
		if len(extraNames) == 0 {
			continue
		}
		var errnoCopy *uint32
		if bucket.errnoRet != nil {
			v := *bucket.errnoRet
			errnoCopy = &v
		}
		var argsCopy []OCISyscallArg
		if len(bucket.args) > 0 {
			argsCopy = append([]OCISyscallArg(nil), bucket.args...)
		}
		merged = append(merged, OCISyscallRule{
			Names:    extraNames,
			Action:   bucket.action,
			Args:     argsCopy,
			ErrnoRet: errnoCopy,
		})
	}
	curr.Syscalls = merged
}

// ErrnoForUnknownSyscalls returns the ENOSYS errno value used as
// defaultErrnoRet so libcs can fall back to older syscall variants.
func ErrnoForUnknownSyscalls() uint32 {
	return errnoRetENOSYS
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

package profile

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/baseline"
	"github.com/alexno10/seccomp-profiler/internal/ebpf"
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

type OCISeccompArchMap struct {
	Architecture     string   `json:"architecture"`
	SubArchitectures []string `json:"subArchitectures,omitempty"`
}

type OCISeccompProfile struct {
	DefaultAction    string              `json:"defaultAction"`
	DefaultErrnoRet  *uint32             `json:"defaultErrnoRet,omitempty"`
	Architectures    []string            `json:"architectures,omitempty"`
	ArchMap          []OCISeccompArchMap `json:"archMap,omitempty"`
	Flags            []string            `json:"flags,omitempty"`
	ListenerPath     string              `json:"listenerPath,omitempty"`
	ListenerMetadata string              `json:"listenerMetadata,omitempty"`
	Comment          string              `json:"comment,omitempty"`
	Syscalls         []OCISyscallRule    `json:"syscalls"`
}

// EffectiveArchitectures returns the sorted deduplicated union of Architectures
// and ArchMap entries (both Architecture and SubArchitectures).
func (p *OCISeccompProfile) EffectiveArchitectures() []string {
	if p == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	add := func(a string) {
		a = strings.TrimSpace(a)
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, a := range p.Architectures {
		add(a)
	}
	for _, m := range p.ArchMap {
		add(m.Architecture)
		for _, sub := range m.SubArchitectures {
			add(sub)
		}
	}
	sort.Strings(out)
	return out
}

type OCISyscallFilter struct {
	Caps      []string `json:"caps,omitempty"`
	Arches    []string `json:"arches,omitempty"`
	MinKernel string   `json:"minKernel,omitempty"`
}

type OCISyscallRule struct {
	Names    []string          `json:"names"`
	Action   string            `json:"action"`
	ErrnoRet *uint32           `json:"errnoRet,omitempty"`
	Args     []OCISyscallArg   `json:"args,omitempty"`
	Comment  string            `json:"comment,omitempty"`
	Includes *OCISyscallFilter `json:"includes,omitempty"`
	Excludes *OCISyscallFilter `json:"excludes,omitempty"`
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
	CompatSyscallCount uint64             `json:"compatSyscallCount"`
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
	KernelErrors     ebpf.ErrorStats            `json:"kernelErrors,omitempty"`
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
	KernelErrors     ebpf.ErrorStats
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
		ver = "1.2.0"
	}

	// 32-bit compat syscalls are reported but deliberately not profiled:
	// the profile stays native-only and the diff gate fails on compat hits.
	seccompArchs := syscalls.SeccompArchitectures(arch, false)
	if len(seccompArchs) == 0 {
		return nil, fmt.Errorf("unsupported architecture %q", arch)
	}
	primarySeccompArch := seccompArchs[0]

	var detectedRuntimes []string
	rtMode := strings.ToLower(strings.TrimSpace(opts.RuntimeMode))
	switch rtMode {
	case "", "auto":
		images := make([]string, 0, len(target.Containers))
		for _, c := range target.Containers {
			if c.Image != "" {
				images = append(images, c.Image)
			}
		}
		detectedRuntimes = baseline.DetectRuntimesFromImages(target.ExecutedBins, images)
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
			return nil, fmt.Errorf("observed unknown syscall number %d on arch %q (%d calls): update internal/syscalls tables", nr, arch, count)
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
			tok = strings.TrimSpace(tok)
			if tok == "" || !nameKnownToArch(tok) {
				continue
			}
			addSource(tok, baseline.SourceExtraAllow)
			extraAllowed[tok] = true
		}
	}

	// Whenever clone3 is blocked with ENOSYS so libcs fall back to clone, ensure
	// the constrained clone allow rule exists even if clone was never observed.
	if _, hasClone3 := entries["clone3"]; hasClone3 && !extraAllowed["clone3"] {
		if _, hasClone := entries["clone"]; !hasClone && !extraAllowed["clone"] {
			addBaselineSource("clone", "clone3-fallback")
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
		KernelErrors: opts.KernelErrors,
		Syscalls:     rawSyscalls,
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
	lockData, err := ReadFileNoSymlink(lockFile)
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
	return writeFileAtomic(lockFile, lockBytes)
}

func lockKey(filePath string) string {
	clean := filepath.Clean(filePath)
	abs, err := filepath.Abs(clean)
	if err == nil {
		if cwd, cErr := os.Getwd(); cErr == nil {
			if rel, rErr := filepath.Rel(cwd, abs); rErr == nil &&
				rel != "" && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return filepath.ToSlash(rel)
			}
		}
		return filepath.ToSlash(abs)
	}
	return filepath.ToSlash(clean)
}

func lookupLockHash(files map[string]string, filePath, targetName string) (string, bool) {
	if h, ok := files[lockKey(filePath)]; ok {
		return h, true
	}
	if h, ok := files[targetName]; ok {
		return h, true
	}
	return "", false
}

// LoadLockHashes loads a snapshot of existing path/target->sha256 entries from
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

		res := WriteResult{
			TargetName:  b.TargetName,
			ProfilePath: profilePath,
			RawPath:     rawPath,
		}

		if existingBytes, err := ReadFileNoSymlink(profilePath); err == nil {
			existingHash := sha256Hex(existingBytes)
			lockedHash, hasLock := lookupLockHash(lock.Files, profilePath, b.TargetName)
			if !hasLock || lockedHash != existingHash {
				res.ProtectedManualEdit = true
				res.SuggestedPath = filepath.Join(outDir, b.TargetName+".suggested.json")
				if err := writeFileAtomic(res.SuggestedPath, ociBytes); err != nil {
					return nil, err
				}
				results = append(results, res)
				continue
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}

		if err := writeFileAtomic(profilePath, ociBytes); err != nil {
			return nil, err
		}
		lock.Files[lockKey(profilePath)] = sha256Hex(ociBytes)
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

		if existing, err := ReadFileNoSymlink(path); err == nil {
			locked, hasLock := lookupLockHash(baselineHashes, path, b.TargetName)
			if !hasLock || locked != sha256Hex(existing) {
				suggested := filepath.Join(filepath.Dir(path), b.TargetName+".suggested.json")
				if err := writeFileAtomic(suggested, ociBytes); err != nil {
					return nil, err
				}
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
		lock.Files[lockKey(path)] = sha256Hex(ociBytes)
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
	if name == "." || strings.Contains(name, "..") {
		return fmt.Errorf("invalid target name %q: must not be a relative path component", name)
	}
	if strings.HasSuffix(strings.ToLower(name), ".suggested") {
		return fmt.Errorf("invalid target name %q: must not end with .suggested", name)
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

func sudoUserIDs() (int, int) {
	uidStr := os.Getenv("SUDO_UID")
	gidStr := os.Getenv("SUDO_GID")
	if uidStr == "" && gidStr == "" {
		return -1, -1
	}
	uid := -1
	gid := -1
	if v, err := strconv.Atoi(uidStr); err == nil && v >= 0 {
		uid = v
	}
	if v, err := strconv.Atoi(gidStr); err == nil && v >= 0 {
		gid = v
	}
	return uid, gid
}

// openNoSymlinkDir verifies every existing directory component via os.Lstat
// (rejecting any symlink component), opens the deepest existing directory via
// os.OpenRoot, and traverses/creates any remaining components inside os.Root
// without following symlinks.
func openNoSymlinkDir(dir string, create bool, perm os.FileMode) (*os.Root, error) {
	if strings.TrimSpace(dir) == "" {
		dir = "."
	}
	absDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return nil, err
	}
	var rootBase, rel string
	if vol := filepath.VolumeName(absDir); vol != "" {
		rootBase = vol + string(filepath.Separator)
		rel = strings.TrimPrefix(absDir, rootBase)
	} else {
		rootBase = string(filepath.Separator)
		rel = strings.TrimPrefix(absDir, rootBase)
	}

	var parts []string
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			return nil, fmt.Errorf("refusing path traversal segment %q in %q", seg, dir)
		}
		parts = append(parts, seg)
	}

	existingAnc := rootBase
	nextIdx := 0
	for i, seg := range parts {
		candidate := filepath.Join(existingAnc, seg)
		fi, lErr := os.Lstat(candidate)
		if lErr != nil {
			if os.IsNotExist(lErr) {
				if !create {
					return nil, lErr
				}
				break
			}
			return nil, lErr
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to traverse symlink directory %q in %q", candidate, dir)
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("path component %q in %q is not a directory", candidate, dir)
		}
		existingAnc = candidate
		nextIdx = i + 1
	}

	cur, err := os.OpenRoot(existingAnc)
	if err != nil {
		return nil, err
	}
	uid, gid := sudoUserIDs()
	for _, seg := range parts[nextIdx:] {
		fi, lErr := cur.Lstat(seg)
		if lErr != nil {
			if os.IsNotExist(lErr) && create {
				if mkErr := cur.Mkdir(seg, perm); mkErr != nil {
					if !os.IsExist(mkErr) {
						_ = cur.Close()
						return nil, mkErr
					}
					fi2, lErr2 := cur.Lstat(seg)
					if lErr2 != nil {
						_ = cur.Close()
						return nil, lErr2
					}
					if fi2.Mode()&os.ModeSymlink != 0 || !fi2.IsDir() {
						_ = cur.Close()
						return nil, fmt.Errorf("refusing non-directory or symlink segment %q in %q", seg, dir)
					}
				} else if uid >= 0 || gid >= 0 {
					_ = cur.Lchown(seg, uid, gid)
				}
			} else {
				_ = cur.Close()
				return nil, lErr
			}
		} else {
			if fi.Mode()&os.ModeSymlink != 0 {
				_ = cur.Close()
				return nil, fmt.Errorf("refusing to traverse symlink directory %q in %q", seg, dir)
			}
			if !fi.IsDir() {
				_ = cur.Close()
				return nil, fmt.Errorf("path component %q in %q is not a directory", seg, dir)
			}
		}
		next, oErr := cur.OpenRoot(seg)
		_ = cur.Close()
		if oErr != nil {
			return nil, oErr
		}
		cur = next
	}
	return cur, nil
}

// EnsureNoSymlinkDir ensures dir exists without traversing or creating any
// symlink components along its path.
func EnsureNoSymlinkDir(dir string, perm os.FileMode) error {
	if strings.TrimSpace(dir) == "" || dir == "." {
		return nil
	}
	r, err := openNoSymlinkDir(dir, true, perm)
	if err != nil {
		return err
	}
	return r.Close()
}

// RemoveRegularFileNoSymlink removes a regular file without following symlinks
// in any parent component or the destination itself.
func RemoveRegularFileNoSymlink(path string) error {
	clean := filepath.Clean(path)
	dirRoot, err := openNoSymlinkDir(filepath.Dir(clean), false, 0)
	if err != nil {
		return err
	}
	defer dirRoot.Close()

	base := filepath.Base(clean)
	if base == "" || base == "." || base == ".." {
		return fmt.Errorf("invalid target file name %q", path)
	}
	fi, err := dirRoot.Lstat(base)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to remove symlink %s", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing to remove non-regular file %s", path)
	}
	return dirRoot.Remove(base)
}

func mkdirAllChown(dir string, perm os.FileMode) error {
	return EnsureNoSymlinkDir(dir, perm)
}

// WriteFileAtomicNoSymlink atomically writes data to path while verifying no
// parent directory or destination is a symlink and assigning SUDO_UID:SUDO_GID
// ownership on the open file descriptor before Rename (zero post-rename Chown TOCTOU).
func WriteFileAtomicNoSymlink(path string, data []byte, chownToSudo bool) error {
	clean := filepath.Clean(path)
	dirRoot, err := openNoSymlinkDir(filepath.Dir(clean), true, 0o755)
	if err != nil {
		return err
	}
	defer dirRoot.Close()

	base := filepath.Base(clean)
	if base == "" || base == "." || base == ".." {
		return fmt.Errorf("invalid target file name %q", path)
	}
	if info, err := dirRoot.Lstat(base); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlink %s", path)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmpName := ".seccomp-profiler-" + hex.EncodeToString(rnd[:])
	tmp, err := dirRoot.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = dirRoot.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if chownToSudo {
		if uid, gid := sudoUserIDs(); uid >= 0 || gid >= 0 {
			_ = tmp.Chown(uid, gid)
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		if err := os.Rename(filepath.Join(filepath.Dir(clean), tmpName), clean); err != nil {
			return err
		}
	} else {
		if err := dirRoot.Rename(tmpName, base); err != nil {
			return err
		}
	}
	cleanupTmp = false
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	return WriteFileAtomicNoSymlink(path, data, true)
}

// ReadFileNoSymlink reads path without following symlinks in any directory
// component or in the final path element.
func ReadFileNoSymlink(path string) ([]byte, error) {
	clean := filepath.Clean(path)
	dirRoot, err := openNoSymlinkDir(filepath.Dir(clean), false, 0)
	if err != nil {
		return nil, err
	}
	defer dirRoot.Close()

	base := filepath.Base(clean)
	fi, err := dirRoot.Lstat(base)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to read symlink %s", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to read non-regular file %s", path)
	}
	return dirRoot.ReadFile(base)
}

func LoadOCIProfile(path string) (*OCISeccompProfile, error) {
	data, err := ReadFileNoSymlink(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p OCISeccompProfile
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("seccomp profile %q: unexpected trailing JSON data", path)
	}
	if strings.TrimSpace(p.ListenerPath) != "" {
		return nil, fmt.Errorf("seccomp profile %q uses unsupported listenerPath %q", path, p.ListenerPath)
	}
	for i, r := range p.Syscalls {
		if r.Includes != nil || r.Excludes != nil {
			return nil, fmt.Errorf("seccomp profile %q rule %d uses Docker conditional includes/excludes filters which cannot be safely flattened to static OCI rules", path, i)
		}
	}
	return &p, nil
}

func LoadRawProfileV1(path string) (*RawProfileV1, error) {
	data, err := ReadFileNoSymlink(path)
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
		generatorVersion = "1.2.0"
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
		var compatCount uint64
		var mergedErrors ebpf.ErrorStats
		mergedSyscalls := make(map[string]*RawSyscallEntry)

		for _, s := range shards {
			compatCount += s.Target.CompatSyscallCount
			mergedErrors = mergedErrors.Add(s.KernelErrors)
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

		// Mirror profile.Build clone3->clone fallback when clone3 is ENOSYS'd.
		if c3Entry, hasClone3 := mergedSyscalls["clone3"]; hasClone3 && !hasSource(c3Entry.Sources, baseline.SourceExtraAllow) {
			if _, hasClone := mergedSyscalls["clone"]; !hasClone {
				if _, knownClone := syscalls.NumberByName(arch, "clone"); knownClone {
					mergedSyscalls["clone"] = &RawSyscallEntry{
						Sources: []string{"clone3-fallback"},
					}
				}
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
			KernelErrors: mergedErrors,
			Syscalls:     finalSyscalls,
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

func isHardDenyAction(action string) bool {
	switch strings.TrimSpace(action) {
	case "SCMP_ACT_KILL", "SCMP_ACT_KILL_THREAD", "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_TRAP":
		return true
	default:
		return false
	}
}

func uncondRulePriority(action string, errnoRet *uint32, fromCurr bool) int {
	base := 0
	switch strings.TrimSpace(action) {
	case "SCMP_ACT_KILL_PROCESS":
		base = 700
	case "SCMP_ACT_KILL_THREAD":
		base = 600
	case "SCMP_ACT_KILL":
		base = 500
	case "SCMP_ACT_TRAP":
		base = 400
	case "SCMP_ACT_ERRNO":
		base = 300
	case "SCMP_ACT_TRACE":
		base = 200
	case "SCMP_ACT_NOTIFY":
		base = 100
	case "SCMP_ACT_LOG":
		base = 50
	}
	if errnoRet != nil {
		base += 10
	}
	if fromCurr {
		base++
	}
	return base
}

func MergeCommittedIntoOCI(curr *OCISeccompProfile, committed *OCISeccompProfile) {
	if curr == nil || committed == nil {
		return
	}
	committedUncondAllow := make(map[string]bool)
	committedProtected := make(map[string]bool)
	for _, r := range committed.Syscalls {
		if r.Action == "" {
			continue
		}
		if len(r.Args) == 0 && r.ErrnoRet == nil && r.Action == "SCMP_ACT_ALLOW" {
			for _, n := range r.Names {
				if n != "" {
					committedUncondAllow[n] = true
				}
			}
			continue
		}
		if len(r.Args) > 0 || isHardDenyAction(r.Action) {
			for _, n := range r.Names {
				if n != "" {
					committedProtected[n] = true
				}
			}
		}
	}

	allowSet := make(map[string]bool)
	for n := range committedUncondAllow {
		allowSet[n] = true
	}
	for _, r := range curr.Syscalls {
		if len(r.Args) == 0 && r.ErrnoRet == nil && r.Action == "SCMP_ACT_ALLOW" {
			for _, n := range r.Names {
				if n != "" && !committedProtected[n] {
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
	var condOrder []string
	condByKey := make(map[string]*extraRuleBucket)

	type uncondChoice struct {
		action   string
		errnoRet *uint32
		prio     int
	}
	uncondBest := make(map[string]uncondChoice)

	processRules := func(rules []OCISyscallRule, fromCurr bool) {
		for _, r := range rules {
			if r.Action == "" || (len(r.Args) == 0 && r.ErrnoRet == nil && r.Action == "SCMP_ACT_ALLOW") {
				continue
			}
			if len(r.Args) > 0 {
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
				bucket, ok := condByKey[key]
				if !ok {
					bucket = &extraRuleBucket{
						action:   r.Action,
						errnoRet: errnoCopy,
						args:     canonArgs,
						nameSet:  make(map[string]bool),
					}
					condByKey[key] = bucket
					condOrder = append(condOrder, key)
				}
				for _, n := range kept {
					bucket.nameSet[n] = true
				}
				continue
			}
			// Unconditional non-ALLOW rule: deduplicate per syscall by priority so
			// conflicting actions/errnos never emit duplicate rules for libseccomp (-EEXIST).
			prio := uncondRulePriority(r.Action, r.ErrnoRet, fromCurr)
			var errnoCopy *uint32
			if r.ErrnoRet != nil {
				v := *r.ErrnoRet
				errnoCopy = &v
			}
			for _, n := range r.Names {
				if n == "" || allowSet[n] {
					continue
				}
				prev, exists := uncondBest[n]
				if !exists || prio > prev.prio {
					uncondBest[n] = uncondChoice{
						action:   r.Action,
						errnoRet: errnoCopy,
						prio:     prio,
					}
				}
			}
		}
	}

	processRules(curr.Syscalls, true)
	processRules(committed.Syscalls, false)

	var uncondOrder []string
	uncondBuckets := make(map[string]*extraRuleBucket)
	var uncondNames []string
	for n := range uncondBest {
		uncondNames = append(uncondNames, n)
	}
	sort.Strings(uncondNames)
	for _, n := range uncondNames {
		c := uncondBest[n]
		errnoKey := ""
		if c.errnoRet != nil {
			errnoKey = strconv.FormatUint(uint64(*c.errnoRet), 10)
		}
		key := c.action + "|" + errnoKey
		b, ok := uncondBuckets[key]
		if !ok {
			var errnoCopy *uint32
			if c.errnoRet != nil {
				v := *c.errnoRet
				errnoCopy = &v
			}
			b = &extraRuleBucket{
				action:   c.action,
				errnoRet: errnoCopy,
				nameSet:  make(map[string]bool),
			}
			uncondBuckets[key] = b
			uncondOrder = append(uncondOrder, key)
		}
		b.nameSet[n] = true
	}

	var names []string
	for n := range allowSet {
		names = append(names, n)
	}
	sort.Strings(names)

	merged := make([]OCISyscallRule, 0, 1+len(condOrder)+len(uncondOrder))
	if len(names) > 0 {
		merged = append(merged, OCISyscallRule{Names: names, Action: "SCMP_ACT_ALLOW"})
	}
	for _, key := range condOrder {
		bucket := condByKey[key]
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
		argsCopy := append([]OCISyscallArg(nil), bucket.args...)
		merged = append(merged, OCISyscallRule{
			Names:    extraNames,
			Action:   bucket.action,
			Args:     argsCopy,
			ErrnoRet: errnoCopy,
		})
	}
	for _, key := range uncondOrder {
		bucket := uncondBuckets[key]
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
		merged = append(merged, OCISyscallRule{
			Names:    extraNames,
			Action:   bucket.action,
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

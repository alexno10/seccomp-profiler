package profile

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

	"github.com/alexno10/seccomp-profiler/internal/baseline"
	"github.com/alexno10/seccomp-profiler/internal/selector"
	"github.com/alexno10/seccomp-profiler/internal/syscalls"
)

type OCISeccompProfile struct {
	DefaultAction string           `json:"defaultAction"`
	Architectures []string         `json:"architectures"`
	Syscalls      []OCISyscallRule `json:"syscalls"`
}

type OCISyscallRule struct {
	Names  []string        `json:"names"`
	Action string          `json:"action"`
	Args   []OCISyscallArg `json:"args,omitempty"`
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
	ID         string            `json:"id"`
	Image      string            `json:"image"`
	Labels     map[string]string `json:"labels,omitempty"`
	DurationMs int64             `json:"durationMs"`
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
		ver = "1.0.0"
	}

	seccompArchs := syscalls.SeccompArchitectures(arch, target.CompatHits > 0)
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
		addSource(name, baseline.SourceRuntime)
	}
	for _, name := range baseLayers[baseline.SourceLifecycle] {
		addSource(name, baseline.SourceLifecycle)
	}
	for _, rt := range detectedRuntimes {
		rtLayers := baseline.LayerSyscalls(baseline.ModeNone, rt)
		src := baseline.LangSource(rt)
		for _, name := range rtLayers[src] {
			addSource(name, src)
		}
	}
	for _, extra := range opts.ExtraAllow {
		for _, tok := range strings.FieldsFunc(extra, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
		}) {
			addSource(tok, baseline.SourceExtraAllow)
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
			ID:         c.ID,
			Image:      c.Image,
			Labels:     c.Labels,
			DurationMs: c.DurationMs,
		})
	}
	if rawContainers == nil {
		rawContainers = []RawContainerInfo{}
	}
	if detectedRuntimes == nil {
		detectedRuntimes = []string{}
	}

	oci := OCISeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: seccompArchs,
		Syscalls: []OCISyscallRule{
			{
				Names:  allNames,
				Action: "SCMP_ACT_ALLOW",
			},
		},
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

func WriteTargetFiles(outDir, rawDir, lockFile string, built []*BuiltProfile) ([]WriteResult, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		return nil, err
	}

	lock := lockFileSchema{Files: make(map[string]string)}
	if lockData, err := os.ReadFile(lockFile); err == nil {
		_ = json.Unmarshal(lockData, &lock)
		if lock.Files == nil {
			lock.Files = make(map[string]string)
		}
	}

	var results []WriteResult
	for _, b := range built {
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
		if err := os.WriteFile(rawPath, rawBytes, 0o644); err != nil {
			return nil, err
		}

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
				if err := os.WriteFile(res.SuggestedPath, ociBytes, 0o644); err != nil {
					return nil, err
				}
				results = append(results, res)
				continue
			}
		}

		if err := os.WriteFile(profilePath, ociBytes, 0o644); err != nil {
			return nil, err
		}
		lock.Files[b.TargetName] = sha256Hex(ociBytes)
		results = append(results, res)
	}

	if lockFile != "" {
		if err := os.MkdirAll(filepath.Dir(lockFile), 0o755); err != nil {
			return nil, err
		}
		lockBytes, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			return nil, err
		}
		lockBytes = append(lockBytes, '\n')
		if err := os.WriteFile(lockFile, lockBytes, 0o644); err != nil {
			return nil, err
		}
	}

	return results, nil
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
		generatorVersion = "1.0.0"
	}

	byTarget := make(map[string][]*RawProfileV1)
	var targetOrder []string
	for _, r := range raws {
		if r == nil || r.Target.Name == "" {
			continue
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
		arch := syscalls.Arch(first.Host.Arch)
		if arch == "" {
			arch = syscalls.ArchAMD64
		}

		seenContainers := make(map[string]bool)
		var mergedContainers []RawContainerInfo
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
			for _, c := range s.Target.Containers {
				if c.ID != "" && seenContainers[c.ID] {
					continue
				}
				if c.ID != "" {
					seenContainers[c.ID] = true
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

		totalContainers := len(mergedContainers)
		if totalContainers == 0 {
			for _, s := range shards {
				totalContainers += s.Target.ContainerCount
			}
		}
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

		seccompArchs := syscalls.SeccompArchitectures(arch, compatCount > 0)
		oci := OCISeccompProfile{
			DefaultAction: "SCMP_ACT_ERRNO",
			Architectures: seccompArchs,
			Syscalls: []OCISyscallRule{
				{
					Names:  allNames,
					Action: "SCMP_ACT_ALLOW",
				},
			},
		}
		raw := RawProfileV1{
			SchemaVersion:    "v1",
			GeneratedAt:      generatedAt.UTC().Format(time.RFC3339),
			GeneratorVersion: generatorVersion,
			Host: RawHostInfo{
				Arch:        string(arch),
				SeccompArch: seccompArchs[0],
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

func MergeCommittedIntoOCI(curr *OCISeccompProfile, committed *OCISeccompProfile) {
	if curr == nil || committed == nil {
		return
	}
	allowSet := make(map[string]bool)
	for _, r := range curr.Syscalls {
		if (r.Action == "SCMP_ACT_ALLOW" || r.Action == "") && len(r.Args) == 0 {
			for _, n := range r.Names {
				allowSet[n] = true
			}
		}
	}
	var extraRules []OCISyscallRule
	for _, r := range committed.Syscalls {
		if len(r.Args) > 0 {
			extraRules = append(extraRules, r)
			continue
		}
		if r.Action == "SCMP_ACT_ALLOW" || r.Action == "" {
			for _, n := range r.Names {
				allowSet[n] = true
			}
		} else {
			extraRules = append(extraRules, r)
		}
	}
	var names []string
	for n := range allowSet {
		names = append(names, n)
	}
	sort.Strings(names)

	curr.Syscalls = []OCISyscallRule{
		{
			Names:  names,
			Action: "SCMP_ACT_ALLOW",
		},
	}
	curr.Syscalls = append(curr.Syscalls, extraRules...)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

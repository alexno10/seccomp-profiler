package selector

import (
	"sort"
	"strings"
)

type ContainerRecord struct {
	ID           string
	Name         string
	Image        string
	Labels       map[string]string
	DurationMs   int64
	ExecutedBins []string
	SyscallHits  map[int]uint32
	CompatHits   uint32
}

type TargetRule struct {
	Name      string            `yaml:"name" json:"name"`
	ImageGlob string            `yaml:"image" json:"image"`
	Labels    map[string]string `yaml:"labels" json:"labels"`
}

type Config struct {
	Rules         []TargetRule
	GroupBy       string
	ExtraExcludes []string
}

type MatchedTarget struct {
	Name                 string
	GroupBy              string
	Containers           []ContainerRecord
	MergedHits           map[int]uint32
	ContainersPerSyscall map[int]int
	CompatHits           uint32
	ExecutedBins         []string
}

type SkippedContainer struct {
	ID     string
	Image  string
	Labels map[string]string
	Reason string
}

var defaultExcludeGlobs = []string{
	"testcontainers/ryuk*",
	"*/testcontainers/ryuk*",
	"testcontainers/sshd*",
	"*/testcontainers/sshd*",
	"testcontainers/vnc-recorder*",
	"*/testcontainers/vnc-recorder*",
	"moby/buildkit*",
	"*/moby/buildkit*",
	"tonistiigi/binfmt*",
	"*/tonistiigi/binfmt*",
	"ghcr.io/actions/*",
}

func NormalizeImageName(image string) string {
	s := strings.TrimSpace(image)
	if idx := strings.IndexByte(s, '@'); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.LastIndexByte(s, '/'); idx != -1 {
		s = s[idx+1:]
	}
	if idx := strings.IndexByte(s, ':'); idx != -1 {
		s = s[:idx]
	}
	if s == "" {
		return "container"
	}
	return s
}

func Evaluate(cfg Config, containers []ContainerRecord) ([]MatchedTarget, []SkippedContainer) {
	byName := make(map[string]*MatchedTarget)
	var skipped []SkippedContainer

	for _, c := range containers {
		if len(cfg.Rules) > 0 {
			rule, ok := matchRules(cfg.Rules, c)
			if !ok {
				if isDefaultExcluded(c) {
					skipped = append(skipped, SkippedContainer{ID: c.ID, Image: c.Image, Labels: c.Labels, Reason: "excluded-default"})
				} else if matchesAnyGlob(cfg.ExtraExcludes, c.Image) {
					skipped = append(skipped, SkippedContainer{ID: c.ID, Image: c.Image, Labels: c.Labels, Reason: "excluded-user"})
				} else {
					skipped = append(skipped, SkippedContainer{ID: c.ID, Image: c.Image, Labels: c.Labels, Reason: "unmatched-selector"})
				}
				continue
			}
			name := rule.Name
			if name == "" {
				name, _ = resolveGroupKey(cfg.GroupBy, c)
			}
			mergeIntoTarget(byName, name, "selector", c)
			continue
		}

		if isDefaultExcluded(c) {
			skipped = append(skipped, SkippedContainer{ID: c.ID, Image: c.Image, Labels: c.Labels, Reason: "excluded-default"})
			continue
		}
		if matchesAnyGlob(cfg.ExtraExcludes, c.Image) {
			skipped = append(skipped, SkippedContainer{ID: c.ID, Image: c.Image, Labels: c.Labels, Reason: "excluded-user"})
			continue
		}

		targetName, groupByUsed := resolveGroupKey(cfg.GroupBy, c)
		mergeIntoTarget(byName, targetName, groupByUsed, c)
	}

	var targets []MatchedTarget
	for _, t := range byName {
		targets = append(targets, *t)
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Name < targets[j].Name
	})
	return targets, skipped
}

func mergeIntoTarget(byName map[string]*MatchedTarget, name, groupBy string, c ContainerRecord) {
	t, ok := byName[name]
	if !ok {
		t = &MatchedTarget{
			Name:                 name,
			GroupBy:              groupBy,
			MergedHits:           make(map[int]uint32),
			ContainersPerSyscall: make(map[int]int),
		}
		byName[name] = t
	}
	t.Containers = append(t.Containers, c)
	t.CompatHits += c.CompatHits
	t.ExecutedBins = append(t.ExecutedBins, c.ExecutedBins...)
	for nr, count := range c.SyscallHits {
		if count == 0 {
			continue
		}
		t.MergedHits[nr] += count
		t.ContainersPerSyscall[nr]++
	}
}

func resolveGroupKey(groupBy string, c ContainerRecord) (string, string) {
	gb := strings.TrimSpace(groupBy)
	if gb == "" {
		gb = "auto"
	}
	switch {
	case gb == "compose-service":
		if svc := strings.TrimSpace(c.Labels["com.docker.compose.service"]); svc != "" {
			return svc, "compose-service"
		}
		return NormalizeImageName(c.Image), "image"
	case gb == "image":
		return NormalizeImageName(c.Image), "image"
	case strings.HasPrefix(gb, "label:"):
		key := strings.TrimPrefix(gb, "label:")
		if val := strings.TrimSpace(c.Labels[key]); val != "" {
			return val, gb
		}
		return NormalizeImageName(c.Image), "image"
	default: // "auto"
		if svc := strings.TrimSpace(c.Labels["com.docker.compose.service"]); svc != "" {
			return svc, "compose-service"
		}
		return NormalizeImageName(c.Image), "image"
	}
}

func isDefaultExcluded(c ContainerRecord) bool {
	if matchesAnyGlob(defaultExcludeGlobs, c.Image) {
		return true
	}
	if c.Labels["org.testcontainers.ryuk"] == "true" {
		return true
	}
	return false
}

func matchRules(rules []TargetRule, c ContainerRecord) (TargetRule, bool) {
	for _, r := range rules {
		if r.ImageGlob != "" && !matchGlob(r.ImageGlob, c.Image) {
			continue
		}
		labelsMatch := true
		for k, v := range r.Labels {
			if c.Labels[k] != v {
				labelsMatch = false
				break
			}
		}
		if !labelsMatch {
			continue
		}
		return r, true
	}
	return TargetRule{}, false
}

func matchesAnyGlob(globs []string, value string) bool {
	for _, g := range globs {
		g = strings.TrimSpace(g)
		if g != "" && matchGlob(g, value) {
			return true
		}
	}
	return false
}

func matchGlob(pattern, str string) bool {
	if pattern == "*" {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == str
	}
	if !strings.HasPrefix(str, parts[0]) {
		return false
	}
	str = str[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(str, parts[i])
		if idx == -1 {
			return false
		}
		str = str[idx+len(parts[i]):]
	}
	last := parts[len(parts)-1]
	return strings.HasSuffix(str, last)
}

func ParseTargetsInput(raw string) []TargetRule {
	var rules []TargetRule
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "-"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var name, expr string
		if parts := strings.SplitN(line, "->", 2); len(parts) == 2 {
			expr = strings.TrimSpace(parts[0])
			name = strings.TrimSpace(parts[1])
		} else {
			expr = line
		}
		rule := TargetRule{Name: name}
		for _, tok := range strings.Fields(expr) {
			if strings.HasPrefix(tok, "labels:") {
				rule.Labels = make(map[string]string)
				for _, kv := range strings.Split(strings.TrimPrefix(tok, "labels:"), ",") {
					if kvParts := strings.SplitN(kv, "=", 2); len(kvParts) == 2 {
						rule.Labels[strings.TrimSpace(kvParts[0])] = strings.TrimSpace(kvParts[1])
					}
				}
			} else if strings.HasPrefix(tok, "image:") {
				rule.ImageGlob = strings.TrimPrefix(tok, "image:")
			} else {
				rule.ImageGlob = tok
			}
		}
		if rule.ImageGlob != "" || len(rule.Labels) > 0 {
			rules = append(rules, rule)
		}
	}
	return rules
}

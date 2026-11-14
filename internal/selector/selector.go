package selector

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

type ContainerRecord struct {
	ID           string
	Name         string
	Image        string
	Labels       map[string]string
	DurationMs   int64
	Preexisting  bool
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
	Rules          []TargetRule
	GroupBy        string
	ExtraExcludes  []string
	ComposeProject string
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

// NormalizeImageName strips registry, tag, and digest from an image reference.
// For image-ID-only references ("sha256:...") it returns "sha256"; callers
// that need a unique fallback should prefer the container ID (see
// resolveGroupKey).
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

// isValidTargetName mirrors profile.ValidateTargetName. Target names are used
// as output file names by a root daemon, so labels and image names must never
// be able to traverse paths.
func isValidTargetName(name string) bool {
	if name == "" || len(name) > 100 {
		return false
	}
	if name == "." || strings.Contains(name, "..") {
		return false
	}
	if strings.HasSuffix(strings.ToLower(name), ".suggested") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

func Evaluate(cfg Config, containers []ContainerRecord) ([]MatchedTarget, []SkippedContainer) {
	byName := make(map[string]*MatchedTarget)
	var skipped []SkippedContainer

	for _, c := range containers {
		if cfg.ComposeProject != "" && c.Labels["com.docker.compose.project"] != cfg.ComposeProject {
			skipped = append(skipped, SkippedContainer{ID: c.ID, Image: c.Image, Labels: c.Labels, Reason: "compose-project-mismatch"})
			continue
		}

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
			if !isValidTargetName(name) {
				skipped = append(skipped, SkippedContainer{ID: c.ID, Image: c.Image, Labels: c.Labels, Reason: "invalid-target-name"})
				continue
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
		if !isValidTargetName(targetName) {
			skipped = append(skipped, SkippedContainer{ID: c.ID, Image: c.Image, Labels: c.Labels, Reason: "invalid-target-name"})
			continue
		}
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
	fallback := func() string {
		if len(c.ID) >= 12 {
			return c.ID[:12]
		}
		return c.ID
	}
	imageName := func() string {
		name := NormalizeImageName(c.Image)
		// Image-ID-only references all collapse to "sha256"; fall back to the
		// container ID so unrelated containers never merge into one profile.
		if name == "sha256" || name == "container" {
			return fallback()
		}
		return name
	}
	switch {
	case gb == "compose-service":
		if svc := strings.TrimSpace(c.Labels["com.docker.compose.service"]); svc != "" {
			return svc, "compose-service"
		}
		return imageName(), "image"
	case gb == "image":
		return imageName(), "image"
	case strings.HasPrefix(gb, "label:"):
		key := strings.TrimPrefix(gb, "label:")
		if val := strings.TrimSpace(c.Labels[key]); val != "" {
			return val, gb
		}
		return imageName(), "image"
	default: // "auto"
		if svc := strings.TrimSpace(c.Labels["com.docker.compose.service"]); svc != "" {
			return svc, "compose-service"
		}
		return imageName(), "image"
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
			val, exists := c.Labels[k]
			if !exists || val != v {
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
	if pattern == "" {
		return false
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

// ParseTargetsInput parses target selector rules, discarding errors for
// callers that do not validate configuration. Prefer ParseTargetsInputWithErr.
func ParseTargetsInput(raw string) []TargetRule {
	rules, err := ParseTargetsInputWithErr(raw)
	if err != nil {
		return nil
	}
	return rules
}

// ParseTargetsInputWithErr parses multiline shorthand rules or YAML list items
// into TargetRules. Any non-empty input that fails validation returns an error
// instead of silently degrading to auto-discovery.
func ParseTargetsInputWithErr(raw string) ([]TargetRule, error) {
	raw = strings.TrimPrefix(raw, "\xef\xbb\xbf")
	raw = strings.ReplaceAll(raw, "\r\n", "\n")

	var rules []TargetRule
	var cur *TargetRule
	var curIndent int
	var inLabels bool
	var labelsIndent int
	var expectingLabels bool
	var hasName, hasImage, hasLabels bool
	var hasContent bool

	flushCur := func() error {
		if cur == nil {
			return nil
		}
		if expectingLabels {
			return fmt.Errorf("targets rule %q: empty labels block", cur.Name)
		}
		if cur.ImageGlob == "" && len(cur.Labels) == 0 {
			return fmt.Errorf("targets rule %q must specify image or labels", cur.Name)
		}
		if cur.Name != "" && !isValidTargetName(cur.Name) {
			return fmt.Errorf("invalid target name %q", cur.Name)
		}
		rules = append(rules, *cur)
		cur = nil
		inLabels = false
		expectingLabels = false
		hasName = false
		hasImage = false
		hasLabels = false
		return nil
	}

	applyYAMLField := func(lineNum int, r *TargetRule, k, v string, indent int) error {
		switch k {
		case "name":
			if hasName {
				return fmt.Errorf("targets line %d: duplicate field %q", lineNum, k)
			}
			val, err := unquoteTargetScalar(v)
			if err != nil {
				return fmt.Errorf("targets line %d: %w", lineNum, err)
			}
			if val == "" || !isValidTargetName(val) {
				return fmt.Errorf("targets line %d: invalid target name %q", lineNum, val)
			}
			r.Name = val
			hasName = true
		case "image":
			if hasImage {
				return fmt.Errorf("targets line %d: duplicate field %q", lineNum, k)
			}
			val, err := unquoteTargetScalar(v)
			if err != nil {
				return fmt.Errorf("targets line %d: %w", lineNum, err)
			}
			if val == "" || strings.ContainsAny(val, " \t") {
				return fmt.Errorf("targets line %d: invalid image selector %q", lineNum, v)
			}
			r.ImageGlob = val
			hasImage = true
		case "labels":
			if hasLabels {
				return fmt.Errorf("targets line %d: duplicate field %q", lineNum, k)
			}
			hasLabels = true
			if v == "" {
				r.Labels = make(map[string]string)
				inLabels = true
				labelsIndent = indent
				expectingLabels = true
			} else {
				parsed, err := parseInlineLabels(lineNum, v)
				if err != nil {
					return err
				}
				r.Labels = parsed
			}
		default:
			return fmt.Errorf("targets line %d: unknown YAML field %q", lineNum, k)
		}
		return nil
	}

	for idx, rawLine := range strings.Split(raw, "\n") {
		lineNum := idx + 1
		cleaned := stripTargetComment(rawLine)
		trimmed := strings.TrimSpace(cleaned)
		if trimmed == "" {
			continue
		}
		hasContent = true
		indent := countIndent(cleaned)

		isDash := trimmed == "-" || strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "-\t")

		if cur != nil && indent > curIndent && !isDash {
			if inLabels && indent > labelsIndent {
				k, v, ok := splitTargetKV(trimmed)
				if !ok {
					return nil, fmt.Errorf("targets line %d: invalid label entry %q", lineNum, trimmed)
				}
				key, err := unquoteTargetScalar(k)
				if err != nil {
					return nil, fmt.Errorf("targets line %d: %w", lineNum, err)
				}
				if key == "" {
					return nil, fmt.Errorf("targets line %d: empty label key", lineNum)
				}
				val, err := unquoteTargetScalar(v)
				if err != nil {
					return nil, fmt.Errorf("targets line %d: %w", lineNum, err)
				}
				if cur.Labels == nil {
					cur.Labels = make(map[string]string)
				}
				if _, exists := cur.Labels[key]; exists {
					return nil, fmt.Errorf("targets line %d: duplicate label key %q", lineNum, key)
				}
				cur.Labels[key] = val
				expectingLabels = false
				continue
			}
			inLabels = false
			if expectingLabels {
				return nil, fmt.Errorf("targets line %d: empty labels block", lineNum)
			}
			k, v, ok := splitTargetKV(trimmed)
			if !ok {
				return nil, fmt.Errorf("targets line %d: expected key: value inside YAML item, got %q", lineNum, trimmed)
			}
			if err := applyYAMLField(lineNum, cur, k, v, indent); err != nil {
				return nil, err
			}
			continue
		}

		if err := flushCur(); err != nil {
			return nil, err
		}

		if isDash {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			if rest == "" {
				cur = &TargetRule{}
				curIndent = indent
				continue
			}
			if !strings.Contains(rest, "->") {
				if k, v, ok := splitTargetKV(rest); ok && isYAMLTargetItemStart(k, v) {
					cur = &TargetRule{}
					curIndent = indent
					if err := applyYAMLField(lineNum, cur, k, v, indent+2); err != nil {
						return nil, err
					}
					continue
				}
			}
			r, err := parseTargetShorthand(lineNum, rest)
			if err != nil {
				return nil, err
			}
			rules = append(rules, r)
			continue
		}

		r, err := parseTargetShorthand(lineNum, trimmed)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}

	if err := flushCur(); err != nil {
		return nil, err
	}
	if hasContent && len(rules) == 0 {
		return nil, fmt.Errorf("targets input produced no valid rules")
	}
	return rules, nil
}

func isYAMLTargetItemStart(k, v string) bool {
	switch k {
	case "name":
		return true
	case "labels":
		return v == "" || (!strings.Contains(v, "=") && !strings.Contains(v, "image:"))
	case "image":
		return v != "" && !strings.ContainsAny(v, " \t")
	default:
		return false
	}
}

func parseTargetShorthand(lineNum int, line string) (TargetRule, error) {
	if strings.Count(line, "->") > 1 {
		return TargetRule{}, fmt.Errorf("targets line %d: multiple '->' separators", lineNum)
	}
	var name, expr string
	if idx := strings.Index(line, "->"); idx != -1 {
		expr = strings.TrimSpace(line[:idx])
		name = strings.TrimSpace(line[idx+2:])
		if name == "" || !isValidTargetName(name) {
			return TargetRule{}, fmt.Errorf("targets line %d: invalid target name %q", lineNum, name)
		}
	} else {
		expr = line
	}
	if expr == "" {
		return TargetRule{}, fmt.Errorf("targets line %d: missing selector matcher before '->'", lineNum)
	}

	rule := TargetRule{Name: name}
	tokens := strings.Fields(expr)
	for i := 0; i < len(tokens); {
		tok := tokens[i]
		switch {
		case tok == "image:" || strings.HasPrefix(tok, "image:"):
			if rule.ImageGlob != "" {
				return TargetRule{}, fmt.Errorf("targets line %d: duplicate image selector", lineNum)
			}
			val := strings.TrimPrefix(tok, "image:")
			if val == "" {
				i++
				if i >= len(tokens) {
					return TargetRule{}, fmt.Errorf("targets line %d: missing pattern after 'image:'", lineNum)
				}
				val = tokens[i]
			}
			i++
			unq, err := unquoteTargetScalar(val)
			if err != nil || unq == "" || strings.HasPrefix(unq, "labels:") || strings.HasPrefix(unq, "image:") {
				return TargetRule{}, fmt.Errorf("targets line %d: invalid image pattern %q", lineNum, val)
			}
			rule.ImageGlob = unq

		case tok == "labels:" || strings.HasPrefix(tok, "labels:"):
			if rule.Labels != nil {
				return TargetRule{}, fmt.Errorf("targets line %d: duplicate labels selector", lineNum)
			}
			first := strings.TrimPrefix(tok, "labels:")
			i++
			var parts []string
			if first != "" {
				parts = append(parts, first)
			} else {
				if i >= len(tokens) {
					return TargetRule{}, fmt.Errorf("targets line %d: missing k=v pairs after 'labels:'", lineNum)
				}
				parts = append(parts, tokens[i])
				i++
			}
			for len(parts) > 0 {
				last := parts[len(parts)-1]
				if strings.HasSuffix(last, ",") {
					if i >= len(tokens) {
						return TargetRule{}, fmt.Errorf("targets line %d: trailing comma in labels", lineNum)
					}
					parts = append(parts, tokens[i])
					i++
					continue
				}
				if i < len(tokens) && strings.HasPrefix(tokens[i], ",") {
					parts = append(parts, tokens[i])
					i++
					continue
				}
				break
			}
			parsed, err := parseInlineLabels(lineNum, strings.Join(parts, " "))
			if err != nil {
				return TargetRule{}, err
			}
			rule.Labels = parsed

		default:
			if strings.HasSuffix(tok, ":") {
				return TargetRule{}, fmt.Errorf("targets line %d: unexpected key %q in selector", lineNum, tok)
			}
			if rule.ImageGlob != "" {
				return TargetRule{}, fmt.Errorf("targets line %d: unexpected token %q", lineNum, tok)
			}
			unq, err := unquoteTargetScalar(tok)
			if err != nil || unq == "" {
				return TargetRule{}, fmt.Errorf("targets line %d: invalid token %q", lineNum, tok)
			}
			rule.ImageGlob = unq
			i++
		}
	}

	if rule.ImageGlob == "" && len(rule.Labels) == 0 {
		return TargetRule{}, fmt.Errorf("targets line %d: rule must specify image or labels", lineNum)
	}
	return rule, nil
}

func parseInlineLabels(lineNum int, raw string) (map[string]string, error) {
	out := make(map[string]string)
	for _, seg := range strings.Split(raw, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			return nil, fmt.Errorf("targets line %d: empty label pair in %q", lineNum, raw)
		}
		kv := strings.SplitN(seg, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("targets line %d: label %q must use key=value syntax", lineNum, seg)
		}
		k, err := unquoteTargetScalar(strings.TrimSpace(kv[0]))
		if err != nil {
			return nil, fmt.Errorf("targets line %d: %w", lineNum, err)
		}
		v, err := unquoteTargetScalar(strings.TrimSpace(kv[1]))
		if err != nil {
			return nil, fmt.Errorf("targets line %d: %w", lineNum, err)
		}
		if k == "" {
			return nil, fmt.Errorf("targets line %d: empty label key in %q", lineNum, seg)
		}
		if _, exists := out[k]; exists {
			return nil, fmt.Errorf("targets line %d: duplicate label key %q", lineNum, k)
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("targets line %d: empty labels map", lineNum)
	}
	return out, nil
}

func splitTargetKV(line string) (string, string, bool) {
	idx := strings.IndexByte(line, ':')
	if idx == -1 {
		return "", "", false
	}
	k := strings.TrimSpace(line[:idx])
	if k == "" || strings.ContainsAny(k, " \t\"'") {
		return "", "", false
	}
	return k, strings.TrimSpace(line[idx+1:]), true
}

func unquoteTargetScalar(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return "", nil
	}
	if s[0] != '"' && s[0] != '\'' {
		return s, nil
	}
	if len(s) < 2 || s[len(s)-1] != s[0] {
		return "", fmt.Errorf("unclosed quote in %q", s)
	}
	return s[1 : len(s)-1], nil
}

func stripTargetComment(line string) string {
	var inSingle, inDouble bool
	var prev rune
	for i, r := range line {
		switch {
		case inDouble:
			if r == '\\' && i+1 < len(line) {
				prev = r
				continue
			}
			if r == '"' && prev != '\\' {
				inDouble = false
			}
		case inSingle:
			if r == '\'' {
				inSingle = false
			}
		default:
			if r == '#' && (i == 0 || unicode.IsSpace(prev)) {
				return line[:i]
			}
			if r == '"' && (i == 0 || unicode.IsSpace(prev) || prev == ':' || prev == '-') {
				inDouble = true
			} else if r == '\'' && (i == 0 || unicode.IsSpace(prev) || prev == ':' || prev == '-') {
				inSingle = true
			}
		}
		prev = r
	}
	return line
}

func countIndent(line string) int {
	n := 0
	for _, r := range line {
		if r == ' ' {
			n++
		} else if r == '\t' {
			n += 2
		} else {
			break
		}
	}
	return n
}

package diff

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type ApprovalEntry struct {
	Target  string `json:"target" yaml:"target"`
	Syscall string `json:"syscall" yaml:"syscall"`
	Reason  string `json:"reason" yaml:"reason"`
	Expires string `json:"expires" yaml:"expires"`
}

type approvalsFile struct {
	Version  int             `json:"version" yaml:"version"`
	Accepted []ApprovalEntry `json:"accepted" yaml:"accepted"`
}

var knownApprovalKeys = map[string]bool{
	"target":  true,
	"syscall": true,
	"reason":  true,
	"expires": true,
}

// shortcut: parses the flat accepted.yml list without external yaml
// dependencies. It is deliberately fail-closed: unknown keys and list items
// outside `accepted:` are errors, not silently ignored input. Upgrade to
// gopkg.in/yaml.v3 with KnownFields(true) if nested anchors are ever needed.
func LoadApprovals(path string) ([]ApprovalEntry, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "{") {
		var af approvalsFile
		if err := json.Unmarshal(data, &af); err != nil {
			return nil, err
		}
		return af.Accepted, nil
	}

	var entries []ApprovalEntry
	var cur *ApprovalEntry
	seenKeys := make(map[string]bool)
	inAccepted := false

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if idx := strings.Index(line, "#"); idx != -1 {
			// strip unquoted comments
			if !strings.ContainsAny(line[:idx], "\"'") {
				line = line[:idx]
			}
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "accepted:") {
			inAccepted = true
			continue
		}
		if !inAccepted {
			if strings.HasPrefix(line, "-") {
				return nil, fmt.Errorf("accepted.yml line %d: list item outside of \"accepted:\" (typo in the header?)", lineNo)
			}
			// Top-level keys (e.g. version) are ignored.
			continue
		}
		if strings.HasPrefix(line, "-") {
			if cur != nil && (cur.Syscall != "" || cur.Target != "") {
				entries = append(entries, *cur)
			}
			cur = &ApprovalEntry{}
			seenKeys = make(map[string]bool)
			line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
			if line == "" {
				continue
			}
		}
		if cur == nil {
			continue
		}
		k, v, ok := splitYAMLKV(line)
		if !ok {
			continue
		}
		if !knownApprovalKeys[k] {
			return nil, fmt.Errorf("accepted.yml line %d: unknown key %q (allowed: target, syscall, reason, expires)", lineNo, k)
		}
		if seenKeys[k] {
			return nil, fmt.Errorf("accepted.yml line %d: duplicate key %q in one entry", lineNo, k)
		}
		seenKeys[k] = true
		switch k {
		case "target":
			cur.Target = v
		case "syscall":
			cur.Syscall = v
		case "reason":
			cur.Reason = v
		case "expires":
			cur.Expires = v
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cur != nil && (cur.Syscall != "" || cur.Target != "") {
		entries = append(entries, *cur)
	}
	return entries, nil
}

// splitYAMLKV splits "key: value". A quoted value is unquoted and anything
// after the closing quote (e.g. a trailing comment) is dropped.
func splitYAMLKV(line string) (string, string, bool) {
	idx := strings.IndexByte(line, ':')
	if idx == -1 {
		return "", "", false
	}
	k := strings.TrimSpace(line[:idx])
	v := strings.TrimSpace(line[idx+1:])
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		if end := strings.IndexByte(v[1:], v[0]); end != -1 {
			return k, v[1 : 1+end], true
		}
	}
	return k, strings.Trim(v, "\"'"), true
}

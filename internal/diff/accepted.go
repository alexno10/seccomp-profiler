package diff

import (
	"bufio"
	"encoding/json"
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

// shortcut: parses flat accepted.yml list without external yaml dependency, upgrade to gopkg.in/yaml.v3 if nested anchors are needed
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
	inAccepted := false

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if idx := strings.Index(line, "#"); idx != -1 {
			// strip unquoted comments
			if !strings.Contains(line[:idx], "\"") && !strings.Contains(line[:idx], "'") {
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
			continue
		}
		if strings.HasPrefix(line, "-") {
			if cur != nil && (cur.Syscall != "" || cur.Target != "") {
				entries = append(entries, *cur)
			}
			cur = &ApprovalEntry{}
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
	if cur != nil && (cur.Syscall != "" || cur.Target != "") {
		entries = append(entries, *cur)
	}
	return entries, sc.Err()
}

func splitYAMLKV(line string) (string, string, bool) {
	idx := strings.IndexByte(line, ':')
	if idx == -1 {
		return "", "", false
	}
	k := strings.TrimSpace(line[:idx])
	v := strings.TrimSpace(line[idx+1:])
	v = strings.Trim(v, "\"'")
	return k, v, true
}

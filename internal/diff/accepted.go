package diff

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
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
	content := strings.TrimPrefix(string(data), "\xef\xbb\xbf")
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "{") {
		dec := json.NewDecoder(strings.NewReader(trimmed))
		dec.DisallowUnknownFields()
		var af approvalsFile
		if err := dec.Decode(&af); err != nil {
			return nil, err
		}
		var trailing any
		if err := dec.Decode(&trailing); err != io.EOF {
			return nil, fmt.Errorf("accepted.yml: unexpected trailing JSON data")
		}
		if err := validateApprovalEntries(af.Accepted); err != nil {
			return nil, err
		}
		return af.Accepted, nil
	}

	var entries []ApprovalEntry
	var cur *ApprovalEntry
	seenKeys := make(map[string]bool)
	inAccepted := false
	acceptedClosed := false

	flushCurrent := func(lineNo int) error {
		if cur == nil {
			return nil
		}
		if strings.TrimSpace(cur.Target) == "" || strings.TrimSpace(cur.Syscall) == "" {
			return fmt.Errorf("accepted.yml line %d: approval entry must specify both target and syscall", lineNo)
		}
		entries = append(entries, *cur)
		cur = nil
		return nil
	}

	sc := bufio.NewScanner(strings.NewReader(content))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(stripYAMLComment(sc.Text()))
		if line == "" {
			continue
		}
		if !inAccepted {
			if line == "accepted:" {
				inAccepted = true
				continue
			}
			if line == "accepted: []" {
				inAccepted = true
				acceptedClosed = true
				continue
			}
			if strings.HasPrefix(line, "-") {
				return nil, fmt.Errorf("accepted.yml line %d: list item outside of \"accepted:\" (typo in the header?)", lineNo)
			}
			k, v, ok := splitYAMLKV(line)
			if !ok {
				return nil, fmt.Errorf("accepted.yml line %d: invalid line outside \"accepted:\"", lineNo)
			}
			if k != "version" {
				return nil, fmt.Errorf("accepted.yml line %d: unknown top-level key %q (expected version or accepted)", lineNo, k)
			}
			if _, err := strconv.Atoi(v); err != nil {
				return nil, fmt.Errorf("accepted.yml line %d: invalid version %q", lineNo, v)
			}
			continue
		}
		if acceptedClosed {
			return nil, fmt.Errorf("accepted.yml line %d: unexpected content after \"accepted: []\"", lineNo)
		}
		if strings.HasPrefix(line, "-") {
			if len(line) > 1 && line[1] != ' ' && line[1] != '\t' {
				return nil, fmt.Errorf("accepted.yml line %d: invalid list item syntax %q", lineNo, line)
			}
			if err := flushCurrent(lineNo); err != nil {
				return nil, err
			}
			cur = &ApprovalEntry{}
			seenKeys = make(map[string]bool)
			line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
			if line == "" {
				continue
			}
		}
		if cur == nil {
			return nil, fmt.Errorf("accepted.yml line %d: expected list item '-' under \"accepted:\"", lineNo)
		}
		k, v, ok := splitYAMLKV(line)
		if !ok {
			return nil, fmt.Errorf("accepted.yml line %d: invalid key-value pair %q", lineNo, line)
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
	if err := flushCurrent(lineNo); err != nil {
		return nil, err
	}
	if err := validateApprovalEntries(entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func validateApprovalEntries(entries []ApprovalEntry) error {
	seen := make(map[[2]string]bool, len(entries))
	for i, e := range entries {
		t := strings.TrimSpace(e.Target)
		s := strings.TrimSpace(e.Syscall)
		if t == "" || s == "" {
			return fmt.Errorf("accepted.yml entry %d: must specify both target and syscall", i+1)
		}
		if exp := strings.TrimSpace(e.Expires); exp != "" {
			if _, err := time.Parse("2006-01-02", exp); err != nil {
				if _, err := time.Parse(time.RFC3339, exp); err != nil {
					return fmt.Errorf("accepted.yml entry %d (%s/%s): invalid expires %q (expected YYYY-MM-DD or RFC3339)", i+1, t, s, exp)
				}
			}
		}
		pair := [2]string{t, s}
		if seen[pair] {
			return fmt.Errorf("accepted.yml: duplicate approval entry for target=%q syscall=%q", t, s)
		}
		seen[pair] = true
	}
	return nil
}

// stripYAMLComment removes an unquoted # comment (preceded by whitespace or at
// index 0) without breaking on apostrophes inside unquoted prose scalars.
func stripYAMLComment(line string) string {
	var inSingle, inDouble bool
	var prev rune
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case inDouble:
			if r == '\\' && i+1 < len(runes) {
				i++
				prev = runes[i]
				continue
			}
			if r == '"' {
				inDouble = false
			}
		case inSingle:
			if r == '\'' {
				if i+1 < len(runes) && runes[i+1] == '\'' {
					i++
					prev = '\''
					continue
				}
				inSingle = false
			}
		default:
			if r == '#' && (i == 0 || unicode.IsSpace(prev)) {
				return string(runes[:i])
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

// splitYAMLKV splits "key: value". A quoted value is unquoted with escape
// handling and fails closed on unclosed quotes or trailing garbage.
func splitYAMLKV(line string) (string, string, bool) {
	idx := strings.IndexByte(line, ':')
	if idx == -1 {
		return "", "", false
	}
	k := strings.TrimSpace(line[:idx])
	if k == "" || strings.ContainsAny(k, " \t\"'") {
		return "", "", false
	}
	v := strings.TrimSpace(line[idx+1:])
	if v == "" {
		return k, "", true
	}
	if v[0] == '"' {
		var sb strings.Builder
		for i := 1; i < len(v); i++ {
			if v[i] == '\\' {
				if i+1 >= len(v) {
					return "", "", false
				}
				i++
				switch v[i] {
				case 'n':
					sb.WriteByte('\n')
				case 't':
					sb.WriteByte('\t')
				default:
					sb.WriteByte(v[i])
				}
				continue
			}
			if v[i] == '"' {
				if strings.TrimSpace(v[i+1:]) != "" {
					return "", "", false
				}
				return k, sb.String(), true
			}
			sb.WriteByte(v[i])
		}
		return "", "", false
	}
	if v[0] == '\'' {
		var sb strings.Builder
		for i := 1; i < len(v); i++ {
			if v[i] == '\'' {
				if i+1 < len(v) && v[i+1] == '\'' {
					sb.WriteByte('\'')
					i++
					continue
				}
				if strings.TrimSpace(v[i+1:]) != "" {
					return "", "", false
				}
				return k, sb.String(), true
			}
			sb.WriteByte(v[i])
		}
		return "", "", false
	}
	return k, v, true
}

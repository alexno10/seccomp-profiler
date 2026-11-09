package diff_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alexno10/seccomp-profiler/internal/diff"
)

// FuzzLoadApprovals guards the hand-rolled YAML parser against panics on
// adversarial accepted.yml content.
func FuzzLoadApprovals(f *testing.F) {
	f.Add("version: 1\naccepted:\n  - target: api\n    syscall: ptrace\n    reason: \"x\"\n")
	f.Add("accepted:\n- syscall: a#b'c\n")
	f.Add("{\n  \"version\": 1,\n  \"accepted\": [{\"target\": \"*\", \"syscall\": \"bpf\"}]\n}")
	f.Add("accepted:\n-  -  -   #\n\t\tweird\ttabs\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, content string) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "accepted.yml")
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Skip()
		}
		_, _ = diff.LoadApprovals(path)
	})
}

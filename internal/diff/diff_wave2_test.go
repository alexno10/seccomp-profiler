package diff

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsExpired_RFC3339PrecisionAndDateBoundary(t *testing.T) {
	// RFC3339 timestamp earlier on the same UTC date MUST already be expired.
	now := time.Date(2026, 11, 12, 15, 0, 0, 0, time.UTC)
	if !isExpired("2026-11-12T10:00:00Z", now) {
		t.Fatal("expected 2026-11-12T10:00:00Z to be expired at 15:00:00Z")
	}
	if isExpired("2026-11-12T16:00:00Z", now) {
		t.Fatal("expected 2026-11-12T16:00:00Z not to be expired at 15:00:00Z")
	}
	// Date-only entries stay valid through the entire listed UTC day.
	if isExpired("2026-11-12", time.Date(2026, 11, 12, 23, 59, 59, 0, time.UTC)) {
		t.Fatal("expected date-only 2026-11-12 to remain valid through 23:59:59Z")
	}
	if !isExpired("2026-11-12", time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("expected date-only 2026-11-12 to expire on 2026-11-13T00:00:00Z")
	}
}

func TestFindApproval_ExactTargetBeatsWildcardRegardlessOfOrder(t *testing.T) {
	approvals := []ApprovalEntry{
		{Target: "*", Syscall: "clone3", Reason: "wildcard", Expires: "2020-01-01"},
		{Target: "api", Syscall: "clone3", Reason: "exact", Expires: "2099-01-01"},
	}
	got, ok := findApproval(approvals, "api", "clone3")
	if !ok || got.Reason != "exact" {
		t.Fatalf("expected exact match to beat earlier wildcard, got ok=%v entry=%+v", ok, got)
	}
}

func TestFileChanged_MissingFilesSemantics(t *testing.T) {
	tmp := t.TempDir()
	missingA := filepath.Join(tmp, "missing-a.json")
	missingB := filepath.Join(tmp, "missing-b.json")
	if FileChanged(missingA, missingB) {
		t.Fatal("expected FileChanged=false when both files are missing")
	}

	present := filepath.Join(tmp, "present.json")
	if err := os.WriteFile(present, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !FileChanged(missingA, present) {
		t.Fatal("expected FileChanged=true when one file is missing and the other exists")
	}
	if FileChanged(present, present) {
		t.Fatal("expected FileChanged=false for identical content")
	}
}

package sessions

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRecorderErrorAndNilBranches(t *testing.T) {
	var nilRecorder *recorder
	nilRecorder.WriteOutput([]byte("ignored"))
	nilRecorder.WriteInput([]byte("ignored"))
	if err := nilRecorder.Close(); err != nil {
		t.Fatalf("nil Close returned %v", err)
	}
	if err := nilRecorder.Sync(); err != nil {
		t.Fatalf("nil Sync returned %v", err)
	}
	if got := nilRecorder.Path(); got != "" {
		t.Fatalf("nil Path = %q, want empty", got)
	}

	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile blocker: %v", err)
	}
	if _, err := newRecorder(filepath.Join(blocker, "child.cast"), 80, 24, "bad"); err == nil {
		t.Fatal("expected mkdir failure from newRecorder")
	}

	path := filepath.Join(dir, "record.cast")
	rec, err := newRecorder(path, 80, 24, "title")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	if rec.Path() != path {
		t.Fatalf("Path = %q, want %q", rec.Path(), path)
	}
	rec.WriteOutput([]byte("hello"))
	rec.WriteInput([]byte("world"))
	if err := rec.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close second call: %v", err)
	}
	rec.WriteOutput([]byte("ignored"))
	rec.WriteInput([]byte("ignored"))
	if err := rec.Sync(); err != nil {
		t.Fatalf("Sync after Close: %v", err)
	}
}

func TestRecorderCloseNilAndSyncNil(t *testing.T) {
	if err := (*recorder)(nil).Close(); err != nil {
		t.Fatalf("nil Close returned %v", err)
	}
	if err := (*recorder)(nil).Sync(); err != nil {
		t.Fatalf("nil Sync returned %v", err)
	}
}

func TestRecorderCloseAndSyncAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.cast")
	rec, err := newRecorder(path, 80, 24, "title")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := rec.Sync(); err != nil {
		t.Fatalf("Sync after Close: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close second call: %v", err)
	}
}

var _ = errors.New

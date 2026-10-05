package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCoverage97OpenRejectsDirectoryPath(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir); err == nil {
		t.Fatal("opened a directory as a database")
	}
	parent := t.TempDir()
	blocker := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(blocker, "state.db")); err == nil {
		t.Fatal("opened a database under a file")
	}
}

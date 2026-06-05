package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreOpenErrors(t *testing.T) {
	// 1. Unwriteable directory
	dir := t.TempDir()
	badDir := filepath.Join(dir, "bad")
	os.Mkdir(badDir, 0o400) // read-only
	_, _ = Open(filepath.Join(badDir, "db", "file.db"))

	// 2. Chmod failure (create a file where a dir should be)
	fileDir := filepath.Join(dir, "filedir")
	os.WriteFile(fileDir, []byte("x"), 0o644)
	_, _ = Open(filepath.Join(fileDir, "db.sqlite"))

	// 3. Bad permissions on the DB file itself (chmod fails on the sidecars)
	validDir := filepath.Join(dir, "valid")
	os.Mkdir(validDir, 0o700)
	dbPath := filepath.Join(validDir, "test.db")
	st, err := Open(dbPath)
	if err == nil {
		st.Close()
		// Try to reopen after making it read-only
		os.Chmod(dbPath, 0o400)
		_, _ = Open(dbPath)
	}
}

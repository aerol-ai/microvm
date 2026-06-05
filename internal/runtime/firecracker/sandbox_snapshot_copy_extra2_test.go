package firecracker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyFile_Extra(t *testing.T) {
	dir := t.TempDir()

	// src is a directory
	if err := copyFile(dir, filepath.Join(dir, "dst")); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("expected directory error, got %v", err)
	}

	// dst create fails (e.g. dst is a directory)
	src := filepath.Join(dir, "src")
	os.WriteFile(src, []byte("data"), 0644)
	dstDir := filepath.Join(dir, "dstDir")
	os.Mkdir(dstDir, 0755)
	if err := copyFile(src, dstDir); err == nil || !strings.Contains(err.Error(), "create") {
		t.Errorf("expected create error, got %v", err)
	}
}

func TestSyncFileAndDir_Extra(t *testing.T) {
	// syncFile non-existent
	if err := syncFile("/no-exist"); err == nil {
		t.Errorf("expected syncFile error")
	}

	// syncDir non-existent (should not panic/error)
	syncDir("/no-exist")
}

package firecracker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSandboxSnapshot_CopyFile_ExtraCoverage(t *testing.T) {
	dir := t.TempDir()

	// src doesn't exist
	if err := copyFile(filepath.Join(dir, "no-exist"), filepath.Join(dir, "dst")); err == nil || !strings.Contains(err.Error(), "stat ") {
		t.Errorf("expected stat error, got %v", err)
	}

	// src is a directory
	if err := copyFile(dir, filepath.Join(dir, "dst")); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("expected directory error, got %v", err)
	}

	// dst creation fails (e.g. dst is a directory)
	srcPath := filepath.Join(dir, "src")
	os.WriteFile(srcPath, []byte("test"), 0600)
	if err := copyFile(srcPath, dir); err == nil || !strings.Contains(err.Error(), "create ") {
		t.Errorf("expected create error, got %v", err)
	}
}

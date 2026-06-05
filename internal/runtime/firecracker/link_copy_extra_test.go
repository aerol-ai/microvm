package firecracker

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLinkOrCopyRootfs_FallbackCoverage(t *testing.T) {
	dir := t.TempDir()

	// src is a directory -> os.Link fails with EPERM, falls back to copy.
	// copy fails because src is a directory (io.Copy fails).
	dst := filepath.Join(dir, "dst")
	err := linkOrCopyRootfs(dir, dst)
	if err == nil || !strings.Contains(err.Error(), "copy template rootfs") {
		t.Errorf("expected copy template rootfs error (is a directory), got %v", err)
	}

	// copy path success -> we need os.Link to fail but copy to succeed.
	// Unfortunately without crossing mount points or mocking, it's hard to make Link fail and Open succeed for a regular file.
	// But we covered the fallback open/create/copy failure path.

	// open failure
	// src is a file that doesn't exist -> os.Link fails with ENOENT.
	// Wait, ENOENT doesn't fall back, it returns immediately!
	err = linkOrCopyRootfs(filepath.Join(dir, "no-exist"), dst)
	if err == nil || !strings.Contains(err.Error(), "link template rootfs") {
		t.Errorf("expected link error, got %v", err)
	}
}

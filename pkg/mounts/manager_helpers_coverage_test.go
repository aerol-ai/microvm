package mounts

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

func TestWriteCredFileAndCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "cred.json")

	if err := writeCredFile(path, []byte("secret")); err != nil {
		t.Fatalf("writeCredFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cred: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cred mode = %v, want 0600", info.Mode().Perm())
	}

	// cleanupCred removes the file; second call is a no-op.
	m := &Manager{}
	m.cleanupCred(adapters.Plan{CredFile: path})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("cred file should be removed, stat err = %v", err)
	}
	m.cleanupCred(adapters.Plan{CredFile: path}) // no panic on missing file
	m.cleanupCred(adapters.Plan{})               // empty CredFile is a no-op
}

func TestWaitForMountTimesOut(t *testing.T) {
	dir := t.TempDir()
	// A path that never becomes a distinct mount point times out quickly.
	if err := waitForMount(filepath.Join(dir, "never"), 250*time.Millisecond); err == nil {
		t.Fatal("waitForMount should time out for a non-mount path")
	}
}

func TestKillMountNil(t *testing.T) {
	if err := killMount(nil); err != nil {
		t.Fatalf("killMount(nil) = %v, want nil", err)
	}
}

func TestWriteCredFileErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0400); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	err := writeCredFile(filepath.Join(dir, "newdir", "cred.json"), []byte("data"))
	if err == nil {
		t.Fatal("expected error")
	}

	dir2 := t.TempDir()
	path2 := filepath.Join(dir2, "cred.json")
	os.Mkdir(path2, 0700)
	err = writeCredFile(path2, []byte("data"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCleanupOrphanDirAndUnmountTree(t *testing.T) {
	logger := slog.Default()
	m, _ := New(logger, Config{RootDir: t.TempDir(), CredDir: t.TempDir()})
	dir := filepath.Join(m.rootDir, "test-orphan")
	os.Mkdir(dir, 0700)
	m.cleanupOrphanDir(dir)
	unmountTree(logger, dir)
}

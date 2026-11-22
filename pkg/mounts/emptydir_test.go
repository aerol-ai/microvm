package mounts

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEmptyOnDevice: everything in the folder goes, the folder stays, a
// link is removed and never followed, and a folder on another device (a
// mount) is left with what it holds.
func TestEmptyOnDevice(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	keep := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(keep, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustMk := func(p string) {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustMk(filepath.Join(dir, "a", "b"))
	mustMk(filepath.Join(dir, "mnt", "inside"))
	if err := os.WriteFile(filepath.Join(dir, "a", "b", "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	mnt := filepath.Join(dir, "mnt")
	prev := pathDevOf
	pathDevOf = func(p string) uint64 {
		if p == mnt || filepath.Dir(p) == mnt {
			return 99
		}
		return 1
	}
	t.Cleanup(func() { pathDevOf = prev })
	if err := EmptyOnDevice(dir); err == nil {
		t.Fatal("a folder on another device was walked")
	}
	if _, err := os.Stat(filepath.Join(mnt, "inside")); err != nil {
		t.Fatalf("the mount's files went: %v", err)
	}
	for _, gone := range []string{"a", "link"} {
		if _, err := os.Lstat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Errorf("%s left: %v", gone, err)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("followed the link: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("the folder itself went: %v", err)
	}
	if err := EmptyOnDevice(filepath.Join(dir, "missing")); err != nil {
		t.Fatalf("a missing folder: %v", err)
	}
	pathDevOf = prev
	if err := EmptyOnDevice(mnt); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(mnt); len(entries) != 0 {
		t.Fatalf("left %v", entries)
	}
}

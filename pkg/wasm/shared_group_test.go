package wasm

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSharedModes(t *testing.T) {
	t.Cleanup(func() { sharedWithGroup.Store(false) })
	if sharedFileMode(0o600) != 0o600 || sharedDirMode(0o700) != 0o700 {
		t.Fatal("modes changed with sharing off")
	}
	ShareFilesWithGroup()
	for _, tc := range []struct{ in, want fs.FileMode }{{0o600, 0o660}, {0o644, 0o664}, {0o400, 0o440}, {0o200, 0o220}} {
		if got := sharedFileMode(tc.in); got != tc.want {
			t.Errorf("file %o -> %o, want %o", tc.in, got, tc.want)
		}
	}
	if got := sharedDirMode(0o700); got != 0o770 {
		t.Errorf("dir 0700 -> %o", got)
	}
}

// TestWriteSnapshotDirSharesWithGroup: a worker of privilege mode split
// writes its checkpoint so its group, which sandboxd is in, can read it
// and copy it out; with sharing off the modes are single mode's.
func TestWriteSnapshotDirSharesWithGroup(t *testing.T) {
	t.Cleanup(func() { sharedWithGroup.Store(false) })
	old := syscall.Umask(0o007)
	t.Cleanup(func() { syscall.Umask(old) })
	capture := SnapshotCapture{Config: SnapshotConfig{CloneGeneration: "g1"}, Memory: []byte("memory")}
	for _, tc := range []struct {
		share       bool
		dirs, files fs.FileMode
	}{
		{false, 0o700, 0o600},
		{true, 0o770, 0o660},
	} {
		sharedWithGroup.Store(tc.share)
		dst := filepath.Join(t.TempDir(), "mem.snap")
		if err := WriteSnapshotDir(dst, capture); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(dst)
		if err != nil || st.Mode().Perm() != tc.dirs {
			t.Fatalf("share=%v: folder %v (%v), want %o", tc.share, st.Mode().Perm(), err, tc.dirs)
		}
		for _, f := range SnapshotFiles(dst) {
			if st, err := os.Stat(f); err != nil || st.Mode().Perm() != tc.files {
				t.Fatalf("share=%v: %s mode %v (%v), want %o", tc.share, filepath.Base(f), st.Mode().Perm(), err, tc.files)
			}
		}
		if _, err := ReadSnapshotDir(dst, ""); err != nil {
			t.Fatalf("share=%v: read back: %v", tc.share, err)
		}
	}
	// A folder the chmod cannot reach fails the write and leaves nothing.
	sharedWithGroup.Store(true)
	parent := t.TempDir()
	oldChmod := chmodSnapshotDir
	t.Cleanup(func() { chmodSnapshotDir = oldChmod })
	chmodSnapshotDir = func(string, os.FileMode) error { return os.ErrPermission }
	if err := WriteSnapshotDir(filepath.Join(parent, "mem.snap"), capture); err == nil {
		t.Fatal("wrote with the folder unshared")
	}
	if left, _ := os.ReadDir(parent); len(left) != 0 {
		t.Fatalf("left %v", left)
	}
}

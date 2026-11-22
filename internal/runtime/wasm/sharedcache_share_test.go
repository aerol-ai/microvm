//go:build unix

package wasm

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestShareAtFollowsNoLink: in split mode the worker can write the owner's
// cache folder, so it could swap the new version folder for a link between
// the make and the share. shareAt gives the folder itself to the worker's
// group (setgid, 0770) and refuses anything at the name that is not a
// folder, a link to one included: the link's target keeps its group and mode.
func TestShareAtFollowsNoLink(t *testing.T) {
	gid := shareGID()
	owner := t.TempDir()
	elsewhere := filepath.Join(t.TempDir(), "agent-only")
	if err := os.Mkdir(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	before := statOf(t, elsewhere)
	if err := os.Mkdir(filepath.Join(owner, "v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(owner, "v2")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owner, "v3"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ownerFD, err := unix.Open(owner, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ownerFD)

	if err := shareAt(ownerFD, "v1", gid); err != nil {
		t.Fatal(err)
	}
	if st := statOf(t, filepath.Join(owner, "v1")); int(st.Gid) != gid || st.Mode&0o7777 != syscall.S_ISGID|0o770 {
		t.Fatalf("v1: gid %d mode %o, want %d %o", st.Gid, st.Mode&0o7777, gid, syscall.S_ISGID|0o770)
	}
	for _, name := range []string{"v2", "v3", "v4"} {
		if err := shareAt(ownerFD, name, gid); err == nil {
			t.Errorf("%s: shared, want a refusal", name)
		}
	}
	if after := statOf(t, elsewhere); after.Gid != before.Gid || after.Mode != before.Mode {
		t.Fatalf("the link's target changed: gid %d mode %o, was %d %o", after.Gid, after.Mode, before.Gid, before.Mode)
	}
}

// TestSharedLinkIntoSplit: in split mode a version folder made for the
// worker goes to its group, not its uid (the agent cannot chown to
// another user).
func TestSharedLinkIntoSplit(t *testing.T) {
	d, _, _, _ := splitDriver(t)
	src, owner := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "entry"), []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := d.sharedLinkInto(src, owner, "v1"); err != nil {
		t.Fatal(err)
	}
	if st := statOf(t, filepath.Join(owner, "v1")); int(st.Gid) != d.cfg.Worker.GID || st.Mode&0o7777 != syscall.S_ISGID|0o770 {
		t.Fatalf("v1: gid %d mode %o, want %d %o", st.Gid, st.Mode&0o7777, d.cfg.Worker.GID, syscall.S_ISGID|0o770)
	}
	if _, err := os.Stat(filepath.Join(owner, "v1", "entry")); err != nil {
		t.Fatalf("entry not linked: %v", err)
	}
}

func statOf(t *testing.T, p string) unix.Stat_t {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

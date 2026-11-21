package rootfolder

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestListenNeedsAFolderOfItsOwn is review H1: the socket's folder must be
// closed to everyone but root (here: this test's user), or an agent that
// can write it races root's chmod onto any file. Listen refuses such a
// folder before it binds anything there, and a link on the way.
func TestListenNeedsAFolderOfItsOwn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string) string // returns the socket path
		want  string
	}{
		{"an emptyDir every container can write", func(t *testing.T, dir string) string {
			if err := unix.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "root.sock")
		}, "can be written by others"},
		{"a folder its group can write", func(t *testing.T, dir string) string {
			if err := unix.Chmod(dir, 0o770); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "root.sock")
		}, "can be written by others"},
		{"a sticky folder, which is not enough for the socket's own", func(t *testing.T, dir string) string {
			if err := unix.Chmod(dir, 0o1777); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "root.sock")
		}, "can be written by others"},
		{"a folder under one others can write", func(t *testing.T, dir string) string {
			if err := unix.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
			sub := filepath.Join(dir, "rootd")
			if err := os.Mkdir(sub, 0o755); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(sub, "root.sock")
		}, "can be written by others"},
		{"a folder reached through a link", func(t *testing.T, dir string) string {
			real := filepath.Join(dir, "real")
			if err := os.Mkdir(real, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, filepath.Join(dir, "via")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "via", "root.sock")
		}, "without following a link"},
		{"a link where the socket goes", func(t *testing.T, dir string) string {
			if err := os.Symlink("/etc/hosts", filepath.Join(dir, "root.sock")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "root.sock")
		}, "not a socket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := shortDir(t)
			path := tc.setup(t, dir)
			ln, _, err := Listen(path, os.Getgid())
			if err == nil {
				_ = ln.Close()
				t.Fatalf("Listen in %s succeeded", filepath.Dir(path))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Listen = %v, want %q", err, tc.want)
			}
			if fi, err := os.Lstat(path); err == nil && fi.Mode().Type() == fs.ModeSocket {
				t.Fatal("a socket was made anyway")
			}
			leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".root.sock.*"))
			if len(leftovers) != 0 {
				t.Fatalf("half-made sockets left: %v", leftovers)
			}
		})
	}
	t.Run("a relative folder", func(t *testing.T) {
		if _, err := OpenFolder("run/x"); err == nil {
			t.Fatal("OpenFolder took a relative path")
		}
	})
	t.Run("the root folder itself", func(t *testing.T) {
		fd, err := OpenFolder("/")
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
	})
}

// TestListenLeavesNothingBehindOnAFailedRename: a socket name taken by a
// folder (only root could put one there) fails the rename, and the
// half-made socket is removed.
func TestListenLeavesNothingBehindOnAFailedRename(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "root.sock")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	ln, _, err := Listen(path, os.Getgid())
	if err == nil {
		_ = ln.Close()
		t.Fatal("Listen replaced a folder")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".root.sock.*")); len(leftovers) != 0 {
		t.Fatalf("half-made sockets left: %v", leftovers)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.IsDir() || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the folder is gone: %v", err)
	}
}

// TestListenMakesNothingThroughALink is review N2: a missing socket folder
// is made through the checked folder above it, never by path, so a link on
// the way is refused before root makes anything where it points.
func TestListenMakesNothingThroughALink(t *testing.T) {
	dir := shortDir(t)
	elsewhere := filepath.Join(dir, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dir, "aerolvm")); err != nil {
		t.Fatal(err)
	}
	ln, _, err := Listen(filepath.Join(dir, "aerolvm", "rootd", "root.sock"), os.Getgid())
	if err == nil {
		_ = ln.Close()
		t.Fatal("Listen followed the link")
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, "rootd")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a folder was made through the link: %v", err)
	}
}

// TestListenMakesMissingFolders: missing folders are made root's (here:
// this test's user's) and closed, and the socket goes in the last.
func TestListenMakesMissingFolders(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "a", "b", "root.sock")
	ln, _, err := Listen(path, os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, d := range []string{filepath.Join(dir, "a"), filepath.Join(dir, "a", "b")} {
		fi, err := os.Lstat(d)
		if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
			t.Fatalf("%s: %v, %v", d, fi, err)
		}
	}
}

// TestMakeFolderFails: a name that cannot be made (a read-only folder) is
// an error naming it.
func TestMakeFolderFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only folder")
	}
	dir := shortDir(t)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	ln, _, err := Listen(filepath.Join(dir, "new", "root.sock"), os.Getgid())
	if err == nil {
		_ = ln.Close()
		t.Fatal("Listen made a folder in a read-only one")
	}
	if !strings.Contains(err.Error(), "make "+filepath.Join(dir, "new")) {
		t.Fatalf("Listen = %v", err)
	}
}

// shortDir is a folder short enough for a socket's sun_path (104 bytes on
// macOS), with no link on the way to it.
func shortDir(t testing.TB) string {
	t.Helper()
	d, err := os.MkdirTemp("", "rf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	// Root's code follows no link (macOS: /var is one).
	if d, err = filepath.EvalSymlinks(d); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestCheckFolder: root's or the owner's, closed to others, or sticky
// where sticky is allowed.
func TestCheckFolder(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mode, uid    uint32
		sticky       bool
		wantContains string
	}{
		{"root's, closed", 0o040755, 0, false, ""},
		{"the owner's", 0o040700, 1000, false, ""},
		{"someone else's", 0o040755, 2000, false, "belongs to uid 2000"},
		{"not a folder", 0o100644, 0, false, "not a folder"},
		{"group can write", 0o040775, 0, false, "can be written by others"},
		{"sticky where allowed", 0o041777, 0, true, ""},
		{"sticky where not allowed", 0o041777, 0, false, "can be written by others"},
		{"open, not sticky, where sticky allowed", 0o040777, 0, true, "can be written by others"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckFolder("/x", tc.mode, tc.uid, 1000, tc.sticky)
			if tc.wantContains == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantContains) {
				t.Fatalf("CheckFolder = %v, want %q", err, tc.wantContains)
			}
		})
	}
}

// TestTmpNames: a name TmpName gives is one IsTmpName knows, and nothing
// else is.
func TestTmpNames(t *testing.T) {
	n, err := TmpName("root.sock")
	if err != nil {
		t.Fatal(err)
	}
	if !IsTmpName(n, "root.sock") {
		t.Fatalf("IsTmpName(%q) = false", n)
	}
	for _, other := range []string{"root.sock", ".root.sock.", ".root.sock.ABCDEF0123456789", ".root.sock.0123456789abcdeg", ".other.0123456789abcdef", ".root.sock.0123"} {
		if IsTmpName(other, "root.sock") {
			t.Errorf("IsTmpName(%q) = true", other)
		}
	}
}

// TestWalkFolderWithoutMaking: without mk a missing folder is an error,
// and nothing is made; a check's error stops the walk.
func TestWalkFolderWithoutMaking(t *testing.T) {
	dir := shortDir(t)
	missing := filepath.Join(dir, "missing")
	if _, err := WalkFolder(missing, false, func(string, *unix.Stat_t, bool) error { return nil }); err == nil {
		t.Fatal("walked to a folder that is not there")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a folder was made: %v", err)
	}
	boom := errors.New("refused")
	if _, err := WalkFolder("/", false, func(string, *unix.Stat_t, bool) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("WalkFolder(/) = %v, want the check's error", err)
	}
	if _, err := WalkFolder(dir, false, func(at string, _ *unix.Stat_t, last bool) error {
		if last {
			return boom
		}
		return nil
	}); !errors.Is(err, boom) {
		t.Fatalf("WalkFolder = %v, want the check's error on the last folder", err)
	}
}

// TestListenReplacesADeadSocket: a socket a run that died left behind is
// replaced in one step, and the new one is 0660 to the group.
func TestListenReplacesADeadSocket(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "root.sock")
	old, _, err := Listen(path, os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	_ = old.Close() // does not remove the socket
	if fi, err := os.Lstat(path); err != nil || fi.Mode().Type() != fs.ModeSocket {
		t.Fatalf("closing the listener removed the socket: %v", err)
	}
	ln, fi, err := Listen(path, os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %o, want 0660", fi.Mode().Perm())
	}
}

// TestListenChecksWhatItBound: whatever is at the new name after bind is
// checked before root chgrps and chmods it; anything but the socket just
// made (gone, or a file in its place) fails, and nothing is left behind.
func TestListenChecksWhatItBound(t *testing.T) {
	for _, tc := range []struct {
		name string
		swap func(dfd int, tmp string)
		want string
	}{
		{"gone", func(dfd int, tmp string) { _ = unix.Unlinkat(dfd, tmp, 0) }, "no such file"},
		{"a file in its place", func(dfd int, tmp string) {
			_ = unix.Unlinkat(dfd, tmp, 0)
			fd, err := unix.Openat(dfd, tmp, unix.O_CREAT|unix.O_WRONLY, 0o600)
			if err == nil {
				_ = unix.Close(fd)
			}
		}, "is not the socket just made"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			afterBind = tc.swap
			t.Cleanup(func() { afterBind = nil })
			dir := shortDir(t)
			ln, _, err := Listen(filepath.Join(dir, "root.sock"), os.Getgid())
			if err == nil {
				_ = ln.Close()
				t.Fatal("Listen took what was at the name")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Listen = %v, want %q", err, tc.want)
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Fatalf("left %v", ents)
			}
		})
	}
}

// TestListenNamesTooLong: a socket name the folder cannot hold, and a path
// too long for a socket address, fail before anything is left.
func TestListenNamesTooLong(t *testing.T) {
	dir := shortDir(t)
	if ln, _, err := Listen(filepath.Join(dir, strings.Repeat("s", 300)), os.Getgid()); err == nil {
		_ = ln.Close()
		t.Fatal("Listen took a 300-byte name")
	}
	deep := filepath.Join(dir, strings.Repeat("d", 100))
	if ln, _, err := Listen(filepath.Join(deep, "root.sock"), os.Getgid()); err == nil {
		_ = ln.Close()
		t.Fatal("Listen bound a path longer than a socket address holds")
	} else if !strings.Contains(err.Error(), "listen") {
		t.Fatalf("Listen = %v, want the bind's error", err)
	}
	if ents, _ := os.ReadDir(deep); len(ents) != 0 {
		t.Fatalf("left %v", ents)
	}
}

// TestListenGroupItMayNotUse: a group this user may not give the socket
// fails the chgrp, and the socket made goes (as root every group is
// allowed).
func TestListenGroupItMayNotUse(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may give any group")
	}
	dir := shortDir(t)
	if ln, _, err := Listen(filepath.Join(dir, "root.sock"), 1<<30); err == nil {
		_ = ln.Close()
		t.Fatal("Listen gave the socket a group this user is not in")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("left %v", ents)
	}
}

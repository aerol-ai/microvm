package rootd

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
// can write it races root's chmod onto any file. listen refuses such a
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
			ln, _, err := listen(path, os.Getgid())
			if err == nil {
				_ = ln.Close()
				t.Fatalf("listen in %s succeeded", filepath.Dir(path))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("listen = %v, want %q", err, tc.want)
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
		if _, err := openFolder("run/x"); err == nil {
			t.Fatal("openFolder took a relative path")
		}
	})
	t.Run("the root folder itself", func(t *testing.T) {
		fd, err := openFolder("/")
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
	ln, _, err := listen(path, os.Getgid())
	if err == nil {
		_ = ln.Close()
		t.Fatal("listen replaced a folder")
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
	ln, _, err := listen(filepath.Join(dir, "aerolvm", "rootd", "root.sock"), os.Getgid())
	if err == nil {
		_ = ln.Close()
		t.Fatal("listen followed the link")
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
	ln, _, err := listen(path, os.Getgid())
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
	ln, _, err := listen(filepath.Join(dir, "new", "root.sock"), os.Getgid())
	if err == nil {
		_ = ln.Close()
		t.Fatal("listen made a folder in a read-only one")
	}
	if !strings.Contains(err.Error(), "make "+filepath.Join(dir, "new")) {
		t.Fatalf("listen = %v", err)
	}
}

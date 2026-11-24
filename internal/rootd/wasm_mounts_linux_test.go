//go:build linux

package rootd

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestOpenMountPoint: a mount point is opened through the sandbox's folder
// of the helper's, with no link followed anywhere on the way, for its
// handle alone (O_PATH: the mount itself is never entered).
func TestOpenMountPoint(t *testing.T) {
	root := filepath.Join(shortDir(t), "mounts")
	for _, d := range []string{filepath.Join(root, "sb-1", "0"), filepath.Join(root, "sb-2", "0"), filepath.Join(root, "open")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f, err := openMountPoint(root, "sb-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	_ = f.Close()
	if err != nil || flags&unix.O_PATH == 0 || f.Name() != filepath.Join(root, "sb-1", "0") {
		t.Fatalf("handle %s flags %o (%v): want O_PATH", f.Name(), flags, err)
	}
	// What the mount points' folders must never hold, as only root could
	// put it there.
	if err := os.Symlink(filepath.Join(root, "sb-2"), filepath.Join(root, "sb-3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "sb-2", "0"), filepath.Join(root, "sb-1", "1")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sb-1", "2"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "open"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "open", "0"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		id    string
		index int
	}{
		"a sandbox folder that is a link": {"sb-3", 0},
		"a mount point that is a link":    {"sb-1", 1},
		"a mount point that is a file":    {"sb-1", 2},
		"a missing mount point":           {"sb-1", 3},
		"a missing sandbox folder":        {"sb-9", 0},
		"a folder others can write":       {"open", 0},
		"a sandbox id that climbs":        {"..", 0},
	} {
		if f, err := openMountPoint(root, tc.id, tc.index); err == nil {
			_ = f.Close()
			t.Errorf("%s: opened", name)
		}
	}
}

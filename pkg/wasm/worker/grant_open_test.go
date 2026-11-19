package worker

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// grantWorker is a worker uid/gid that is not the test's own, so the test's
// folders count as not the worker's unless they are open to everyone.
var grantWorker = Confinement{UID: 4242, GID: 4242}

func withGrantPolicy(t *testing.T, p GrantPolicy) {
	t.Helper()
	prev := grantPolicy.Load()
	SetGrantPolicy(p)
	t.Cleanup(func() { grantPolicy.Store(prev) })
}

// R2: a path sandboxd passes is opened from its trusted folder one name at
// a time: no link is followed, no folder the worker could write is passed
// through, and a file must be a plain one the worker cannot change.
func TestOpenGrantPathConfined(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	mk := func(rel string, mode os.FileMode) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(rel), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // past the umask
			t.Fatal(err)
		}
		return p
	}
	if err := os.WriteFile(secret, []byte("host"), 0o600); err != nil {
		t.Fatal(err)
	}
	plain := mk("modules/m.wasm", 0o600)
	work := filepath.Join(root, "run", "sb-1")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(work, 0o777); err != nil { // the worker's own /work
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "modules", "link.wasm")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "run", "dirlink")); err != nil {
		t.Fatal(err)
	}
	open := mk("open/inner/f", 0o600)
	if err := os.Chmod(filepath.Dir(open), 0o777); err != nil {
		t.Fatal(err)
	}
	everyone := mk("modules/everyone.wasm", 0o666)
	hard := filepath.Join(root, "modules", "hard.wasm")
	if err := os.Link(secret, hard); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root, "modules", "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	withGrantPolicy(t, GrantPolicy{Roots: []string{root, "relative", ""}, Worker: grantWorker})

	for _, tc := range []struct {
		name   string
		path   string
		strict bool
		ok     bool
	}{
		{"plain module", plain, false, true},
		{"root-owned snapshot file", plain, true, true},
		{"the worker's own folder last", work, false, true},
		{"a root itself", root, false, true},
		{"link as the last name", filepath.Join(root, "modules", "link.wasm"), false, false},
		{"link on the way", filepath.Join(root, "run", "dirlink", "secret"), false, false},
		{"through a folder open to everyone", filepath.Join(filepath.Dir(open), "f"), false, false},
		{"through the worker's folder", filepath.Join(work, "x"), false, false},
		{"file the worker may write", everyone, false, false},
		{"file with a second name", hard, false, false},
		{"not a file or folder", fifo, false, false},
		{"missing", filepath.Join(root, "modules", "none"), false, false},
		{"relative", "modules/m.wasm", false, false},
	} {
		f, err := openGrantPath(tc.path, tc.strict)
		if (err == nil) != tc.ok {
			t.Fatalf("%s: open = %v, want ok=%v", tc.name, err, tc.ok)
		}
		if f != nil {
			_ = f.Close()
		}
	}
	// A snapshot file must be root's: as root, one owned by another uid is
	// refused.
	if os.Geteuid() == 0 {
		if err := os.Chown(plain, 4343, 4343); err != nil {
			t.Fatal(err)
		}
		if _, err := openGrantPath(plain, true); !errors.Is(err, errGrantRefused) {
			t.Fatalf("snapshot file of another uid = %v", err)
		}
		// And a folder of the worker's own on the way is refused.
		mid := filepath.Join(root, "mine", "x")
		if err := os.MkdirAll(mid, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(filepath.Dir(mid), grantWorker.UID, grantWorker.GID); err != nil {
			t.Fatal(err)
		}
		if _, err := openGrantPath(mid, false); !errors.Is(err, errGrantRefused) {
			t.Fatalf("through a folder the worker owns = %v", err)
		}
	}
	// Without a confinement, paths open as they always did (a link too).
	withGrantPolicy(t, GrantPolicy{Roots: []string{root}})
	f, err := openGrantPath(filepath.Join(root, "modules", "link.wasm"), false)
	if err != nil {
		t.Fatalf("unconfined open: %v", err)
	}
	_ = f.Close()
	if _, err := openGrantPath(fifo, false); err == nil {
		t.Fatal("unconfined open took a FIFO")
	}
}

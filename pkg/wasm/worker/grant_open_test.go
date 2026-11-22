package worker

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
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

// F-G: a folder or file the worker owns counts as one it can write whatever
// its mode (it can chmod it back), and so does one that carries an access
// ACL, which the mode bits do not show.
func TestWorkerWritable(t *testing.T) {
	me := Confinement{UID: os.Getuid(), GID: 4242}
	other := grantWorker
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	fd, err := syscall.Open(dir, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	if !workerWritable(fd, st, me) {
		t.Fatal("a read-only folder the worker owns counted as safe")
	}
	if workerWritable(fd, st, other) {
		t.Fatal("a read-only folder of another uid counted as writable")
	}
	prev := hasAccessACL
	t.Cleanup(func() { hasAccessACL = prev })
	hasAccessACL = func(int) bool { return true }
	if !workerWritable(fd, st, other) {
		t.Fatal("a folder with an ACL counted as safe")
	}
	hasAccessACL = prev
	if hasAccessACL(fd) {
		t.Fatal("a plain temp folder has an access ACL")
	}
	group, world := st, st
	group.Mode &^= 0o777
	group.Mode |= 0o020
	group.Gid = uint32(other.GID)
	world.Mode &^= 0o777
	world.Mode |= 0o002
	if !workerWritable(-1, group, other) || !workerWritable(-1, world, other) {
		t.Fatal("a group- or world-writable folder counted as safe")
	}
}

// TestPlainGrantName: the plain open's name is the path itself for every
// clean path that does not climb above the working folder, absolute or
// relative, ".." inside a name included; anything else is refused.
func TestPlainGrantName(t *testing.T) {
	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{"/", true},
		{"/var/lib/sandboxd/wasm/modules/app.wasm", true},
		{"/srv/v1..2/app.wasm", true},
		{"/srv/..hidden", true},
		{"modules/app.wasm", true},
		{"mods/v1..2/app.wasm", true},
		{".", true},
		{"..", false},
		{"../x", false},
		{"../../srv/app.wasm", false},
		{"/srv/../etc", false}, // not clean: openGrants cleans first
		{"a/./b", false},
		{"a//b", false},
		{"/srv/", false},
		{"", false},
	} {
		name, ok := plainGrantName(tc.path)
		if ok != tc.ok || ok && name != tc.path {
			t.Errorf("plainGrantName(%q) = %q, %v; want ok %v and the path itself", tc.path, name, ok, tc.ok)
		}
	}
}

// TestOpenGrantPathPlain: with workers not confined, a clean path opens as
// it always did, by the same name; a relative path that climbs above the
// working folder is refused, and openGrants leaves it out (the worker then
// opens it itself).
func TestOpenGrantPathPlain(t *testing.T) {
	withGrantPolicy(t, GrantPolicy{})
	dir := t.TempDir()
	file := filepath.Join(dir, "m.wasm")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{file, dir, "grant_open.go"} { // the last relative to the test's folder
		f, err := openGrantPath(p, false)
		if err != nil {
			t.Fatalf("open %q: %v", p, err)
		}
		if f.Name() != p {
			t.Errorf("open %q named %q", p, f.Name())
		}
		_ = f.Close()
	}
	climb := filepath.Join("..", filepath.Base(mustGetwd(t)), "grant_open.go")
	if _, err := os.Stat(climb); err != nil {
		t.Fatalf("the climbing path should name a real file: %v", err)
	}
	if _, err := openGrantPath(climb, false); !errors.Is(err, errGrantRefused) {
		t.Fatalf("open %q = %v, want a refusal", climb, err)
	}
	files, names := openGrants([]string{file, climb})
	defer closeFiles(files)
	if len(files) != 1 || len(names) != 1 || names[0] != file {
		t.Fatalf("granted %v", names)
	}
}

// TestOpenGrantPathConfinedName: the confined walk names the file it opens
// by the clean path, as before.
func TestOpenGrantPathConfinedName(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "m.wasm")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	withGrantPolicy(t, GrantPolicy{Roots: []string{root}, Worker: grantWorker})
	f, err := openGrantPath(file+"/", false)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Name() != file {
		t.Fatalf("named %q, want %q", f.Name(), file)
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

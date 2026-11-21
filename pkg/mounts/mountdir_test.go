package mounts

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// fakeMountTable stands in /proc/self/mountinfo with one line per mount
// point and returns a function that rewrites it.
func fakeMountTable(t *testing.T, points ...string) func(points ...string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mountinfo")
	write := func(points ...string) {
		var b strings.Builder
		b.WriteString("22 1 0:21 / /proc rw - proc proc rw\n")
		for i, p := range points {
			p = strings.ReplaceAll(p, " ", `\040`)
			b.WriteString("3" + string(rune('0'+i)) + " 22 0:5" + string(rune('0'+i)) + " / " + p + " rw,nosuid master:1 - nfs4 h:/e rw\n")
		}
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(points...)
	prev := mountInfoPath
	mountInfoPath = path
	t.Cleanup(func() { mountInfoPath = prev })
	return write
}

// stubUmount records unmounts; ok decides which succeed (the lazy one too).
func stubUmount(t *testing.T, ok func(path string) bool) *[]string {
	t.Helper()
	var calls []string
	prevU, prevL := sweepUmount, sweepLazyUmount
	sweepUmount = func(p string) error {
		calls = append(calls, p)
		if ok(p) {
			return nil
		}
		return errors.New("umount: target is busy")
	}
	sweepLazyUmount = func(p string) error {
		if ok(p) {
			return nil
		}
		return errors.New("umount: not permitted")
	}
	t.Cleanup(func() { sweepUmount, sweepLazyUmount = prevU, prevL })
	return &calls
}

// The regression: UnmountAll of a sandbox whose mount this process does not
// track (a previous sandboxd left it) used to os.RemoveAll the folder, which
// walks into the live mount and deletes the storage's files. Now the mount
// is unmounted first, and a mount that will not go keeps the folder, with
// everything in it.
func TestUnmountAllNeverRemovesThroughALiveMount(t *testing.T) {
	m := newTestManager(t, nil)
	var logs bytes.Buffer
	m.logger = slog.New(slog.NewTextHandler(&logs, nil))
	hostPath := m.hostPath("sb-live", 0)
	if err := os.MkdirAll(hostPath, 0o700); err != nil {
		t.Fatal(err)
	}
	// What the storage holds, as seen through the mount.
	kept := filepath.Join(hostPath, "the-users-data.txt")
	if err := os.WriteFile(kept, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	rewrite := fakeMountTable(t, hostPath)

	stubUmount(t, func(string) bool { return false })
	err := m.UnmountAll("sb-live")
	if !errors.Is(err, errStillMounted) || !strings.Contains(err.Error(), hostPath) {
		t.Fatalf("UnmountAll = %v, want errStillMounted naming %s", err, hostPath)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("a file under a live mount was deleted: %v", err)
	}
	if !strings.Contains(logs.String(), "not removing a mount folder") {
		t.Fatalf("not logged: %s", logs.String())
	}

	// Once the unmount works, the folder goes. (The file is still in the
	// stand-in folder because nothing was really mounted over it; it goes
	// with the folder, which is on the folder's own device.)
	calls := stubUmount(t, func(p string) bool { rewrite(); return true })
	if err := m.UnmountAll("sb-live"); err != nil {
		t.Fatalf("UnmountAll = %v", err)
	}
	if !slices.Equal(*calls, []string{hostPath}) {
		t.Fatalf("unmounted %v, want %s", *calls, hostPath)
	}
	if _, err := os.Stat(filepath.Join(m.rootDir, "sb-live")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mount folder left: %v", err)
	}
}

// Sweep clears an orphan's folder the same way.
func TestSweepKeepsALiveMount(t *testing.T) {
	m := newTestManager(t, nil)
	hostPath := m.hostPath("sb-orphan", 0)
	if err := os.MkdirAll(hostPath, 0o700); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(hostPath, "keep")
	if err := os.WriteFile(kept, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fakeMountTable(t, hostPath)
	stubUmount(t, func(string) bool { return false })
	m.Sweep(map[string]struct{}{})
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("Sweep deleted through a live mount: %v", err)
	}
	if _, swept := m.sweeping["sb-orphan"]; swept {
		t.Fatal("the sweep claim was not released")
	}
}

// A mount set that fails part way rolls back what it made, and its folder
// goes the same way: a mount whose unmount fails keeps the folder, and the
// storage's files under it.
func TestFailedMountSetRollbackKeepsALiveMount(t *testing.T) {
	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeNFS: fakeAdapter{},
		models.MountTypeS3:  fakeAdapter{buildErr: errors.New("bad spec")},
	})
	// The first mount (a kernel mount, which here runs `true`) is made and
	// stays in place: its unmount fails. The storage's file is put under it
	// by hand. The second fails to build, so the set rolls back.
	hostPath := m.hostPath("sb-half", 0)
	if err := os.MkdirAll(hostPath, 0o700); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(hostPath, "keep")
	if err := os.WriteFile(kept, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fakeMountTable(t, hostPath)
	stubUmount(t, func(string) bool { return false })
	prevU, prevL := runUmount, runLazyUmount
	runUmount = func(string) error { return errors.New("umount: target is busy") }
	runLazyUmount = runUmount
	t.Cleanup(func() { runUmount, runLazyUmount = prevU, prevL })

	if _, err := m.MountAll(t.Context(), "sb-half", []models.MountSpec{
		{Type: models.MountTypeNFS, Target: "/a"},
		{Type: models.MountTypeS3, Target: "/b"},
	}); err == nil {
		t.Fatal("MountAll succeeded with a spec that cannot build")
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("the rollback deleted through a live mount: %v", err)
	}
}

// mountPointsUnder finds a mount in the table (a bind on the same device is
// only there), or by its device where there is no table; never walks into
// one; and lists the deepest first.
func TestMountPointsUnder(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sb")
	spaced := filepath.Join(dir, "a b")
	deep := filepath.Join(dir, "1", "2")
	byDev := filepath.Join(dir, "3")
	inside := filepath.Join(byDev, "inside")
	for _, p := range []string{spaced, deep, inside} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fakeMountTable(t, spaced, filepath.Join(dir, "1"), deep, "/elsewhere", dir+"-other/0")
	prev := pathDevOf
	pathDevOf = func(p string) uint64 {
		switch p {
		case byDev:
			return 7
		case inside:
			t.Errorf("walked into the mount at %s", byDev)
		}
		return prev(p)
	}
	t.Cleanup(func() { pathDevOf = prev })

	got := mountPointsUnder(dir)
	want := []string{deep, filepath.Join(dir, "1"), byDev, spaced}
	if !slices.Equal(got, want) {
		t.Fatalf("mountPointsUnder = %v, want %v", got, want)
	}

	// The table names resolved paths; dir may be spelled through a symlink.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(spaced)
	if err != nil {
		t.Fatal(err)
	}
	fakeMountTable(t, resolved)
	if got := mountTablePointsUnder(link); !slices.Equal(got, []string{filepath.Join(link, "a b")}) {
		t.Fatalf("through a symlink: %v", got)
	}

	// No table: only the device test.
	mountInfoPath = filepath.Join(t.TempDir(), "absent")
	if got := mountPointsUnder(dir); !slices.Equal(got, []string{byDev}) {
		t.Fatalf("without a table: %v", got)
	}
}

// removeOnDevice deletes the folder's own files, removes a symlink without
// following it, and refuses to walk into another device.
func TestRemoveOnDevice(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "not-ours")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "sb")
	if err := os.MkdirAll(filepath.Join(dir, "0", "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0", "sub", "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := removeOnDevice(dir); err != nil {
		t.Fatalf("removeOnDevice = %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("folder left: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("followed a symlink out: %v", err)
	}

	mount := filepath.Join(dir, "0")
	if err := os.MkdirAll(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(mount, "keep")
	if err := os.WriteFile(kept, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	prev := pathDevOf
	pathDevOf = func(p string) uint64 {
		if p == mount {
			return 9
		}
		return prev(p)
	}
	t.Cleanup(func() { pathDevOf = prev })
	if err := removeOnDevice(dir); !errors.Is(err, errStillMounted) {
		t.Fatalf("removeOnDevice = %v, want errStillMounted", err)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("walked into another device: %v", err)
	}

	if err := removeOnDevice(filepath.Join(outside, "absent")); err != nil {
		t.Fatalf("absent = %v", err)
	}
	if err := removeOnDevice(target); err != nil {
		t.Fatalf("a file = %v", err)
	}
}

func TestUnescapeMountInfo(t *testing.T) {
	for in, want := range map[string]string{
		`/plain`:            "/plain",
		`/a\040b`:           "/a b",
		`/tab\011x\134y`:    "/tab\tx\\y",
		`/bad\9zz`:          `/bad\9zz`,
		`/short\04`:         `/short\04`,
		`/mnt/sb\040x/0\04`: `/mnt/sb x/0\04`,
	} {
		if got := unescapeMountInfo(in); got != want {
			t.Errorf("unescapeMountInfo(%q) = %q, want %q", in, got, want)
		}
	}
}

// UnmountAll never removes outside the root for an id mountSet would
// refuse, and a sandbox with no folder costs nothing.
func TestUnmountAllBadIDAndNoFolder(t *testing.T) {
	m := newTestManager(t, nil)
	outside := filepath.Join(filepath.Dir(m.rootDir), "victim")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := m.UnmountAll("../victim"); err != nil {
		t.Fatalf("UnmountAll(bad id) = %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("removed outside the root: %v", err)
	}
	mountInfoPath = filepath.Join(t.TempDir(), "must-not-be-read")
	t.Cleanup(func() { mountInfoPath = "/proc/self/mountinfo" })
	if err := m.UnmountAll("sb-none"); err != nil {
		t.Fatalf("UnmountAll(no folder) = %v", err)
	}
}

// TestMountFolder: the folder of a valid id is the cleaned rootDir/<id>,
// and an id that could leave rootDir, or that mountSet would refuse, has
// none, so UnmountAll and the rollback never build a path from it.
func TestMountFolder(t *testing.T) {
	root := t.TempDir()
	m := &Manager{rootDir: root + string(filepath.Separator) + "." + string(filepath.Separator)}
	cases := []struct {
		id     string
		want   string
		wantOK bool
	}{
		{"sb-1234abcd", filepath.Join(root, "sb-1234abcd"), true},
		{"caller_chosen-ID", filepath.Join(root, "caller_chosen-ID"), true},
		{"", "", false},
		{".", "", false},
		{"..", "", false},
		{"../escape", "", false},
		{"a/b", "", false},
		{"/etc", "", false},
		{"sb 1", "", false},
		{strings.Repeat("a", 129), "", false},
	}
	for _, c := range cases {
		got, ok := m.mountFolder(c.id)
		if got != c.want || ok != c.wantOK {
			t.Errorf("mountFolder(%q) = %q, %v; want %q, %v", c.id, got, ok, c.want, c.wantOK)
		}
	}
}

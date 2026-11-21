package wasm

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func grantFile(t *testing.T, scope, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	GrantHostPath(scope, path, f)
}

func TestHostGrants(t *testing.T) {
	t.Cleanup(func() {
		for _, s := range []string{"", "sb-1", "sb-2"} {
			ReleaseHostGrants(s)
		}
	})
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(filepath.Join(work, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(dir, "m.wasm")
	if err := os.WriteFile(module, []byte("module"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "sub", "f"), []byte("in work"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Nothing granted: paths are used as they are.
	var seen string
	if err := WithHostPath(work, func(p string) error { seen = p; return nil }); err != nil || seen != work {
		t.Fatalf("ungranted = %q, %v", seen, err)
	}
	if err := WithHostPath("", func(p string) error { seen = p; return nil }); err != nil || seen != "" {
		t.Fatalf("empty = %q, %v", seen, err)
	}
	if b, err := ReadHostFile(module); err != nil || string(b) != "module" {
		t.Fatalf("ungranted read = %q, %v", b, err)
	}
	GrantHostPath("sb-1", work, nil) // nil: nothing to hold
	GrantHostPath("sb-1", "", mustOpen(t, work))

	grantFile(t, "sb-1", work)
	grantFile(t, "sb-2", work) // the same path held by two sandboxes
	grantFile(t, "", module)
	if runtime.GOOS != "linux" {
		// Off Linux a grant is closed at once and paths are used as they are.
		if grantedHostPaths() != 0 {
			t.Fatalf("%d grants held off linux", grantedHostPaths())
		}
		return
	}
	if grantedHostPaths() != 2 {
		t.Fatalf("grants = %d, want 2", grantedHostPaths())
	}
	// A path beneath a granted directory goes through its descriptor.
	target := filepath.Join(work, "sub", "f")
	if err := WithHostPath(target, func(p string) error {
		seen = p
		b, err := os.ReadFile(p)
		if err == nil && string(b) != "in work" {
			t.Fatalf("read %q", b)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(seen, "/proc/self/fd/") || !strings.HasSuffix(seen, "/sub/f") {
		t.Fatalf("resolved = %q", seen)
	}
	// A granted file is read through its descriptor: no reopen, so not even
	// its name is needed any more.
	if err := os.Remove(module); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadHostFile(module); err != nil || string(b) != "module" {
		t.Fatalf("granted read after unlink = %q, %v", b, err)
	}
	// A newer grant replaces the handle: a /work removed and made again is
	// reached through the new one.
	if err := os.RemoveAll(work); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "new"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	grantFile(t, "sb-1", work)
	if b, err := ReadHostFile(filepath.Join(work, "new")); err != nil || string(b) != "new" {
		t.Fatalf("after re-grant = %q, %v", b, err)
	}
	// Released by one holder, kept for the other; then gone.
	ReleaseHostGrants("sb-1")
	if grantedHostPaths() != 2 {
		t.Fatalf("grants after one release = %d", grantedHostPaths())
	}
	ReleaseHostGrants("sb-2")
	ReleaseHostGrants("")
	if grantedHostPaths() != 0 {
		t.Fatalf("grants after all releases = %d", grantedHostPaths())
	}
	if _, err := ReadHostFile(module); err == nil {
		t.Fatal("released module still read")
	}
}

func mustOpen(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// A directory only root may search is still reached through a grant: what
// a worker that dropped its privileges relies on. Only meaningful when the
// test is not root (root searches anything).
func TestHostGrantSkipsParentPermissions(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		t.Skip("needs a non-root user on linux")
	}
	t.Cleanup(func() { ReleaseHostGrants("sb-p") })
	private := filepath.Join(t.TempDir(), "private")
	work := filepath.Join(private, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(private, "snap")
	if err := os.WriteFile(snap, []byte("snap"), 0o600); err != nil {
		t.Fatal(err)
	}
	grantFile(t, "sb-p", work)
	grantFile(t, "sb-p", snap)
	if err := os.Chmod(private, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(private, 0o700) })
	if _, err := os.Stat(work); err == nil {
		t.Fatal("parent permissions not in effect")
	}
	if err := WithHostPath(filepath.Join(work, "f"), func(p string) error {
		return os.WriteFile(p, []byte("x"), 0o600)
	}); err != nil {
		t.Fatalf("write under a granted dir: %v", err)
	}
	if b, err := ReadHostFile(snap); err != nil || string(b) != "snap" {
		t.Fatalf("granted file = %q, %v", b, err)
	}
}

func TestSetCompileCacheDir(t *testing.T) {
	t.Cleanup(func() { compileCacheDir.Store(nil) })
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", "/from/env")
	compileCacheDir.Store(nil)
	if got := wazeroCompileCacheDir(); got != "/from/env" {
		t.Fatalf("env cache = %q", got)
	}
	SetCompileCacheDir(" /owner ")
	if got := wazeroCompileCacheDir(); got != "/owner" {
		t.Fatalf("set cache = %q", got)
	}
	SetCompileCacheDir("")
	if got := wazeroCompileCacheDir(); got != "/from/env" {
		t.Fatalf("cleared cache = %q", got)
	}
}

func TestSnapshotFilesAndGrantedRestore(t *testing.T) {
	dir := t.TempDir()
	files := SnapshotFiles(dir)
	if len(files) != 4 || filepath.Dir(files[0]) != dir {
		t.Fatalf("SnapshotFiles = %v", files)
	}
	snap := filepath.Join(dir, "mem.snap")
	if err := WriteSnapshotDir(snap, SnapshotCapture{Memory: []byte("memory")}); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "linux" {
		return
	}
	t.Cleanup(func() { ReleaseHostGrants("sb-s") })
	for _, f := range SnapshotFiles(snap) {
		grantFile(t, "sb-s", f)
	}
	// Read through the four descriptors once the folder is gone.
	if err := os.RemoveAll(snap); err != nil {
		t.Fatal(err)
	}
	in, err := ReadSnapshotDir(snap, EngineNameWazero())
	if err != nil || string(in.Memory) != "memory" {
		t.Fatalf("granted restore = %q, %v", in.Memory, err)
	}
}

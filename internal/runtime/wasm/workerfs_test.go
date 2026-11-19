package wasm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// selfWorker is a worker uid/gid the test may chown to: its own, or
// nobody's when the test runs as root (root is never a worker uid).
func selfWorker() worker.Confinement {
	if os.Geteuid() == 0 {
		return worker.Confinement{UID: 65534, GID: 65534}
	}
	return worker.Confinement{UID: os.Getuid(), GID: os.Getgid()}
}

func ownerOf(t *testing.T, path string) int {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return int(st.Sys().(*syscall.Stat_t).Uid)
}

func TestEnsureWorkDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run", "sb")
	// Workers that do not drop: the dir is made and nothing else.
	d := New(Config{}, nil)
	if err := d.ensureWorkDir(dir); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("work dir = %v, %v", st, err)
	}
	// Workers that drop: a dir that is already theirs is not walked.
	d = New(Config{Worker: selfWorker()}, nil)
	if err := d.ensureWorkDir(dir); err != nil {
		t.Fatal(err)
	}
	if !d.workerOwns() {
		t.Fatal("worker confinement not seen")
	}
	// A path that cannot be a dir.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.ensureWorkDir(filepath.Join(file, "sb")); err == nil {
		t.Fatal("work dir under a file made")
	}
}

// The tree walk hands over dirs and singly-named regular files, and never
// follows or touches a symlink, a FIFO or a file with a second name.
func TestChownTree(t *testing.T) {
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, []byte("host"), 0o600); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	mk := func(rel string) string {
		p := filepath.Join(work, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	plain := mk("a/b/plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, mk("a/escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, mk("a/dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(mk("fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, mk("hard")); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	want := uid
	if os.Geteuid() == 0 {
		uid, gid, want = 65534, 65534, 65534
	}
	if err := chownTree(work, uid, gid); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{work, filepath.Join(work, "a"), filepath.Join(work, "a", "b"), plain} {
		if got := ownerOf(t, p); got != want {
			t.Fatalf("%s owner = %d, want %d", p, got, want)
		}
	}
	if os.Geteuid() == 0 {
		// Nothing outside the tree changed, through a link of either kind.
		if ownerOf(t, victim) != 0 || ownerOf(t, outside) != 0 {
			t.Fatal("chownTree reached outside the tree")
		}
		if ownerOf(t, filepath.Join(work, "fifo")) != 0 || ownerOf(t, filepath.Join(work, "a", "escape")) != 0 {
			t.Fatal("chownTree changed a FIFO or a symlink")
		}
	}
	if err := chownTree(filepath.Join(work, "missing"), uid, gid); err == nil {
		t.Fatal("missing tree walked")
	}
}

// As root, a /work made before workers dropped is handed over whole.
func TestEnsureWorkDirHandsOverAnOldWorkDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to own a file as another uid")
	}
	dir := filepath.Join(t.TempDir(), "sb")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d := New(Config{Worker: worker.Confinement{UID: 65534, GID: 65534}}, nil)
	if err := d.ensureWorkDir(dir); err != nil {
		t.Fatal(err)
	}
	if ownerOf(t, filepath.Join(dir, "sub", "f")) != 65534 || ownerOf(t, dir) != 65534 {
		t.Fatal("old work dir not handed to the worker uid")
	}
}

func TestStageAndPromoteCheckpoint(t *testing.T) {
	modules := t.TempDir()
	final := filepath.Join(modules, "sb", "mem.snap")
	for _, d := range []*Driver{New(Config{}, nil), New(Config{Worker: selfWorker()}, nil)} {
		staged, err := d.stageCheckpoint(final)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(filepath.Dir(staged)) != checkpointStageName {
			t.Fatalf("staged = %q", staged)
		}
		if err := fakeSnapshotWrite(staged); err != nil {
			t.Fatal(err)
		}
		if err := d.promoteCheckpoint(staged, final); err != nil {
			t.Fatalf("promote: %v", err)
		}
		if _, err := os.Stat(filepath.Join(final, "config.json")); err != nil {
			t.Fatalf("published snapshot: %v", err)
		}
		if _, err := os.Stat(filepath.Dir(staged)); !os.IsNotExist(err) {
			t.Fatalf("staging left behind: %v", err)
		}
	}
	// What the worker leaves is checked before anything is published.
	d := New(Config{Worker: selfWorker()}, nil)
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("host"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, plant := range map[string]func(staged string) error{
		"nothing written": func(string) error { return nil },
		"staged symlink":  func(s string) error { return os.Symlink(t.TempDir(), s) },
		"symlinked file": func(s string) error {
			return mkdirThen(s, func() error { return os.Symlink(outside, filepath.Join(s, "memory.bin.zst")) })
		},
		"hard-linked file": func(s string) error {
			return mkdirThen(s, func() error { return os.Link(outside, filepath.Join(s, "memory.bin.zst")) })
		},
		"nested folder": func(s string) error { return os.MkdirAll(filepath.Join(s, "deeper"), 0o700) },
	} {
		staged, err := d.stageCheckpoint(final)
		if err != nil {
			t.Fatal(err)
		}
		if err := plant(staged); err != nil {
			t.Fatal(err)
		}
		if err := d.promoteCheckpoint(staged, final); err == nil {
			t.Fatalf("%s: published", name)
		}
		if _, err := os.Stat(filepath.Join(final, "config.json")); err != nil {
			t.Fatalf("%s: the last good snapshot was lost: %v", name, err)
		}
	}
	// The staging folder cannot be made under a file.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.stageCheckpoint(filepath.Join(blocker, "sb", "mem.snap")); err == nil {
		t.Fatal("staging made under a file")
	}
}

func mkdirThen(dir string, fn func() error) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return fn()
}

func TestCompileCacheFor(t *testing.T) {
	if got := New(Config{}, nil).compileCacheFor("acme"); got != "" {
		t.Fatalf("cache without a root = %q", got)
	}
	root := t.TempDir()
	d := New(Config{CompileCacheDir: root, Worker: selfWorker()}, nil)
	operator, acme, other := d.compileCacheFor(""), d.compileCacheFor("acme"), d.compileCacheFor("other")
	if filepath.Base(operator) != "operator" || acme == other || acme == operator {
		t.Fatalf("caches = %q %q %q: want one per owner", operator, acme, other)
	}
	if filepath.Dir(acme) != filepath.Join(root, "owners") || filepath.Base(acme) != "owner-"+shortHash("acme") {
		t.Fatalf("owner cache = %q", acme)
	}
	if st, err := os.Stat(acme); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("owner cache = %v, %v", st, err)
	}
	if got := worker.CompileCacheOf(d.withCompileCache(context.Background(), "acme")); got != acme {
		t.Fatalf("ctx cache = %q", got)
	}
	// A root that cannot hold folders: no cache, compile without one.
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := New(Config{CompileCacheDir: file}, nil).compileCacheFor("acme"); got != "" {
		t.Fatalf("cache under a file = %q", got)
	}
}

// A resident bucket's hosts use the cache of the owner the bucket serves,
// read off its id, so an adopted bucket gets the same one.
func TestResidentCacheName(t *testing.T) {
	for id, want := range map[string]string{
		residentBucketID("acme", "digest", 64): "owner-" + shortHash("acme"),
		residentBucketID("", "digest", 64):     "operator",
		"not-a-bucket":                         "operator",
	} {
		if got := residentCacheName(id); got != want {
			t.Fatalf("residentCacheName(%q) = %q, want %q", id, got, want)
		}
	}
	d := New(Config{CompileCacheDir: t.TempDir()}, nil)
	if d.compileCacheNamed(residentCacheName(residentBucketID("acme", "d", 64))) != d.compileCacheFor("acme") {
		t.Fatal("a bucket and its owner's own workers use different caches")
	}
}

// ctxSupervisor records the compile cache each worker is started with,
// and whether it stays root.
type ctxSupervisor struct {
	fakeSupervisor
	caches []string
	roots  []bool
}

func (s *ctxSupervisor) Ensure(ctx context.Context, id, sock string) error {
	s.caches = append(s.caches, worker.CompileCacheOf(ctx))
	s.roots = append(s.roots, worker.KeepsRoot(ctx))
	return s.fakeSupervisor.Ensure(ctx, id, sock)
}

// A sandbox's own worker compiles into its owner's cache.
func TestCreateStartsWorkerWithOwnerCache(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	sup := &ctxSupervisor{}
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir, CompileCacheDir: filepath.Join(dir, "cache")}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(sup)
	client := &recordingWorkerClient{}
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })
	ctx := wasmmod.WithCatalogueOwner(context.Background(), "acme")
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-cache", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if len(sup.caches) != 1 || sup.caches[0] != d.compileCacheFor("acme") {
		t.Fatalf("worker caches = %v", sup.caches)
	}
	// A checkpoint goes through the staging folder to mem.snap.
	out, _, err := d.CheckpointLiveSandbox(ctx, &models.Sandbox{ID: "sb-cache"})
	if err != nil {
		t.Fatal(err)
	}
	if out != d.checkpointDir("sb-cache") {
		t.Fatalf("checkpoint at %q", out)
	}
	if _, err := os.Stat(filepath.Join(out, "config.json")); err != nil {
		t.Fatalf("published checkpoint: %v", err)
	}
	// A worker that writes no snapshot fails the checkpoint.
	client.checkpointErr = errors.New("worker failed")
	if _, _, err := d.CheckpointLiveSandbox(ctx, &models.Sandbox{ID: "sb-cache"}); err == nil {
		t.Fatal("failed checkpoint reported done")
	}
}

// R1: a worker that left its staged checkpoint open to everyone (0777 /
// 0666) gets it back as root's 0700 / 0600, so the handle it kept cannot
// swap a file for a link after the publish.
func TestPromoteCheckpointResetsModes(t *testing.T) {
	for _, d := range []*Driver{New(Config{}, nil), New(Config{Worker: selfWorker()}, nil)} {
		final := filepath.Join(t.TempDir(), "sb", "mem.snap")
		staged, err := d.stageCheckpoint(final)
		if err != nil {
			t.Fatal(err)
		}
		if err := fakeSnapshotWrite(staged); err != nil {
			t.Fatal(err)
		}
		for path, mode := range map[string]os.FileMode{filepath.Dir(staged): 0o777, staged: 0o777, filepath.Join(staged, "config.json"): 0o666} {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
		}
		if err := d.promoteCheckpoint(staged, final); err != nil {
			t.Fatal(err)
		}
		for path, want := range map[string]os.FileMode{final: 0o700, filepath.Join(final, "config.json"): 0o600} {
			st, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != want {
				t.Fatalf("%s mode = %v, want %v", path, st.Mode().Perm(), want)
			}
			if got := ownerOf(t, path); got != os.Geteuid() {
				t.Fatalf("%s owner = %d, want sandboxd's %d", path, got, os.Geteuid())
			}
		}
	}
}

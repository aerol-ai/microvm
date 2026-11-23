//go:build unix

package wasm

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// splitCheckpointDriver is a split driver with a modules folder of its own
// and the test's own uid as the worker's: the files the test writes as
// "the worker" are then the worker's.
func splitCheckpointDriver(t *testing.T) *Driver {
	t.Helper()
	d := New(Config{ModulesDir: t.TempDir(), HelperSockets: helperSockets,
		Worker: worker.Confinement{UID: os.Getuid(), GID: shareGID()}}, nil)
	return d
}

// writeWorkerSnapshot writes a real snapshot at staged, as a worker would.
func writeWorkerSnapshot(t *testing.T, staged string, memory []byte) {
	t.Helper()
	if err := wasmengine.WriteSnapshotDir(staged, wasmengine.SnapshotCapture{
		Config: wasmengine.SnapshotConfig{CloneGeneration: "gen-1"}, Memory: memory}); err != nil {
		t.Fatal(err)
	}
}

// TestSplitCheckpointCopiesOut: in privilege mode split the worker writes
// its checkpoint in a staging folder it shares with sandboxd's group, and
// sandboxd publishes a copy of its own: its folder 0700, its files 0600,
// the worker's copy gone.
func TestSplitCheckpointCopiesOut(t *testing.T) {
	d := splitCheckpointDriver(t)
	final := d.checkpointDir("sb-1")
	staged, err := d.stageCheckpoint(final)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Dir(staged))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSetgid == 0 || st.Mode().Perm() != 0o770 || int(st.Sys().(*syscall.Stat_t).Gid) != shareGID() {
		t.Fatalf("staging folder %v gid %d: want the worker's group, 2770", st.Mode(), st.Sys().(*syscall.Stat_t).Gid)
	}
	memory := bytes.Repeat([]byte("checkpointed guest memory "), 4096)
	writeWorkerSnapshot(t, staged, memory)
	// What the worker wrote is open to its group, as a worker sharing
	// with its group leaves it (pkg/wasm WriteSnapshotDir).
	if err := os.Chmod(staged, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := d.promoteCheckpoint(staged, final); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if got := modeOf(t, final); got != 0o700 {
		t.Fatalf("published folder mode %o", got)
	}
	for _, f := range wasmengine.SnapshotFiles(final) {
		if got := modeOf(t, f); got != 0o600 {
			t.Fatalf("%s mode %o", filepath.Base(f), got)
		}
		if ownerOf(t, f) != os.Geteuid() {
			t.Fatalf("%s is not sandboxd's", filepath.Base(f))
		}
	}
	snap, err := wasmengine.ReadSnapshotDir(final, "")
	if err != nil || !bytes.Equal(snap.Memory, memory) || snap.Config.CloneGeneration != "gen-1" {
		t.Fatalf("published snapshot: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(staged)); !os.IsNotExist(err) {
		t.Fatalf("staging left behind: %v", err)
	}
	assertNoCopiesLeft(t, filepath.Dir(final))
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func assertNoCopiesLeft(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".mem.snap-") {
			t.Fatalf("left %s", e.Name())
		}
	}
}

// TestSplitCheckpointRefusesWhatTheWorkerLeft: what a worker staged is
// checked through the open file before a byte of it is published, and a
// worker that broke out of its engine cannot make sandboxd copy anything
// but its own snapshot's files: no link, no file with another name, no
// FIFO to hang on, no name sandboxd does not know, nothing too large. The
// last good snapshot stays.
func TestSplitCheckpointRefusesWhatTheWorkerLeft(t *testing.T) {
	d := splitCheckpointDriver(t)
	final := d.checkpointDir("sb-1")
	good, err := d.stageCheckpoint(final)
	if err != nil {
		t.Fatal(err)
	}
	writeWorkerSnapshot(t, good, []byte("the last good memory"))
	if err := d.promoteCheckpoint(good, final); err != nil {
		t.Fatal(err)
	}
	secretDir := t.TempDir()
	secret := filepath.Join(secretDir, "secret")
	if err := os.WriteFile(secret, []byte("sandboxd's own secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSecretSnapshot := func(dir string) error {
		return wasmengine.WriteSnapshotDir(dir, wasmengine.SnapshotCapture{Memory: []byte("elsewhere")})
	}
	for name, tc := range map[string]struct {
		plant func(staged string) error
		want  error
	}{
		"nothing written": {func(string) error { return nil }, errStagedSnapshot},
		"mem.snap a link to another folder": {func(s string) error {
			other := filepath.Join(secretDir, "other.snap")
			if err := writeSecretSnapshot(other); err != nil {
				return err
			}
			return os.Symlink(other, s)
		}, errStagedSnapshot},
		"mem.snap a file": {func(s string) error { return os.WriteFile(s, []byte("x"), 0o600) }, errStagedSnapshot},
		"a file a link": {func(s string) error {
			return snapshotThen(s, func(cfg string) error {
				if err := os.Remove(cfg); err != nil {
					return err
				}
				return os.Symlink(secret, cfg)
			})
		}, errStagedSnapshot},
		"a file with two names": {func(s string) error {
			return snapshotThen(s, func(cfg string) error {
				if err := os.Remove(cfg); err != nil {
					return err
				}
				return os.Link(secret, cfg)
			})
		}, errStagedSnapshot},
		"a FIFO": {func(s string) error {
			return snapshotThen(s, func(cfg string) error {
				mem := filepath.Join(filepath.Dir(cfg), "memory.zstd")
				if err := os.Remove(mem); err != nil {
					return err
				}
				return syscall.Mkfifo(mem, 0o660)
			})
		}, errStagedSnapshot},
		"a name sandboxd does not know": {func(s string) error {
			return snapshotThen(s, func(cfg string) error {
				return os.WriteFile(filepath.Join(filepath.Dir(cfg), "extra"), []byte("x"), 0o600)
			})
		}, errStagedSnapshot},
		"a folder inside": {func(s string) error {
			return snapshotThen(s, func(cfg string) error { return os.Mkdir(filepath.Join(filepath.Dir(cfg), "deeper"), 0o700) })
		}, errStagedSnapshot},
		"a file too large": {func(s string) error {
			return snapshotThen(s, func(cfg string) error {
				// Sparse: no disk is used.
				return os.Truncate(filepath.Join(filepath.Dir(cfg), "memory.zstd"), wasmengine.MaxSnapshotFileBytes+1)
			})
		}, errCheckpointTooLarge},
		"no config": {func(s string) error {
			return snapshotThen(s, func(cfg string) error { return os.Remove(cfg) })
		}, errStagedSnapshot},
	} {
		staged, err := d.stageCheckpoint(final)
		if err != nil {
			t.Fatal(err)
		}
		if err := tc.plant(staged); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := d.promoteCheckpoint(staged, final); !errors.Is(err, tc.want) {
			t.Fatalf("%s: promote = %v, want %v", name, err, tc.want)
		}
		snap, err := wasmengine.ReadSnapshotDir(final, "")
		if err != nil || string(snap.Memory) != "the last good memory" {
			t.Fatalf("%s: the last good snapshot was lost: %v", name, err)
		}
		if _, err := os.Stat(filepath.Dir(staged)); !os.IsNotExist(err) {
			t.Fatalf("%s: staging left behind: %v", name, err)
		}
		assertNoCopiesLeft(t, filepath.Dir(final))
	}
	if raw, err := os.ReadFile(secret); err != nil || string(raw) != "sandboxd's own secret" {
		t.Fatalf("the file outside changed: %q %v", raw, err)
	}
	// A checkpoint path outside the modules folder is never read or
	// written.
	outside := filepath.Join(t.TempDir(), "sb-1")
	writeWorkerSnapshot(t, filepath.Join(outside, checkpointStageName, "mem.snap"), []byte("elsewhere"))
	for _, tc := range [][2]string{
		{filepath.Join(outside, checkpointStageName, "mem.snap"), final},
		{good, filepath.Join(outside, "mem.snap")},
		{filepath.Join(d.cfg.ModulesDir, "..", "x", "mem.snap"), final},
	} {
		if err := d.copyOutCheckpoint(tc[0], tc[1]); !errors.Is(err, errStagedSnapshot) {
			t.Fatalf("%v: %v", tc, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "mem.snap")); !os.IsNotExist(err) {
		t.Fatalf("published outside the modules folder: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, checkpointStageName)); err != nil {
		t.Fatalf("removed a folder outside the modules folder: %v", err)
	}
}

// snapshotThen writes a real snapshot at dir and changes its config with fn.
func snapshotThen(dir string, fn func(cfg string) error) error {
	if err := wasmengine.WriteSnapshotDir(dir, wasmengine.SnapshotCapture{Memory: []byte("guest")}); err != nil {
		return err
	}
	return fn(filepath.Join(dir, "config.json"))
}

// TestSplitCheckpointRefusesAnotherUsersFile: a staged file of a user
// that is neither the worker nor sandboxd is not copied (root only: only
// root can give a file away).
func TestSplitCheckpointRefusesAnotherUsersFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make a file of another user")
	}
	d := splitCheckpointDriver(t)
	d.cfg.Worker.UID = 61000
	final := d.checkpointDir("sb-1")
	for name, target := range map[string]func(staged string) string{
		"the folder": func(s string) string { return s },
		"a file":     func(s string) string { return filepath.Join(s, "memory.zstd") },
	} {
		staged, err := d.stageCheckpoint(final)
		if err != nil {
			t.Fatal(err)
		}
		writeWorkerSnapshot(t, staged, []byte("guest"))
		if err := os.Lchown(target(staged), 4321, 4321); err != nil {
			t.Fatal(err)
		}
		if err := d.promoteCheckpoint(staged, final); !errors.Is(err, errStagedSnapshot) {
			t.Fatalf("%s of another user: %v", name, err)
		}
	}
	// The worker's own files are taken.
	staged, err := d.stageCheckpoint(final)
	if err != nil {
		t.Fatal(err)
	}
	writeWorkerSnapshot(t, staged, []byte("guest"))
	if err := filepath.Walk(staged, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, 61000, 61000)
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.promoteCheckpoint(staged, final); err != nil {
		t.Fatalf("the worker's own checkpoint: %v", err)
	}
	if ownerOf(t, filepath.Join(final, "memory.zstd")) != 0 {
		t.Fatal("the published copy is not sandboxd's")
	}
}

// TestSplitCheckpointRoundTrip: a real worker checkpoints a sandbox in
// split mode, sandboxd copies it out, and a passivated sandbox comes back
// from the copy, through the descriptors sandboxd passes the worker.
func TestSplitCheckpointRoundTrip(t *testing.T) {
	dir := t.TempDir()
	// macOS sun_path is capped at 104 bytes: sockets under /tmp.
	sockets, err := os.MkdirTemp("", "aws")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockets) })
	runDir := filepath.Join(dir, "run")
	modulesDir := filepath.Join(dir, "modules")
	for _, p := range []string{runDir, modulesDir} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	modPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "demo.wasm")
	sup := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range sup.workers {
			_ = sup.Stop(id)
		}
	})
	d := New(Config{RunDir: runDir, ModulesDir: modulesDir, DefaultMemoryMB: 64, HelperSockets: sockets,
		Worker: worker.Confinement{UID: os.Getuid(), GID: shareGID()}}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc123"})
	d.SetWorkerSupervisor(sup)
	ctx := context.Background()
	req := models.CreateSandboxRequest{Image: "demo.wasm", Durability: models.DurabilityDurable, MemoryMB: 64}
	if _, err := d.Create(ctx, req, "s1", "", nil); err != nil {
		t.Fatalf("a durable create in split: %v", err)
	}
	sb := &models.Sandbox{ID: "s1", Durability: models.DurabilityDurable, ModuleRef: "demo.wasm", ModuleDigest: "abc123", MemoryMB: 64}
	if _, _, err := d.CheckpointLiveSandbox(ctx, sb); err != nil {
		t.Fatalf("live checkpoint: %v", err)
	}
	path, gen, err := d.CheckpointSandbox(ctx, sb)
	if err != nil {
		t.Fatalf("passivate: %v", err)
	}
	if modeOf(t, path) != 0o700 || modeOf(t, filepath.Join(path, "memory.zstd")) != 0o600 {
		t.Fatal("the published checkpoint is not sandboxd's alone")
	}
	sb.Status, sb.CheckpointPath, sb.CloneGeneration = models.SandboxStatusPassivated, path, gen
	state, err := d.RehydrateSandbox(ctx, sb, nil)
	if err != nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("wake: %v", err)
	}
	// A stale generation is still fenced.
	if _, err := d.RehydrateSandbox(ctx, &models.Sandbox{ID: "s2", ModuleRef: "demo.wasm", ModuleDigest: "abc123",
		CheckpointPath: path, CloneGeneration: "a-newer-generation"}, nil); !errors.Is(err, models.ErrSnapshotFenced) {
		t.Fatalf("a stale checkpoint: %v", err)
	}
}

// TestSplitCheckpointOfABadID: a sandbox id with a path in it names no
// instance, so nothing is staged or written outside the modules folder.
func TestSplitCheckpointOfABadID(t *testing.T) {
	d := splitCheckpointDriver(t)
	if _, _, err := d.CheckpointSandbox(context.Background(), &models.Sandbox{ID: "../escape"}); err == nil {
		t.Fatal("checkpointed a sandbox id with a path in it")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(d.cfg.ModulesDir), "escape")); !os.IsNotExist(err) {
		t.Fatalf("wrote outside the modules folder: %v", err)
	}
}

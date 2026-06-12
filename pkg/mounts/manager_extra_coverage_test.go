package mounts

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

type failingKernelAdapter struct{}

func (failingKernelAdapter) Build(sandboxID string, index int, spec models.MountSpec, hostTarget, credDir string) (adapters.Plan, error) {
	return adapters.Plan{
		Argv:          []string{"/bin/false"},
		IsKernelMount: true,
	}, nil
}

type fuseSleepAdapter struct {
	unlinkCred bool
}

func (fuseSleepAdapter) Build(sandboxID string, index int, spec models.MountSpec, hostTarget, credDir string) (adapters.Plan, error) {
	plan := adapters.Plan{
		Argv:          []string{"sleep", "30"},
		IsKernelMount: false,
	}
	if spec.Credentials["k"] != "" {
		plan.CredFile = filepath.Join(credDir, sandboxID+"-cred")
		plan.CredBody = []byte(spec.Credentials["k"])
		plan.UnlinkCred = true
	}
	return plan, nil
}

func TestMountOneKernelMountFailure(t *testing.T) {
	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeNFS: failingKernelAdapter{},
	})
	_, err := m.MountAll(context.Background(), "sb-kernel-fail", []models.MountSpec{
		{Type: models.MountTypeNFS, Source: "host:/x", Target: "/mnt"},
	})
	if err == nil {
		t.Fatal("expected kernel mount failure")
	}
}

func TestMountOneUnknownAdapter(t *testing.T) {
	m := newTestManager(t, map[models.MountType]adapters.Adapter{})
	_, err := m.MountAll(context.Background(), "sb-unknown", []models.MountSpec{
		{Type: models.MountType("bogus"), Source: "x", Target: "/mnt"},
	})
	if err == nil {
		t.Fatal("expected unknown adapter error")
	}
}

func TestSuperviseExitDoubleCrashDisables(t *testing.T) {
	root := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(logger, Config{RootDir: root, CredDir: t.TempDir(), WaitTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)

	hostPath := filepath.Join(root, "sb-double", "0")
	if err := os.MkdirAll(hostPath, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	state := &mountState{
		sandboxID: "sb-double",
		index:     0,
		hostPath:  hostPath,
		plan:      adapters.Plan{Argv: []string{"true"}},
		cmd:       cmd,
		lastCrash: time.Now().UTC().Add(-5 * time.Second),
		restarts:  1,
	}
	m.mu.Lock()
	m.state["sb-double"] = []*mountState{state}
	m.mu.Unlock()

	m.superviseExit(state)
	if !state.disabled {
		t.Fatal("expected mount disabled after second crash within 30s")
	}
}

func TestSuperviseExitRestartSpawnFailure(t *testing.T) {
	root := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(logger, Config{RootDir: root, CredDir: t.TempDir(), WaitTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)

	hostPath := filepath.Join(root, "sb-spawn-fail", "0")
	if err := os.MkdirAll(hostPath, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	state := &mountState{
		sandboxID: "sb-spawn-fail",
		index:     0,
		hostPath:  hostPath,
		plan:      adapters.Plan{Argv: []string{"/no/such/binary"}},
		cmd:       cmd,
	}
	m.mu.Lock()
	m.state["sb-spawn-fail"] = []*mountState{state}
	m.mu.Unlock()

	m.superviseExit(state)
	if !state.disabled {
		t.Fatal("expected disabled after restart spawn failure")
	}
}

func TestTearDownStateFUSEAndKernel(t *testing.T) {
	root := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(logger, Config{RootDir: root, CredDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	hostKernel := filepath.Join(root, "k", "0")
	hostFUSE := filepath.Join(root, "f", "0")
	os.MkdirAll(hostKernel, 0o700)
	os.MkdirAll(hostFUSE, 0o700)

	credPath := filepath.Join(t.TempDir(), "cred.json")
	os.WriteFile(credPath, []byte("x"), 0o600)

	cmd := exec.Command("sleep", "2")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start sleep:", err)
	}
	t.Cleanup(func() {
		_ = killMount(cmd)
	})

	_ = m.tearDownState(&mountState{
		hostPath: hostKernel,
		plan:     adapters.Plan{IsKernelMount: true, CredFile: credPath},
	})
	_ = m.tearDownState(&mountState{
		hostPath: hostFUSE,
		plan:     adapters.Plan{IsKernelMount: false},
		cmd:      cmd,
	})
}

func TestWriteCredFileWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cred.json")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := writeCredFile(path, []byte("data")); err == nil {
		t.Fatal("expected write error on read-only file opened for write")
	}
}

func TestUnmountPathAndSweepReadError(t *testing.T) {
	_ = unmountPath(t.TempDir())

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	root := t.TempDir()
	m, err := New(logger, Config{RootDir: root, CredDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	m.Sweep(map[string]struct{}{})
}

func TestMountAllMkdirSandboxDirFailure(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(logger, Config{RootDir: root, CredDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	m.adapters = map[models.MountType]adapters.Adapter{models.MountTypeS3: fakeAdapter{}}

	_, err = m.MountAll(context.Background(), "blocker", []models.MountSpec{
		{Type: models.MountTypeS3, Source: "s3://a", Target: "/a"},
	})
	if err == nil {
		t.Fatal("expected mkdir failure when sandbox id collides with file")
	}
}

func TestKillMountSIGKILLAfterTimeout(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start sleep:", err)
	}
	if err := killMount(cmd); err != nil {
		t.Fatalf("killMount: %v", err)
	}
}

func TestSuperviseExitRewritesCredOnRestart(t *testing.T) {
	root := t.TempDir()
	credDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(logger, Config{RootDir: root, CredDir: credDir, WaitTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)

	hostPath := filepath.Join(root, "sb-cred", "0")
	if err := os.MkdirAll(hostPath, 0o700); err != nil {
		t.Fatal(err)
	}
	credPath := filepath.Join(credDir, "cred.json")
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	state := &mountState{
		sandboxID: "sb-cred",
		index:     0,
		hostPath:  hostPath,
		plan: adapters.Plan{
			Argv:     []string{"/no/such/binary"},
			CredFile: credPath,
			CredBody: []byte("secret"),
		},
		cmd: cmd,
	}
	m.mu.Lock()
	m.state["sb-cred"] = []*mountState{state}
	m.mu.Unlock()

	m.superviseExit(state)
	if _, err := os.Stat(credPath); err != nil {
		t.Fatalf("cred file not rewritten on restart attempt: %v", err)
	}
}

func TestNewNilLoggerRejected(t *testing.T) {
	_, err := New(nil, Config{RootDir: t.TempDir(), CredDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for nil logger")
	}
}

func TestMountOneFUSESuccessUnlinksCred(t *testing.T) {
	oldProbe := waitForMountProbe
	waitForMountProbe = func(string, time.Duration) error { return nil }
	t.Cleanup(func() { waitForMountProbe = oldProbe })

	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeS3: fuseSleepAdapter{unlinkCred: true},
	})
	specs := []models.MountSpec{{
		Type: models.MountTypeS3, Source: "s3://b", Target: "/b",
		Credentials: map[string]string{"k": "secret"},
	}}
	binds, err := m.MountAll(context.Background(), "sb-fuse-ok", specs)
	if err != nil {
		t.Fatalf("MountAll: %v", err)
	}
	if len(binds) != 1 {
		t.Fatalf("binds = %d, want 1", len(binds))
	}
	m.mu.Lock()
	st := m.state["sb-fuse-ok"][0]
	m.mu.Unlock()
	if st.plan.CredFile != "" {
		if _, err := os.Stat(st.plan.CredFile); !os.IsNotExist(err) {
			t.Fatal("expected cred file unlinked after successful FUSE mount")
		}
	}
	if err := m.UnmountAll("sb-fuse-ok"); err != nil {
		t.Fatalf("UnmountAll: %v", err)
	}
}

func TestUnmountPathSuccess(t *testing.T) {
	oldUmount, oldLazy := runUmount, runLazyUmount
	runUmount = func(string) error { return nil }
	t.Cleanup(func() {
		runUmount = oldUmount
		runLazyUmount = oldLazy
	})
	if err := unmountPath(t.TempDir()); err != nil {
		t.Fatalf("unmountPath: %v", err)
	}
}

func TestUnmountPathLazyFallback(t *testing.T) {
	oldUmount, oldLazy := runUmount, runLazyUmount
	runUmount = func(string) error { return os.ErrPermission }
	runLazyUmount = func(string) error { return nil }
	t.Cleanup(func() {
		runUmount = oldUmount
		runLazyUmount = oldLazy
	})
	if err := unmountPath(t.TempDir()); err != nil {
		t.Fatalf("unmountPath lazy: %v", err)
	}
}

func TestUnmountTreeSimulatedMountpoints(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	root := t.TempDir()
	parent := filepath.Join(root, "orphan")
	child := filepath.Join(parent, "0")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}

	oldDev := pathDevOf
	pathDevOf = func(path string) uint64 {
		if path == child {
			return 42
		}
		return oldDev(path)
	}
	t.Cleanup(func() { pathDevOf = oldDev })

	var umountCalls atomic.Int32
	oldSweepUmount, oldSweepLazy := sweepUmount, sweepLazyUmount
	sweepUmount = func(path string) error {
		umountCalls.Add(1)
		if path == child {
			return nil
		}
		return os.ErrInvalid
	}
	sweepLazyUmount = func(string) error { return os.ErrInvalid }
	t.Cleanup(func() {
		sweepUmount = oldSweepUmount
		sweepLazyUmount = oldSweepLazy
	})

	unmountTree(logger, parent)
	if umountCalls.Load() != 1 {
		t.Fatalf("sweep umount calls = %d, want 1", umountCalls.Load())
	}
}

func TestUnmountTreeLazyUmountWarning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	root := t.TempDir()
	parent := filepath.Join(root, "orphan")
	child := filepath.Join(parent, "0")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}

	oldDev := pathDevOf
	pathDevOf = func(path string) uint64 {
		if path == child {
			return 99
		}
		return oldDev(path)
	}
	t.Cleanup(func() { pathDevOf = oldDev })

	oldSweepUmount, oldSweepLazy := sweepUmount, sweepLazyUmount
	sweepUmount = func(string) error { return os.ErrInvalid }
	sweepLazyUmount = func(string) error { return os.ErrInvalid }
	t.Cleanup(func() {
		sweepUmount = oldSweepUmount
		sweepLazyUmount = oldSweepLazy
	})

	unmountTree(logger, parent)
}

func TestWriteCredFileSuccessAndMkdirFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "cred.json")
	if err := writeCredFile(path, []byte("secret")); err != nil {
		t.Fatalf("writeCredFile: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "secret" {
		t.Fatalf("cred body = %q", body)
	}

	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeCredFile(filepath.Join(blocker, "cred.json"), []byte("x")); err == nil {
		t.Fatal("expected mkdir failure when parent path is a file")
	}
}

func TestCleanupOrphanDirAndSweep(t *testing.T) {
	root := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(logger, Config{RootDir: root, CredDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	orphan := filepath.Join(root, "orphan-sb")
	if err := os.MkdirAll(filepath.Join(orphan, "0"), 0o700); err != nil {
		t.Fatal(err)
	}
	m.cleanupOrphanDir(orphan)
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan dir still exists: %v", err)
	}

	// Sweep skips tracked and keep-listed sandboxes.
	tracked := filepath.Join(root, "tracked")
	os.MkdirAll(tracked, 0o700)
	m.mu.Lock()
	m.state["tracked"] = []*mountState{{sandboxID: "tracked", hostPath: tracked}}
	m.mu.Unlock()
	kept := filepath.Join(root, "kept")
	os.MkdirAll(kept, 0o700)

	m.Sweep(map[string]struct{}{"kept": {}})
	if _, err := os.Stat(tracked); err != nil {
		t.Fatal("tracked dir removed")
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatal("kept dir removed")
	}
}

func TestUnmountAllRemoveAllFailure(t *testing.T) {
	root := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(logger, Config{RootDir: root, CredDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	sandboxDir := filepath.Join(root, "sb-rm-fail")
	if err := os.MkdirAll(sandboxDir, 0o700); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(sandboxDir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sandboxDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sandboxDir, 0o700) })

	m.mu.Lock()
	m.state["sb-rm-fail"] = []*mountState{{sandboxID: "sb-rm-fail", hostPath: sandboxDir}}
	m.mu.Unlock()
	if err := m.UnmountAll("sb-rm-fail"); err == nil {
		t.Fatal("expected RemoveAll failure")
	}
}

func TestReestablishRemountsWhenPartial(t *testing.T) {
	credCounter := &atomic.Int32{}
	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeS3: fakeAdapter{wroteCred: credCounter, credKey: "secret"},
	})
	specs := []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://a", Target: "/a", Credentials: map[string]string{"secret": "x"}}}
	if err := m.Reestablish(context.Background(), "sb-partial", specs); err != nil {
		t.Fatal(err)
	}
	// Simulate partial state (fewer tracked than specs).
	m.mu.Lock()
	m.state["sb-partial"] = m.state["sb-partial"][:0]
	m.mu.Unlock()
	if err := m.Reestablish(context.Background(), "sb-partial", specs); err != nil {
		t.Fatal(err)
	}
}

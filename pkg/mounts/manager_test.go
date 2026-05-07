package mounts

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// fakeAdapter pretends to be a kernel mount so the manager doesn't try to
// supervise a process. The "mount" itself is faked by writing a sentinel
// file into hostTarget; the manager's waitForMount probe checks st.Dev so
// we'd need a real mount to satisfy it. To bypass that, we call shouldHook
// before MountAll is invoked and rebind the manager's mount probe.
type fakeAdapter struct {
	buildErr  error
	wroteCred *atomic.Int32
	credKey   string
}

func (f fakeAdapter) Build(sandboxID string, index int, spec models.MountSpec, hostTarget, credDir string) (adapters.Plan, error) {
	if f.buildErr != nil {
		return adapters.Plan{}, f.buildErr
	}
	plan := adapters.Plan{
		Argv:          []string{"true"}, // exits immediately
		IsKernelMount: true,
	}
	if val, ok := spec.Credentials[f.credKey]; ok && f.credKey != "" {
		plan.CredFile = filepath.Join(credDir, sandboxID+"-fake-"+f.credKey)
		plan.CredBody = []byte(val)
		if f.wroteCred != nil {
			f.wroteCred.Add(1)
		}
	}
	return plan, nil
}

// newTestManager swaps in a stub adapter map and a no-op mount-readiness
// probe so tests don't need a real FUSE/kernel mount to exercise lifecycle
// code.
func newTestManager(t *testing.T, adapterMap map[models.MountType]adapters.Adapter) *Manager {
	t.Helper()
	root := t.TempDir()
	creds := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(logger, Config{
		RootDir:     root,
		CredDir:     creds,
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.adapters = adapterMap
	t.Cleanup(m.Close)
	return m
}

func TestManagerMountAllAndUnmountAll(t *testing.T) {
	credCounter := &atomic.Int32{}
	fa := fakeAdapter{wroteCred: credCounter, credKey: "secret"}
	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeS3: fa,
	})

	specs := []models.MountSpec{
		{
			Type:        models.MountTypeS3,
			Source:      "s3://bucket-a",
			Target:      "/data/a",
			Credentials: map[string]string{"secret": "AAAA"},
		},
		{
			Type:   models.MountTypeS3,
			Source: "s3://bucket-b",
			Target: "/data/b",
		},
	}

	binds, err := m.MountAll(context.Background(), "sb-test", specs)
	if err != nil {
		t.Fatalf("MountAll: %v", err)
	}
	if len(binds) != 2 {
		t.Fatalf("got %d binds, want 2", len(binds))
	}
	if binds[0].ContainerPath != "/data/a" || binds[1].ContainerPath != "/data/b" {
		t.Errorf("binds wrong: %+v", binds)
	}
	if want := int32(1); credCounter.Load() != want {
		t.Errorf("cred writes = %d, want %d", credCounter.Load(), want)
	}
	for _, b := range binds {
		if _, err := os.Stat(b.HostPath); err != nil {
			t.Errorf("host path missing: %v", err)
		}
	}

	hb := m.HostBindsFor("sb-test")
	if len(hb) != 2 {
		t.Errorf("HostBindsFor = %d, want 2", len(hb))
	}

	if err := m.UnmountAll("sb-test"); err != nil {
		t.Errorf("UnmountAll: %v", err)
	}
	if hb := m.HostBindsFor("sb-test"); len(hb) != 0 {
		t.Errorf("HostBindsFor after unmount = %d, want 0", len(hb))
	}
}

func TestManagerMountAllRollbackOnFailure(t *testing.T) {
	good := fakeAdapter{}
	bad := fakeAdapter{buildErr: errFake}
	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeS3:  good,
		models.MountTypeNFS: bad,
	})

	specs := []models.MountSpec{
		{Type: models.MountTypeS3, Source: "s3://a", Target: "/a"},
		{Type: models.MountTypeNFS, Source: "host:/a", Target: "/b"},
	}
	binds, err := m.MountAll(context.Background(), "sb-fail", specs)
	if err == nil {
		t.Fatalf("MountAll succeeded unexpectedly: %+v", binds)
	}
	// Sandbox dir should have been removed during rollback.
	if _, err := os.Stat(filepath.Join(m.rootDir, "sb-fail")); !os.IsNotExist(err) {
		t.Errorf("sandbox dir not cleaned up: err=%v", err)
	}
	if hb := m.HostBindsFor("sb-fail"); len(hb) != 0 {
		t.Errorf("HostBindsFor after rollback = %d, want 0", len(hb))
	}
}

func TestManagerReestablishIdempotent(t *testing.T) {
	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeS3: fakeAdapter{},
	})

	specs := []models.MountSpec{
		{Type: models.MountTypeS3, Source: "s3://a", Target: "/a"},
	}
	if err := m.Reestablish(context.Background(), "sb-x", specs); err != nil {
		t.Fatalf("first Reestablish: %v", err)
	}
	first := m.HostBindsFor("sb-x")
	if err := m.Reestablish(context.Background(), "sb-x", specs); err != nil {
		t.Fatalf("second Reestablish: %v", err)
	}
	second := m.HostBindsFor("sb-x")
	if first[0].HostPath != second[0].HostPath {
		t.Errorf("host path changed across Reestablish: %s != %s", first[0].HostPath, second[0].HostPath)
	}
}

func TestManagerSuperviseRestartsAfterFirstCrash(t *testing.T) {
	root := t.TempDir()
	creds := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(logger, Config{RootDir: root, CredDir: creds, WaitTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(m.Close)

	// Inject a state with a process that exits immediately. We bypass MountAll
	// entirely and simulate the "kernel mount succeeded" path by registering a
	// state with a finished cmd, then call superviseExit-like restart logic by
	// setting up a fake supervised state and triggering restart manually.
	hostPath := filepath.Join(root, "sb-sup", "0")
	if err := os.MkdirAll(hostPath, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	state := &mountState{
		sandboxID:  "sb-sup",
		index:      0,
		hostPath:   hostPath,
		plan:       adapters.Plan{Argv: []string{"true"}},
		cmd:        cmd,
		startedAt:  time.Now().UTC(),
		supervised: true,
	}
	m.mu.Lock()
	m.state["sb-sup"] = []*mountState{state}
	m.mu.Unlock()

	// Drive the supervisor synchronously; it'll Wait() on the cmd, observe
	// the exit, and restart once.
	m.superviseExit(state)

	m.mu.Lock()
	defer m.mu.Unlock()
	if state.disabled {
		t.Errorf("state disabled after first crash; should have restarted")
	}
	if state.restarts != 1 {
		t.Errorf("restarts = %d, want 1", state.restarts)
	}
}

var errFake = &fakeErr{msg: "build failed (simulated)"}

type fakeErr struct{ msg string }

func (e *fakeErr) Error() string { return e.msg }

// TestSweepRemovesOrphanDirsButKeepsLive verifies the startup sweeper:
// any directory under RootDir whose sandbox-id is not in the keep set or
// the live tracked map is removed; everything else is left alone.
func TestSweepRemovesOrphanDirsButKeepsLive(t *testing.T) {
	root := t.TempDir()
	credDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(logger, Config{RootDir: root, CredDir: credDir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Lay down three sandbox dirs:
	//   sb-keep   → in the keep set (live container)
	//   sb-live   → tracked in m.state (mid-mount)
	//   sb-orphan → neither: should be removed
	for _, id := range []string{"sb-keep", "sb-live", "sb-orphan"} {
		if err := os.MkdirAll(filepath.Join(root, id, "0"), 0o700); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	// Mark sb-live as tracked.
	m.mu.Lock()
	m.state["sb-live"] = []*mountState{{sandboxID: "sb-live", index: 0, hostPath: filepath.Join(root, "sb-live", "0")}}
	m.mu.Unlock()

	m.Sweep(map[string]struct{}{"sb-keep": {}})

	// sb-keep and sb-live still present, sb-orphan gone.
	if _, err := os.Stat(filepath.Join(root, "sb-keep")); err != nil {
		t.Errorf("sb-keep was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "sb-live")); err != nil {
		t.Errorf("sb-live (tracked) was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "sb-orphan")); !os.IsNotExist(err) {
		t.Errorf("sb-orphan should be gone, stat err = %v", err)
	}
}

// TestSweepIgnoresMissingRoot is the boring "first run before anything has
// been mounted" path. It must not error or panic.
func TestSweepIgnoresMissingRoot(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Build a Manager but then nuke its root behind its back.
	root := t.TempDir()
	credDir := t.TempDir()
	m, err := New(logger, Config{RootDir: root, CredDir: credDir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("setup: %v", err)
	}
	m.Sweep(map[string]struct{}{}) // must not panic
}

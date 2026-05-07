package mounts

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestRecoveryFromCrashedCreate exercises the realistic restart scenario:
//
//  1. sandboxd starts a CreateSandbox call.
//  2. mountAll succeeds — host dir + (fake) FUSE process exist.
//  3. sandboxd dies before Docker create completes; from the kernel's view,
//     the host mount dir is still there with no container ever bound to it.
//  4. sandboxd restarts. The Manager is fresh (in-memory state empty), the
//     reconciler has no record of this sandbox in the DB or in Docker, so
//     it ends up in neither the keep set nor the tracked map.
//  5. Sweep removes the orphan dir cleanly without touching live mounts.
//
// This is the bug class "kill -9 sandboxd mid-create, restart, verify state
// is consistent."
func TestRecoveryFromCrashedCreate(t *testing.T) {
	root := t.TempDir()
	credDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// --- Run 1: sandboxd is alive, finishes MountAll, then "dies." ---
	m1, err := New(logger, Config{RootDir: root, CredDir: credDir})
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	wrote := &atomic.Int32{}
	m1.adapters[models.MountTypeS3] = fakeAdapter{wroteCred: wrote, credKey: "secret"}

	specs := []models.MountSpec{
		{
			Type:   models.MountTypeS3,
			Source: "s3://test-bucket",
			Target: "/workspace",
			Credentials: map[string]string{
				"secret": "AKIA-FAKE",
			},
		},
	}
	binds, err := m1.MountAll(context.Background(), "sb-crashed", specs)
	if err != nil {
		t.Fatalf("MountAll: %v", err)
	}
	if len(binds) != 1 || binds[0].HostPath != filepath.Join(root, "sb-crashed", "0") {
		t.Fatalf("unexpected binds: %+v", binds)
	}
	if _, err := os.Stat(binds[0].HostPath); err != nil {
		t.Fatalf("expected host path to exist: %v", err)
	}

	// "Crash" — drop m1 without calling Close/UnmountAll. Directory survives.
	_ = m1

	// --- Run 2: fresh Manager, empty in-memory state. Reconcile decides
	// the sandbox is unknown (not in keep), and Sweep removes it. ---
	m2, err := New(logger, Config{RootDir: root, CredDir: credDir})
	if err != nil {
		t.Fatalf("second New: %v", err)
	}
	m2.Sweep(map[string]struct{}{}) // no live sandboxes

	if _, err := os.Stat(filepath.Join(root, "sb-crashed")); !os.IsNotExist(err) {
		t.Fatalf("orphan sandbox dir was not cleaned up; stat err = %v", err)
	}
}

// TestRecoveryDoesNotRemoveActiveSandbox is the negative half of the above:
// after restart, sandboxes that are *still running* must keep their host
// mount dirs even though they're not yet tracked in the new Manager.
func TestRecoveryDoesNotRemoveActiveSandbox(t *testing.T) {
	root := t.TempDir()
	credDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Pre-existing dir (a running sandbox that survived the restart).
	if err := os.MkdirAll(filepath.Join(root, "sb-running", "0"), 0o700); err != nil {
		t.Fatalf("setup: %v", err)
	}

	m, err := New(logger, Config{RootDir: root, CredDir: credDir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Reconciler tells us this sandbox is in the live set.
	m.Sweep(map[string]struct{}{"sb-running": {}})

	if _, err := os.Stat(filepath.Join(root, "sb-running")); err != nil {
		t.Fatalf("active sandbox dir was incorrectly swept: %v", err)
	}
}

// TestRecoveryReestablishWithFreshManager confirms that after a sandboxd
// restart, calling Reestablish for a still-running container correctly
// re-mounts, even though state was lost.
func TestRecoveryReestablishWithFreshManager(t *testing.T) {
	root := t.TempDir()
	credDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	m, err := New(logger, Config{RootDir: root, CredDir: credDir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.adapters[models.MountTypeS3] = fakeAdapter{}

	specs := []models.MountSpec{{
		Type:   models.MountTypeS3,
		Source: "s3://test-bucket",
		Target: "/workspace",
	}}

	// Pretend the previous incarnation's host dir still exists.
	if err := os.MkdirAll(filepath.Join(root, "sb-survivor", "0"), 0o700); err != nil {
		t.Fatalf("pre-create dir: %v", err)
	}

	// Reestablish with empty in-memory state. Since len(state)==0 != len(specs),
	// it tears down and re-mounts cleanly.
	if err := m.Reestablish(context.Background(), "sb-survivor", specs); err != nil {
		t.Fatalf("Reestablish: %v", err)
	}

	binds := m.HostBindsFor("sb-survivor")
	if len(binds) != 1 {
		t.Fatalf("expected 1 bind after reestablish, got %d", len(binds))
	}
}

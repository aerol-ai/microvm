package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Regression (Kubernetes Phase 0, finding F12): on a containerd-engine host
// where dockerd is stopped or was never installed, the Docker listing fails
// on every pass. Reconcile used to return at that error, so a containerd
// sandbox the kernel killed for memory stayed "started" for good. Now it
// reconciles everything that does not live in Docker, and leaves the
// Docker-owned rows, and the mounts it cannot vouch for, exactly as they are.
func TestReconcileWithoutDockerStillReconcilesContainerd(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	mountsRoot := filepath.Join(t.TempDir(), "mounts")
	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir:     mountsRoot,
		CredDir:     filepath.Join(t.TempDir(), "cred"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	dockerDown := &fakeReconcileRuntime{listErr: errors.New("Cannot connect to the Docker daemon")}
	containerd := &fakeReconcileRuntime{managed: map[string]*models.SandboxRuntimeState{
		// Killed for memory: its task is gone, the container object is not.
		"sb-ctd": {SandboxID: "sb-ctd", ContainerID: "sb-ctd", Status: models.SandboxStatusStopped},
	}}
	svc := &Service{
		cfg:        config.Config{},
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:      st,
		docker:     dockerDown,
		containerd: containerd,
		caddy:      caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second}),
		mounts:     mgr,
	}
	now := time.Now().UTC()
	for _, sb := range []*models.Sandbox{
		{ID: "sb-ctd", Engine: models.ContainerEngineContainerd, ContainerID: "sb-ctd"},
		{ID: "sb-dkr", Engine: models.ContainerEngineDocker, ContainerID: "ctr-dkr"},
	} {
		sb.Image, sb.Status, sb.Runtime = "alpine:3.20", models.SandboxStatusStarted, models.RuntimeDocker
		sb.CPU, sb.MemoryMB = 1, 64
		sb.CreatedAt, sb.UpdatedAt, sb.LastActiveAt = now, now, now
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("seed %s: %v", sb.ID, err)
		}
	}
	// A mount directory of the Docker sandbox: with Docker's list unknown,
	// the stale-mount sweep cannot tell it from a leftover.
	dkrMount := filepath.Join(mountsRoot, "sb-dkr")
	if err := os.MkdirAll(dkrMount, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile = %v, want nil: a failed Docker listing must not stop the pass", err)
	}

	ctd, err := st.Get(ctx, "sb-ctd")
	if err != nil {
		t.Fatalf("Get sb-ctd: %v", err)
	}
	if ctd.Status != models.SandboxStatusStopped || ctd.StatusReason != models.StatusReasonReconcile {
		t.Fatalf("containerd sandbox = %s (%q), want stopped by reconcile", ctd.Status, ctd.StatusReason)
	}
	dkr, err := st.Get(ctx, "sb-dkr")
	if err != nil {
		t.Fatalf("Docker-owned row was removed: %v", err)
	}
	if dkr.Status != models.SandboxStatusStarted {
		t.Fatalf("Docker-owned sandbox = %s, want it left started", dkr.Status)
	}
	if len(dockerDown.inspectRefs) != 0 || len(dockerDown.destroyIDs) != 0 {
		t.Fatalf("Docker was asked about rows it could not list: inspect %v, destroy %v", dockerDown.inspectRefs, dockerDown.destroyIDs)
	}
	if _, err := os.Stat(dkrMount); err != nil {
		t.Fatalf("the Docker sandbox's mount directory was swept: %v", err)
	}
}

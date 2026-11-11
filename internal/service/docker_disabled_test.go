package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"io"
	"log/slog"
)

// C2: a containerd host with no Docker is not degraded by Docker's absence,
// and Docker is not even asked.
func TestHealthWithDockerDisabled(t *testing.T) {
	rt := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}, pingErr: errors.New("Cannot connect to the Docker daemon")}
	svc, _, _ := newServiceRuntimeHarness(t, rt)

	h, err := svc.Health(context.Background())
	if err != nil || h.Docker == "ok" || h.Status != "degraded" {
		t.Fatalf("Docker on and down: %+v, %v; want docker's error and degraded", h, err)
	}

	svc.cfg.DockerDisabled = true
	h, err = svc.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Docker != "disabled" || h.Status != "ok" {
		t.Fatalf("Docker off: %+v, want docker disabled and status ok", h)
	}
}

func TestNodeGuardRuntimesWithDockerDisabled(t *testing.T) {
	svc := &Service{}
	if got := svc.nodeGuardRuntimes(); len(got) != 3 || got[0].name != models.ContainerEngineDocker {
		t.Fatalf("Docker on: %+v, want docker, containerd, firecracker", got)
	}
	svc.cfg.DockerDisabled = true
	for _, nr := range svc.nodeGuardRuntimes() {
		if nr.name == models.ContainerEngineDocker {
			t.Fatal("Docker off: the node guard still covers Docker")
		}
	}
}

// With Docker off, reconcile never lists Docker, still reconciles
// containerd rows, and still sweeps stale mounts.
func TestReconcileWithDockerDisabled(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	mountsRoot := filepath.Join(t.TempDir(), "mounts")
	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir: mountsRoot, CredDir: filepath.Join(t.TempDir(), "cred"), WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Close)
	// Docker must not be asked: listing it would fail the test.
	docker := &fakeReconcileRuntime{listErr: errors.New("docker listed although it is off")}
	containerd := &fakeReconcileRuntime{managed: map[string]*models.SandboxRuntimeState{
		"sb-ctd": {SandboxID: "sb-ctd", ContainerID: "sb-ctd", Status: models.SandboxStatusStopped},
	}}
	svc := &Service{
		cfg:    config.Config{DockerDisabled: true, ContainerEngine: models.ContainerEngineContainerd},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st, docker: docker, containerd: containerd,
		caddy:  caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second}),
		mounts: mgr,
	}
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-ctd", Engine: models.ContainerEngineContainerd, ContainerID: "sb-ctd", Image: "alpine:3.20",
		Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 64,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(mountsRoot, "sb-gone")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile = %v", err)
	}
	if got, _ := st.Get(ctx, "sb-ctd"); got == nil || got.Status != models.SandboxStatusStopped {
		t.Fatalf("containerd row = %+v, want stopped by reconcile", got)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("a stale mount directory survived the sweep: %v", err)
	}
}

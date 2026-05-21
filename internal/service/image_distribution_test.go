package service

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestNormalizeCreateImageDistributionResolvesSnapshotMetadata(t *testing.T) {
	ctx := context.Background()
	st := openImageDistributionStore(t)
	defer st.Close()

	snapshot := &models.SandboxSnapshot{
		Name:                  "e2b/sb-123:default",
		Image:                 "e2b/sb-123:default",
		SourceSandboxID:       "sb-123",
		CreatedAt:             time.Now().UTC(),
		ImageDistributionMode: models.ImageDistributionLocalOnly,
	}
	if err := st.CreateSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("CreateSnapshot() error = %v", err)
	}

	svc := &Service{store: st}
	req := models.CreateSandboxRequest{Image: snapshot.Name}
	if err := svc.NormalizeCreateImageDistribution(ctx, &req); err != nil {
		t.Fatalf("NormalizeCreateImageDistribution() error = %v", err)
	}
	if req.Image != snapshot.Image {
		t.Fatalf("req.Image = %q, want %q", req.Image, snapshot.Image)
	}
	if req.ImageDistributionMode != models.ImageDistributionLocalOnly {
		t.Fatalf("req.ImageDistributionMode = %q, want %q", req.ImageDistributionMode, models.ImageDistributionLocalOnly)
	}
	if !ImageRequiresLocalPlacement(req) {
		t.Fatal("snapshot-backed local image must require local placement")
	}
}

func TestRegisterSnapshotClassifiesImageDistribution(t *testing.T) {
	ctx := context.Background()
	st := openImageDistributionStore(t)
	defer st.Close()
	svc := &Service{store: st}

	aocrImage := "aocr.aerol.ai/team/app@sha256:abc"
	aocr, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{
		Name:      "aocr-template",
		Image:     aocrImage,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RegisterSnapshot(aocr) error = %v", err)
	}
	if aocr.ImageDistributionMode != models.ImageDistributionAOCR || aocr.ImageRegistryRef != aocrImage {
		t.Fatalf("aocr distribution = mode %q ref %q", aocr.ImageDistributionMode, aocr.ImageRegistryRef)
	}

	localImage := docker.BuiltImageNamespace + "/abc123:latest"
	local, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{
		Name:      "local-template",
		Image:     localImage,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RegisterSnapshot(local) error = %v", err)
	}
	if local.ImageDistributionMode != models.ImageDistributionLocalOnly {
		t.Fatalf("local distribution mode = %q, want %q", local.ImageDistributionMode, models.ImageDistributionLocalOnly)
	}
}

func TestNormalizeCreateFailover(t *testing.T) {
	req := models.CreateSandboxRequest{
		Image:                 "ubuntu:22.04",
		ImageDistributionMode: models.ImageDistributionExternalRegistry,
		Failover:              &models.Failover{Policy: "ReCreate"},
	}
	if err := NormalizeCreateFailover(&req); err != nil {
		t.Fatalf("NormalizeCreateFailover() error = %v", err)
	}
	if req.Failover == nil || req.Failover.Policy != models.FailoverPolicyRecreate {
		t.Fatalf("normalized failover = %+v, want recreate", req.Failover)
	}

	req = models.CreateSandboxRequest{
		Image:                 docker.BuiltImageNamespace + "/abc123:latest",
		ImageDistributionMode: models.ImageDistributionLocalOnly,
		Failover:              &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	if err := NormalizeCreateFailover(&req); err == nil {
		t.Fatal("expected local-only failover recreate to be rejected")
	}
}

func TestCreateSnapshotWithOwnershipMarksLocalOnly(t *testing.T) {
	ctx := context.Background()
	st := openImageDistributionStore(t)
	defer st.Close()

	sandbox := &models.Sandbox{
		ID:             "sb-snap-local",
		Image:          "ubuntu:22.04",
		Status:         models.SandboxStatusStarted,
		ContainerID:    "ctr-snap-local",
		ContainerIP:    "10.0.0.15",
		CPU:            1,
		MemoryMB:       1024,
		DiskGB:         10,
		OSUser:         "root",
		Env:            map[string]string{},
		ToolboxEnabled: true,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
		LastActiveAt:   time.Now().UTC(),
		Runtime:        models.RuntimeDocker,
	}
	if err := st.Create(ctx, sandbox); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	rt := &fakeSnapshotRuntime{imageID: "sha256:snapshot-local"}
	svc := &Service{store: st, docker: rt, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	snapshot, _, err := svc.CreateSnapshotWithOwnership(ctx, sandbox.ID, models.CreateSandboxSnapshotRequest{Name: "e2b/sb-snap-local:default"})
	if err != nil {
		t.Fatalf("CreateSnapshotWithOwnership() error = %v", err)
	}
	if snapshot.ImageDistributionMode != models.ImageDistributionLocalOnly {
		t.Fatalf("snapshot.ImageDistributionMode = %q, want %q", snapshot.ImageDistributionMode, models.ImageDistributionLocalOnly)
	}
}

func openImageDistributionStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return st
}

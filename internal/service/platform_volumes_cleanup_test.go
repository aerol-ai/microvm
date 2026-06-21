package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestVolumeMetaSQLiteAttachmentsPath(t *testing.T) {
	s := enabledVolumeService(t)
	ctx := context.Background()

	v, err := s.CreatePlatformVolume(ctx, "data")
	if err != nil {
		t.Fatalf("CreatePlatformVolume: %v", err)
	}
	now := time.Now().UTC()
	if err := s.store.Create(ctx, &models.Sandbox{
		ID: "sb-local", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}
	if err := s.volumeMeta().PutAttachments(ctx, []models.VolumeAttachment{{
		Tenant: v.Tenant, VolumeID: v.ID, SandboxID: "sb-local", Target: "/data", Source: v.Source,
	}}); err != nil {
		t.Fatalf("PutAttachments: %v", err)
	}
	count, err := s.volumeMeta().AttachmentCount(ctx, v.Tenant, v.ID)
	if err != nil || count != 1 {
		t.Fatalf("AttachmentCount = %d, %v", count, err)
	}
	if err := s.volumeMeta().DeleteAttachmentsForSandbox(ctx, "sb-local"); err != nil {
		t.Fatalf("DeleteAttachmentsForSandbox: %v", err)
	}
	count, err = s.volumeMeta().AttachmentCount(ctx, v.Tenant, v.ID)
	if err != nil || count != 0 {
		t.Fatalf("AttachmentCount after delete = %d, %v", count, err)
	}
}

func TestCleanupPlatformVolumeAttachmentsDedupesSandbox(t *testing.T) {
	s := enabledVolumeService(t)
	s.cfg.EnableCluster = true
	s.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	ctx := context.Background()

	v, err := s.CreatePlatformVolume(ctx, "data")
	if err != nil {
		t.Fatalf("CreatePlatformVolume: %v", err)
	}
	if err := s.volumeMeta().PutAttachments(ctx, []models.VolumeAttachment{{
		Tenant: v.Tenant, VolumeID: v.ID, SandboxID: "sb-1", Target: "/data", Source: v.Source,
	}}); err != nil {
		t.Fatalf("PutAttachments: %v", err)
	}
	s.cleanupPlatformVolumeAttachments(ctx, []models.VolumeAttachment{
		{SandboxID: "sb-1"},
		{SandboxID: "sb-1"},
		{SandboxID: ""},
	})
	count, err := s.volumeMeta().AttachmentCount(ctx, v.Tenant, v.ID)
	if err != nil || count != 0 {
		t.Fatalf("attachments after cleanup = %d, %v", count, err)
	}
}

func TestCleanupCreatedPlatformVolumesSkipsMissingVolume(t *testing.T) {
	s := enabledVolumeService(t)
	s.cfg.EnableCluster = true
	s.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	s.cleanupCreatedPlatformVolumes(context.Background(), []models.VolumeAttachment{{
		Tenant: "t-a", VolumeID: "vol-missing", CreatedVolume: true,
	}})
}

func TestCleanupCreatedPlatformVolumesLogsLookupFailure(t *testing.T) {
	s := enabledVolumeService(t)
	s.cfg.EnableCluster = true
	s.logger = slog.Default()
	s.AttachCluster(&failingVolumeLookupCluster{Noop: cluster.NewNoop("self", "http://self", "")})
	s.cleanupCreatedPlatformVolumes(context.Background(), []models.VolumeAttachment{{
		Tenant: "t-a", VolumeID: "vol-1", CreatedVolume: true,
	}})
}

func TestDestroySandboxClearsClusterVolumeAttachments(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.cfg.PlatformVolumes = enabledVolumeService(t).cfg.PlatformVolumes
	svc.cfg.PATToken = "operator-pat"
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	ctx := context.Background()

	v, err := svc.CreatePlatformVolume(ctx, "data")
	if err != nil {
		t.Fatalf("CreatePlatformVolume: %v", err)
	}
	seedStartedSandbox(t, st, "sb-destroy")
	if err := svc.volumeMeta().PutAttachments(ctx, []models.VolumeAttachment{{
		Tenant: v.Tenant, VolumeID: v.ID, SandboxID: "sb-destroy", Target: "/data", Source: v.Source,
	}}); err != nil {
		t.Fatalf("PutAttachments: %v", err)
	}
	if err := svc.DestroySandbox(ctx, "sb-destroy"); err != nil {
		t.Fatalf("DestroySandbox: %v", err)
	}
	count, err := svc.volumeMeta().AttachmentCount(ctx, v.Tenant, v.ID)
	if err != nil || count != 0 {
		t.Fatalf("attachments after destroy = %d, %v", count, err)
	}
}

type failingVolumeLookupCluster struct {
	*cluster.Noop
}

func (f *failingVolumeLookupCluster) VolumeByID(context.Context, string, string) (models.Volume, error) {
	return models.Volume{}, errors.New("lookup failed")
}

func (f *failingVolumeLookupCluster) VolumeDelete(context.Context, string, string) error {
	return store.ErrNotFound
}

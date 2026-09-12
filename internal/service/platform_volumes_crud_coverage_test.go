package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

func TestDeletePlatformVolumeInUseAndByNameMiss(t *testing.T) {
	s := enabledVolumeService(t)
	ctx := context.Background()
	v, err := s.CreatePlatformVolume(ctx, "vol1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.store.Create(ctx, &models.Sandbox{
		ID: "sb-vol", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertSandboxAuditACL(ctx, "sb-vol", "", "inc-sb-vol"); err != nil {
		t.Fatal(err)
	}
	if err := s.volumeMeta().PutAttachments(ctx, []models.VolumeAttachment{{
		VolumeID: v.ID, SandboxID: "sb-vol", IncarnationID: "inc-sb-vol", Target: "/data", Tenant: v.Tenant, Source: v.Source,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePlatformVolume(ctx, v.ID); err == nil || !errors.Is(err, models.ErrPlatformVolumeInUse) {
		t.Fatalf("delete attached = %v, want ErrPlatformVolumeInUse", err)
	}
	if _, err := s.GetPlatformVolumeByName(ctx, "no-such-vol"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("by name miss = %v", err)
	}
}

func TestDeletePlatformVolumeMetaArmsWave21(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	tenant, err := s.volumeTenant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	vol := models.Volume{ID: "v1", Tenant: tenant, Name: "n1", Backend: "s3", Source: "bucket/x", CreatedAt: time.Now().UTC()}

	s.testVolumeMeta = &scriptedVolumeMeta{byID: &vol, attachmentCountErr: errors.New("count boom")}
	if err := s.DeletePlatformVolume(ctx, "v1"); err == nil {
		t.Fatal("expected count error")
	}

	s.testVolumeMeta = &scriptedVolumeMeta{byID: &vol, attachmentCount: 2}
	if err := s.DeletePlatformVolume(ctx, "v1"); !errors.Is(err, models.ErrPlatformVolumeInUse) {
		t.Fatalf("in use: %v", err)
	}

	s2 := enabledVolumeService(t)
	s2.logger = s.logger
	empty := vol
	empty.Source = ""
	s2.testVolumeMeta = &scriptedVolumeMeta{byID: &empty, attachmentCount: 0}
	_ = s2.store.Close()
	_ = s2.DeletePlatformVolume(ctx, "v1")

	s3 := enabledVolumeService(t)
	s3.logger = s.logger
	s3.testVolumeMeta = &scriptedVolumeMeta{byID: &vol, attachmentCount: 0, deleteRowErr: errors.New("del row")}
	if err := s3.DeletePlatformVolume(ctx, "v1"); err == nil {
		t.Fatal("expected delete row error")
	}

	s4 := enabledVolumeService(t)
	s4.testVolumeMeta = &scriptedVolumeMeta{byIDErr: store.ErrNotFound}
	if err := s4.DeletePlatformVolume(ctx, "missing"); err == nil {
		t.Fatal("expected not found")
	}
}

func TestCreateForcePlatformAttachmentsWave21(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.admitter = nil
	svc.cfg.PlatformVolumes = enabledVolumeService(t).cfg.PlatformVolumes
	svc.cfg.PATToken = "operator-pat"
	tenant, _ := svc.volumeTenant(ctx)
	svc.testForcePlatformAttachments = []models.VolumeAttachment{{
		VolumeID: "ghost", Tenant: tenant, Target: "/data",
	}}
	svc.testVolumeMeta = &scriptedVolumeMeta{putAttachmentsErr: errors.New("put boom")}
	pub := true
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", AllowPublicTraffic: &pub,
	}, "sb-attach21")
	if err == nil || !strings.Contains(err.Error(), "persist platform") {
		t.Fatalf("err = %v", err)
	}
}

func TestGetPlatformVolumeByNameDisabledAndSanitize(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	s.cfg.PlatformVolumes.Enabled = false
	if _, err := s.GetPlatformVolumeByName(ctx, "x"); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("disabled = %v", err)
	}
	s.cfg.PlatformVolumes.Enabled = true
	if _, err := s.GetPlatformVolumeByName(ctx, "../bad"); err == nil {
		t.Fatal("expected sanitize failure")
	}
	// Happy path after create.
	v, err := s.CreatePlatformVolume(ctx, "ok-name")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPlatformVolumeByName(ctx, "ok-name")
	if err != nil || got.ID != v.ID {
		t.Fatalf("by name = %+v, %v", got, err)
	}
}

func TestDeleteVolumeRowIfUnattachedEmptySource(t *testing.T) {
	s := enabledVolumeService(t)
	ctx := context.Background()
	v, err := s.CreatePlatformVolume(ctx, "empty-src")
	if err != nil {
		t.Fatal(err)
	}
	// Force empty Source so deleteVolumeRowIfUnattached rebuilds via MountSource.
	v.Source = ""
	if err := s.deleteVolumeRowIfUnattached(ctx, *v); err != nil {
		t.Fatalf("deleteVolumeRowIfUnattached: %v", err)
	}
	if _, err := volumes.SanitizeVolumeName("empty-src"); err != nil {
		t.Fatal(err)
	}
}

func TestPlatformVolumeCRUDDisabledAndTenantErrors(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	s.cfg.PlatformVolumes.Enabled = false
	if _, err := s.CreatePlatformVolume(ctx, "x"); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("create disabled = %v", err)
	}
	if _, err := s.GetPlatformVolume(ctx, "id"); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("get disabled = %v", err)
	}
	if _, err := s.GetPlatformVolumeByName(ctx, "x"); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("getByName disabled = %v", err)
	}
	if _, err := s.ListPlatformVolumes(ctx); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("list disabled = %v", err)
	}
	if err := s.DeletePlatformVolume(ctx, "id"); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("delete disabled = %v", err)
	}

	s2 := enabledVolumeService(t)
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no entropy")}})
	if _, err := s2.CreatePlatformVolume(ctx, "data"); err == nil {
		t.Fatal("expected generateVolumeID failure")
	}
}

func TestPlatformVolumeCRUDTenantAndSanitizeWave8(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	if _, err := s.CreatePlatformVolume(ctx, "../nope"); err == nil {
		t.Fatal("expected sanitize reject")
	}
	// Empty PAT + no user token → TenantScope error on volumeTenant.
	s.cfg.PATToken = ""
	if _, err := s.CreatePlatformVolume(ctx, "data"); err == nil {
		t.Fatal("expected tenant scope failure")
	}
	if _, err := s.GetPlatformVolume(ctx, "vol-x"); err == nil {
		t.Fatal("expected get tenant failure")
	}
	if _, err := s.GetPlatformVolumeByName(ctx, "data"); err == nil {
		t.Fatal("expected getByName tenant failure")
	}
	if _, err := s.ListPlatformVolumes(ctx); err == nil {
		t.Fatal("expected list tenant failure")
	}
	if err := s.DeletePlatformVolume(ctx, "vol-x"); err == nil {
		t.Fatal("expected delete tenant failure")
	}

	s2 := enabledVolumeService(t)
	s2.cfg.PlatformVolumes.MaxPerTenant = 1
	if _, err := s2.CreatePlatformVolume(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.CreatePlatformVolume(ctx, "two"); !errors.Is(err, models.ErrPlatformVolumeQuota) {
		t.Fatalf("quota = %v", err)
	}
}

package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

func enabledVolumeService(t *testing.T) *Service {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &Service{
		cfg: config.Config{
			PATToken: "operator-pat",
			PlatformVolumes: config.PlatformVolumesConfig{
				Enabled:  true,
				Backend:  config.PlatformVolumesBackendS3,
				S3Bucket: "aerol-volumes",
				S3Prefix: "volumes",
			},
		},
		store:  st,
		cipher: newTestCipher(t),
	}
}

// UC-28/UC-31: create is idempotent (duplicate name returns the same row), and
// get/getByName/list resolve it.
func TestPlatformVolumeCRUD(t *testing.T) {
	s := enabledVolumeService(t)
	ctx := context.Background()

	v1, err := s.CreatePlatformVolume(ctx, "Data") // mixed case → sanitized
	if err != nil {
		t.Fatalf("CreatePlatformVolume: %v", err)
	}
	if v1.Name != "data" {
		t.Fatalf("name = %q, want sanitized 'data'", v1.Name)
	}
	// Idempotent: second create of the same name returns the same volume.
	v2, err := s.CreatePlatformVolume(ctx, "data")
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if v2.ID != v1.ID {
		t.Fatalf("duplicate create made a new id: %q vs %q", v2.ID, v1.ID)
	}

	got, err := s.GetPlatformVolume(ctx, v1.ID)
	if err != nil || got.ID != v1.ID {
		t.Fatalf("GetPlatformVolume = %+v, %v", got, err)
	}
	byName, err := s.GetPlatformVolumeByName(ctx, "data")
	if err != nil || byName.ID != v1.ID {
		t.Fatalf("GetPlatformVolumeByName = %+v, %v", byName, err)
	}
	list, err := s.ListPlatformVolumes(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListPlatformVolumes = %d (%v), want 1", len(list), err)
	}
}

// Disabled deployment rejects every CRUD entry point with the 412 sentinel.
func TestPlatformVolumeCRUDDisabled(t *testing.T) {
	s := &Service{cfg: config.Config{PATToken: "op"}} // disabled
	ctx := context.Background()
	if _, err := s.CreatePlatformVolume(ctx, "data"); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.ListPlatformVolumes(ctx); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("list: %v", err)
	}
	if _, err := s.GetPlatformVolume(ctx, "x"); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("get: %v", err)
	}
	if err := s.DeletePlatformVolume(ctx, "x"); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("delete: %v", err)
	}
}

// UC-30: delete with no live attachers removes the row.
func TestPlatformVolumeDeleteNoAttachers(t *testing.T) {
	s := enabledVolumeService(t)
	ctx := context.Background()
	v, err := s.CreatePlatformVolume(ctx, "data")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.DeletePlatformVolume(ctx, v.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetPlatformVolume(ctx, v.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("post-delete get = %v, want ErrNotFound", err)
	}
	pending, err := s.store.ListPendingVolumeDeletions(ctx)
	if err != nil {
		t.Fatalf("ListPendingVolumeDeletions: %v", err)
	}
	if len(pending) != 1 || pending[0].VolumeID != v.ID || pending[0].Source == "" {
		t.Fatalf("pending deletions = %+v, want deleted volume coordinates", pending)
	}
}

// UC-29: a volume still attached to a live sandbox cannot be deleted — 409.
func TestPlatformVolumeDeleteWhileAttached(t *testing.T) {
	s := enabledVolumeService(t)
	ctx := context.Background()
	v, err := s.CreatePlatformVolume(ctx, "data")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Seed a live sandbox and the indexed attachment that createSandbox writes
	// after resolvePlatformVolumes synthesizes the underlying mount.
	tenant, err := s.volumeTenant(ctx)
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	spec, err := buildVolumeSpecForTest(s, tenant, "data")
	if err != nil {
		t.Fatalf("build spec: %v", err)
	}
	now := time.Now().UTC()
	if err := s.store.Create(ctx, &models.Sandbox{
		ID: "sb-attached", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	if err := s.store.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant:    tenant,
		VolumeID:  v.ID,
		SandboxID: "sb-attached",
		Target:    spec.Target,
		Source:    spec.Source,
	}}); err != nil {
		t.Fatalf("PutVolumeAttachments: %v", err)
	}

	if err := s.DeletePlatformVolume(ctx, v.ID); !errors.Is(err, models.ErrPlatformVolumeInUse) {
		t.Fatalf("delete while attached = %v, want ErrPlatformVolumeInUse", err)
	}

	// Deleting the sandbox row releases the attachment through FK cascade;
	// delete then succeeds.
	if err := s.store.Delete(ctx, "sb-attached"); err != nil {
		t.Fatalf("delete sandbox: %v", err)
	}
	if err := s.DeletePlatformVolume(ctx, v.ID); err != nil {
		t.Fatalf("delete after release: %v", err)
	}
}

func buildVolumeSpecForTest(s *Service, tenant, name string) (models.MountSpec, error) {
	return volumes.BuildMountSpec(backendFromConfig(s.cfg.PlatformVolumes), tenant, name, "/data", false)
}

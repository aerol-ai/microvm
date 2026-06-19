package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// Platform-volume CRUD. The Daytona facade exposes volumes as first-class
// objects (create → id → attach/delete); these methods own that lifecycle in
// the version-agnostic service layer so the facade stays a thin DTO translator.
// E2B's attach-by-name path reuses the same backend + tenant scoping without
// needing an object.

// CreatePlatformVolume creates (or, idempotently, returns) the named volume for
// the calling tenant. Duplicate creates converge on the existing row rather than
// erroring, so the operation is safe under retry and concurrent duplicate calls
// (repo idempotency rule).
func (s *Service) CreatePlatformVolume(ctx context.Context, name string) (*models.Volume, error) {
	if !s.cfg.PlatformVolumes.Enabled {
		return nil, models.ErrPlatformVolumesDisabled
	}
	tenant, err := s.volumeTenant(ctx)
	if err != nil {
		return nil, err
	}
	safeName, err := volumes.SanitizeVolumeName(name)
	if err != nil {
		return nil, err
	}

	// Idempotent: if it already exists, return it instead of failing.
	if existing, err := s.store.GetVolume(ctx, tenant, safeName); err == nil {
		return existing, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// Quota is checked only for genuinely new volumes.
	if cap := s.cfg.PlatformVolumes.MaxPerTenant; cap > 0 {
		count, err := s.store.CountVolumes(ctx, tenant)
		if err != nil {
			return nil, err
		}
		if err := volumes.CheckQuota(count, cap); err != nil {
			return nil, fmt.Errorf("%w: %v", models.ErrPlatformVolumeQuota, err)
		}
	}

	id, err := generateVolumeID()
	if err != nil {
		return nil, err
	}
	v := &models.Volume{ID: id, Tenant: tenant, Name: safeName, Backend: s.cfg.PlatformVolumes.Backend}
	if err := s.store.CreateVolume(ctx, v); err != nil {
		// Lost a race with a concurrent create of the same name — return the winner.
		if errors.Is(err, store.ErrVolumeExists) {
			return s.store.GetVolume(ctx, tenant, safeName)
		}
		return nil, err
	}
	return v, nil
}

// GetPlatformVolume returns the tenant's volume by id, or models.ErrNotFound.
func (s *Service) GetPlatformVolume(ctx context.Context, id string) (*models.Volume, error) {
	if !s.cfg.PlatformVolumes.Enabled {
		return nil, models.ErrPlatformVolumesDisabled
	}
	tenant, err := s.volumeTenant(ctx)
	if err != nil {
		return nil, err
	}
	return s.store.GetVolumeByID(ctx, tenant, id)
}

// GetPlatformVolumeByName returns the tenant's volume by name, or
// models.ErrNotFound. The name is sanitized so lookups match how it was stored.
func (s *Service) GetPlatformVolumeByName(ctx context.Context, name string) (*models.Volume, error) {
	if !s.cfg.PlatformVolumes.Enabled {
		return nil, models.ErrPlatformVolumesDisabled
	}
	tenant, err := s.volumeTenant(ctx)
	if err != nil {
		return nil, err
	}
	safeName, err := volumes.SanitizeVolumeName(name)
	if err != nil {
		return nil, err
	}
	return s.store.GetVolume(ctx, tenant, safeName)
}

// ListPlatformVolumes returns all of the tenant's volumes.
func (s *Service) ListPlatformVolumes(ctx context.Context) ([]models.Volume, error) {
	if !s.cfg.PlatformVolumes.Enabled {
		return nil, models.ErrPlatformVolumesDisabled
	}
	tenant, err := s.volumeTenant(ctx)
	if err != nil {
		return nil, err
	}
	return s.store.ListVolumes(ctx, tenant)
}

// DeletePlatformVolume removes a volume, but only when no live sandbox still has
// it attached — otherwise the backing data would vanish out from under a running
// workload. Returns models.ErrPlatformVolumeInUse (→ 409) when attachers remain,
// models.ErrNotFound when the id is unknown.
//
// NOTE: this deletes the metadata row only. Reclaiming the backing storage (the
// S3 prefix / NFS directory) is an operator/lifecycle concern exercised by the
// integration suite (UC-30); we never delete remote data from the request path.
func (s *Service) DeletePlatformVolume(ctx context.Context, id string) error {
	if !s.cfg.PlatformVolumes.Enabled {
		return models.ErrPlatformVolumesDisabled
	}
	tenant, err := s.volumeTenant(ctx)
	if err != nil {
		return err
	}
	vol, err := s.store.GetVolumeByID(ctx, tenant, id)
	if err != nil {
		return err
	}
	attachers, err := s.platformVolumeAttacherCount(ctx, tenant, vol.Name, vol.Backend)
	if err != nil {
		return err
	}
	if attachers > 0 {
		return fmt.Errorf("%w (%d attached)", models.ErrPlatformVolumeInUse, attachers)
	}
	return s.store.DeleteVolume(ctx, tenant, id)
}

// platformVolumeAttacherCount counts live sandboxes whose mounts include the
// given volume. It recomputes the volume's deterministic backend source and
// compares it against each sandbox's unsealed mount sources — the same source
// string BuildMountSpec produces, so the two can never drift. Destroyed
// sandboxes are skipped (their mounts are gone).
func (s *Service) platformVolumeAttacherCount(ctx context.Context, tenant, name, backend string) (int, error) {
	wantSource, err := volumes.MountSource(volumeBackendFor(s.cfg.PlatformVolumes, backend), tenant, name)
	if err != nil {
		return 0, err
	}
	sandboxes, err := s.store.List(ctx)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, sb := range sandboxes {
		if sb == nil || sb.Status == models.SandboxStatusDestroyed {
			continue
		}
		specs, err := s.loadMounts(ctx, sb.ID)
		if err != nil {
			return 0, err
		}
		for _, spec := range specs {
			if spec.Source == wantSource {
				count++
				break
			}
		}
	}
	return count, nil
}

// volumeTenant resolves the calling tenant's scope segment from the request
// context, falling back to the operator scope for the PAT path.
func (s *Service) volumeTenant(ctx context.Context) (string, error) {
	return volumes.TenantScope(callerFromContext(ctx, s.cfg.PATToken))
}

// volumeBackendFor builds the volumes.Backend for a stored volume's backend.
// Normally it matches the operator's configured backend; we honor the row's
// recorded backend so a volume created under s3 still resolves its source even
// if the operator later reconfigures (best-effort — credentials still come from
// current config).
func volumeBackendFor(p config.PlatformVolumesConfig, rowBackend string) volumes.Backend {
	b := backendFromConfig(p)
	if rowBackend != "" {
		b.Kind = rowBackend
	}
	return b
}

func generateVolumeID() (string, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return "vol-" + hex.EncodeToString(buf), nil
}

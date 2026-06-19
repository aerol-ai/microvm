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

	id, err := generateVolumeID()
	if err != nil {
		return nil, err
	}
	v, _, err := s.store.GetOrCreateVolume(ctx, &models.Volume{ID: id, Tenant: tenant, Name: safeName, Backend: s.cfg.PlatformVolumes.Backend}, s.cfg.PlatformVolumes.MaxPerTenant)
	if err != nil {
		if errors.Is(err, store.ErrVolumeQuotaExceeded) {
			return nil, fmt.Errorf("%w: %v", models.ErrPlatformVolumeQuota, err)
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
// The store writes a pending cleanup ledger row before removing the metadata
// row, so backend bytes retain durable reconciliation coordinates even if a
// request-path cleanup worker or operator lifecycle policy is delayed.
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
	source, err := volumes.MountSource(volumeBackendFor(s.cfg.PlatformVolumes, vol.Backend), tenant, vol.Name)
	if err != nil {
		return err
	}
	if err := s.store.DeleteVolumeIfUnattached(ctx, tenant, id, source); err != nil {
		if errors.Is(err, store.ErrVolumeInUse) {
			return fmt.Errorf("%w: %v", models.ErrPlatformVolumeInUse, err)
		}
		return err
	}
	return nil
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

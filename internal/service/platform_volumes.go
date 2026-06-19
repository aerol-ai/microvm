package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// resolvePlatformVolumes translates req.PlatformVolumes (named, operator-backed
// volumes) into synthesized, tenant-scoped MountSpecs appended to req.Mounts. It
// runs on the create boot path BEFORE the firecracker/wasm dispatch so the
// runtime gate applies to every runtime, and before the mount validation + seal
// + MountAll steps so the synthesized specs ride the existing pipeline (sealing,
// reconcile, docker binds) with no extra persistence code.
//
// Translation lives here, in the version-agnostic service layer, rather than in
// each facade: that keeps operator credentials and the tenant-isolation boundary
// in exactly one place. E2B, Daytona, and the native SDKs only ever fill the
// neutral req.PlatformVolumes field.
//
//	PlatformVolumeMount{name,path}
//	      │  gate: enabled? runtime? quota?
//	      ▼
//	volumes.BuildMountSpec(backend, tenantScope, name, path) → MountSpec{s3|nfs}
//	      ▼  appended to req.Mounts (counts against MaxMountsPerSandbox)
func (s *Service) resolvePlatformVolumes(ctx context.Context, req *models.CreateSandboxRequest, chosenRuntime string) ([]models.VolumeAttachment, error) {
	if len(req.PlatformVolumes) == 0 {
		return nil, nil
	}

	pv := s.cfg.PlatformVolumes
	if !pv.Enabled {
		return nil, models.ErrPlatformVolumesDisabled
	}

	// Runtime gate: firecracker and wasm cannot bind-mount host paths, so a
	// volume would silently never appear. Reject before we do any storage work.
	if chosenRuntime == models.RuntimeFirecracker || chosenRuntime == models.RuntimeWasm {
		return nil, fmt.Errorf("%w (got %q)", models.ErrPlatformVolumesUnsupportedRuntime, chosenRuntime)
	}

	tenant, err := volumes.TenantScope(callerFromContext(ctx, s.cfg.PATToken))
	if err != nil {
		return nil, fmt.Errorf("scope platform volume: %w", err)
	}
	if s.store == nil {
		return nil, errors.New("platform volume store is not configured")
	}

	type resolvedVolume struct {
		vol     *models.Volume
		created bool
	}
	byName := map[string]resolvedVolume{}
	attachments := make([]models.VolumeAttachment, 0, len(req.PlatformVolumes))
	for _, ref := range req.PlatformVolumes {
		safeName, err := volumes.SanitizeVolumeName(ref.Name)
		if err != nil {
			return nil, fmt.Errorf("platform volume %q: %w", ref.Name, err)
		}
		resolved := byName[safeName]
		if resolved.vol == nil {
			id, err := generateVolumeID()
			if err != nil {
				return nil, fmt.Errorf("generate platform volume id: %w", err)
			}
			// Freeze the backend coordinate at creation (see CreatePlatformVolume).
			source, err := volumes.MountSource(backendFromConfig(pv), tenant, safeName)
			if err != nil {
				return nil, fmt.Errorf("platform volume %q: %w", ref.Name, err)
			}
			vol, created, err := s.store.GetOrCreateVolume(ctx, &models.Volume{
				ID:      id,
				Tenant:  tenant,
				Name:    safeName,
				Backend: pv.Backend,
				Source:  source,
			}, pv.MaxPerTenant)
			if err != nil {
				if errors.Is(err, store.ErrVolumeQuotaExceeded) {
					return nil, fmt.Errorf("%w: %v", models.ErrPlatformVolumeQuota, err)
				}
				return nil, err
			}
			resolved = resolvedVolume{vol: vol, created: created}
			byName[safeName] = resolved
		}
		spec, err := mountSpecForVolume(volumeBackendFor(pv, resolved.vol.Backend), resolved.vol, tenant, safeName, ref.Path, ref.ReadOnly)
		if err != nil {
			return nil, fmt.Errorf("platform volume %q: %w", ref.Name, err)
		}
		req.Mounts = append(req.Mounts, spec)
		attachments = append(attachments, models.VolumeAttachment{
			Tenant:        tenant,
			VolumeID:      resolved.vol.ID,
			Target:        spec.Target,
			Source:        spec.Source,
			CreatedVolume: resolved.created,
		})
	}
	return attachments, nil
}

// mountSpecForVolume builds the mount for a resolved volume from its frozen
// source. An existing row's stored source is authoritative so the data mounts
// where it was created even if operator config changed since; only a
// pre-migration row with no stored source falls back to deriving it from the
// current backend config.
func mountSpecForVolume(b volumes.Backend, vol *models.Volume, tenant, safeName, target string, readOnly bool) (models.MountSpec, error) {
	if vol != nil && strings.TrimSpace(vol.Source) != "" {
		return volumes.BuildMountSpecForSource(b, vol.Source, target, readOnly)
	}
	return volumes.BuildMountSpec(b, tenant, safeName, target, readOnly)
}

// ResolvePlatformVolumesForReplication rewrites platform-volume references into
// concrete MountSpecs for the cluster-replicated create spec. That preserves the
// already-resolved tenant prefix across failover/recreate, where there is no
// original user auth context to derive the tenant from. It intentionally does no
// quota or volume-row writes; createSandbox already did those before the sandbox
// was admitted.
func (s *Service) ResolvePlatformVolumesForReplication(ctx context.Context, req *models.CreateSandboxRequest) error {
	if req == nil || len(req.PlatformVolumes) == 0 {
		return nil
	}
	pv := s.cfg.PlatformVolumes
	if !pv.Enabled {
		return models.ErrPlatformVolumesDisabled
	}
	if s.store == nil {
		return errors.New("platform volume store is not configured")
	}
	tenant, err := volumes.TenantScope(callerFromContext(ctx, s.cfg.PATToken))
	if err != nil {
		return fmt.Errorf("scope platform volume for replication: %w", err)
	}
	for _, ref := range req.PlatformVolumes {
		safeName, err := volumes.SanitizeVolumeName(ref.Name)
		if err != nil {
			return fmt.Errorf("platform volume %q: %w", ref.Name, err)
		}
		vol, err := s.store.GetVolume(ctx, tenant, safeName)
		if err != nil {
			return fmt.Errorf("get platform volume %q for replication: %w", ref.Name, err)
		}
		spec, err := mountSpecForVolume(volumeBackendFor(pv, vol.Backend), vol, tenant, safeName, ref.Path, ref.ReadOnly)
		if err != nil {
			return fmt.Errorf("platform volume %q: %w", ref.Name, err)
		}
		req.Mounts = append(req.Mounts, spec)
	}
	req.PlatformVolumes = nil
	return nil
}

func (s *Service) cleanupCreatedPlatformVolumes(ctx context.Context, attachments []models.VolumeAttachment) {
	if s.store == nil || len(attachments) == 0 {
		return
	}
	seen := map[string]struct{}{}
	for _, a := range attachments {
		if !a.CreatedVolume {
			continue
		}
		key := a.Tenant + "\x00" + a.VolumeID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if err := s.store.DeleteVolumeIfUnattached(ctx, a.Tenant, a.VolumeID, a.Source); err != nil &&
			!errors.Is(err, store.ErrNotFound) &&
			!errors.Is(err, store.ErrVolumeInUse) {
			if s.logger != nil {
				s.logger.Warn("cleanup platform volume created by failed sandbox create failed",
					"volume_id", a.VolumeID, "tenant", a.Tenant, "err", err)
			}
		}
	}
}

// callerFromContext maps the authenticated request context to the tenant
// identity volumes.TenantScope needs. Background/internal calls (no auth edge)
// surface as HasAccess=false and fall back to the operator-token scope.
func callerFromContext(ctx context.Context, patToken string) volumes.Caller {
	access, ok := controlplane.AccessFromContext(ctx)
	return volumes.Caller{
		OwnerRef:  access.Identity.OwnerRef,
		Operator:  access.Operator,
		HasAccess: ok,
		PATToken:  patToken,
	}
}

// backendFromConfig adapts the operator config into the pure volumes.Backend
// the translation layer consumes (volumes deliberately does not import config).
func backendFromConfig(p config.PlatformVolumesConfig) volumes.Backend {
	return volumes.Backend{
		Kind:              p.Backend,
		S3Bucket:          p.S3Bucket,
		S3Prefix:          p.S3Prefix,
		S3Region:          p.S3Region,
		S3Endpoint:        p.S3Endpoint,
		S3AccessKeyID:     p.S3AccessKeyID,
		S3SecretAccessKey: p.S3SecretAccessKey,
		NFSServer:         p.NFSServer,
		NFSExport:         p.NFSExport,
		NFSOptions:        p.NFSOptions,
	}
}

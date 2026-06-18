package service

import (
	"context"
	"fmt"

	"github.com/aerol-ai/microvm/internal/config"
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
func (s *Service) resolvePlatformVolumes(ctx context.Context, req *models.CreateSandboxRequest, chosenRuntime string) error {
	if len(req.PlatformVolumes) == 0 {
		return nil
	}

	pv := s.cfg.PlatformVolumes
	if !pv.Enabled {
		return models.ErrPlatformVolumesDisabled
	}

	// Runtime gate: firecracker and wasm cannot bind-mount host paths, so a
	// volume would silently never appear. Reject before we do any storage work.
	if chosenRuntime == models.RuntimeFirecracker || chosenRuntime == models.RuntimeWasm {
		return fmt.Errorf("%w (got %q)", models.ErrPlatformVolumesUnsupportedRuntime, chosenRuntime)
	}

	tenant, err := volumes.TenantScope(callerFromContext(ctx, s.cfg.PATToken))
	if err != nil {
		return fmt.Errorf("scope platform volume: %w", err)
	}

	// Quota: a tenant's existing volume count plus the new ones in this request
	// must not exceed the configured cap. existingPlatformVolumeCount returns 0
	// until the volumes store table lands (T4); within-request enforcement holds
	// regardless so a single create can never blow the cap.
	existing, err := s.existingPlatformVolumeCount(ctx, tenant)
	if err != nil {
		return fmt.Errorf("count platform volumes: %w", err)
	}

	backend := backendFromConfig(pv)
	for i, ref := range req.PlatformVolumes {
		if err := volumes.CheckQuota(existing+i, pv.MaxPerTenant); err != nil {
			return fmt.Errorf("%w: %v", models.ErrPlatformVolumeQuota, err)
		}
		spec, err := volumes.BuildMountSpec(backend, tenant, ref.Name, ref.Path, ref.ReadOnly)
		if err != nil {
			return fmt.Errorf("platform volume %q: %w", ref.Name, err)
		}
		req.Mounts = append(req.Mounts, spec)
	}
	return nil
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

// existingPlatformVolumeCount returns how many distinct volumes the tenant
// already has, for cross-request quota enforcement.
//
// TODO(T4): query the `volumes` store table once it exists. Until then this
// returns 0, so only within-request quota is enforced (a single create cannot
// exceed the cap). Cross-request total enforcement lands with the store table.
func (s *Service) existingPlatformVolumeCount(_ context.Context, _ string) (int, error) {
	return 0, nil
}

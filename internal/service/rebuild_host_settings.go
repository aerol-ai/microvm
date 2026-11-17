package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// A node that rebuilds a sandbox it never had (failover recreate, a stuck
// placement moved here, a move, a WASM import) runs that create without
// host powers (cluster/rebuild_refusal.go says why). This is the node's
// check, with its own volume and module configuration, before it creates
// anything:
//
//	mounts         each must be one of the sandbox's own platform volumes:
//	               one the cluster's volume records attach to this sandbox,
//	               of its tenant (or, for an operator's sandbox, of an
//	               operator scope), at the location the volume's record froze
//	               when it was made (volumes.PlatformMountFromRecord); for a
//	               sandbox with no such record, the location this node's
//	               configuration gives (volumes.PlatformMountFor). It is
//	               mounted with this node's backend options. Any other mount
//	               is refused.
//	module_ref     a WASM module from a host path, or a JS bundle from a
//	               file, is refused (the resolver would refuse it anyway
//	               under WithHostPathsDenied; this says why first).
//	custom domains only the hostnames the cluster already binds to this
//	               sandbox are kept (no DNS proof is asked for them again);
//	               the rest are dropped, as a new owner can prove nothing.
//
// A refusal is cluster.ErrHostOnlySpec, which the owner watcher treats as
// permanent for this node.

type rebuiltSpecKey struct{}

// rebuildContext marks ctx for the create of a rebuilt sandbox: no host
// powers, no module from a host path, and the spec's mounts and custom
// domains as rebuildSpecWithoutHostPowers left them, which createSandbox
// then takes without asking for host powers or a DNS proof.
func rebuildContext(ctx context.Context) context.Context {
	ctx = controlplane.ContextWithoutHostPowers(ctx)
	ctx = wasmmod.WithHostPathsDenied(ctx)
	return context.WithValue(ctx, rebuiltSpecKey{}, true)
}

// isRebuiltSpec reports whether ctx is a rebuildContext.
func isRebuiltSpec(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(rebuiltSpecKey{}).(bool)
	return v
}

// hostPathRefChecker is the optional half of WasmModuleResolver that tells
// a module read from a host path apart without resolving it
// (wasmmod.ModuleResolver).
type hostPathRefChecker interface {
	HostPathRef(ctx context.Context, ref string) bool
}

// rebuildSpecWithoutHostPowers returns spec as this node may rebuild
// sandbox id from it (see above), or cluster.ErrHostOnlySpec naming what
// it cannot take.
func (s *Service) rebuildSpecWithoutHostPowers(ctx context.Context, id string, spec models.CreateSandboxRequest) (models.CreateSandboxRequest, error) {
	ownerRef := s.tenantOwnerRefForRecreate(ctx, id)
	placement := cluster.Placement{SandboxID: id, OwnerRef: ownerRef, Spec: &spec}
	var held []string
	incarnation := ""
	if c := s.Cluster(); c != nil {
		if p, ok := c.PlacementOf(id); ok {
			held, incarnation = p.CustomHostnames, strings.TrimSpace(p.IncarnationID)
		}
	}
	refused := cluster.HostOnlySettings(placement)
	if len(spec.Mounts) > 0 && !slices.Contains(refused, "mounts") {
		mounts, ok, err := s.rebuildPlatformMounts(ctx, id, incarnation, ownerRef, spec.Mounts)
		switch {
		case err != nil:
			// The records could not be read: not a refusal, the owner
			// watcher tries again.
			return spec, err
		case ok:
			spec.Mounts = mounts
		default:
			refused = append(refused, "mounts")
		}
	}
	if strings.TrimSpace(spec.Runtime) == models.RuntimeWasm && !slices.Contains(refused, "module_ref") {
		if hp, ok := s.wasmModuleResolver.(hostPathRefChecker); ok &&
			hp.HostPathRef(wasmmod.WithCatalogueOwner(ctx, ownerRef), models.ModuleRefForCreate(spec)) {
			refused = append(refused, "module_ref")
		}
	}
	if len(refused) > 0 {
		return spec, fmt.Errorf("%w: %s", cluster.ErrHostOnlySpec, strings.Join(refused, ", "))
	}
	if len(spec.CustomDomains) > 0 {
		kept := make([]string, 0, len(spec.CustomDomains))
		for _, h := range spec.CustomDomains {
			if slices.Contains(held, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))) {
				kept = append(kept, h)
				continue
			}
			if s.logger != nil {
				s.logger.Warn("cluster: rebuilding a sandbox without a custom hostname the cluster no longer binds to it",
					"sandbox_id", id, "hostname", h)
			}
		}
		spec.CustomDomains = kept
	}
	return spec, nil
}

// rebuildPlatformMounts maps every mount of sandbox id to the platform
// volume of its owner it stands for, as this node mounts it. ok is false
// when one is not such a volume, or this node serves none; err is a volume
// record that could not be read.
//
// The volume's record comes first: it holds the location the volume was
// made at and its own tenant, so a volume made before the operator changed
// the bucket, prefix or export, and an operator's volume on a node with no
// operator token or pinned scope, rebuild here too. Only a mount with no
// record (a sandbox from before the cluster kept them) falls back to the
// location this node's configuration gives.
func (s *Service) rebuildPlatformMounts(ctx context.Context, id, incarnation, ownerRef string, mounts []models.MountSpec) ([]models.MountSpec, bool, error) {
	pv := s.cfg.PlatformVolumes
	if !pv.Enabled {
		return nil, false, nil
	}
	b := backendFromConfig(pv)
	tenant := volumes.TenantForOwnerRef(ownerRef)
	atts, err := s.volumeMeta().AttachmentsForSandbox(ctx, id)
	if err != nil {
		return nil, false, fmt.Errorf("cluster: read the sandbox's volume attachments: %w", err)
	}
	out := make([]models.MountSpec, 0, len(mounts))
	for _, m := range mounts {
		rebuilt, found, err := s.platformMountFromRecord(ctx, b, tenant, incarnation, atts, m)
		if err != nil {
			return nil, false, err
		}
		if !found {
			scope := tenant
			if scope == "" {
				if scope, err = volumes.OperatorScope(s.cfg.OperatorVolumeScope, s.cfg.PATToken); err != nil {
					return nil, false, nil
				}
			}
			if rebuilt, found = volumes.PlatformMountFor(b, scope, m); !found {
				return nil, false, nil
			}
		}
		out = append(out, rebuilt)
	}
	return out, true, nil
}

// platformMountFromRecord is m as the volume record attached to this
// sandbox at m's source and target builds it. found is false when no
// attachment of this incarnation names m, or its volume is gone.
func (s *Service) platformMountFromRecord(ctx context.Context, b volumes.Backend, tenant, incarnation string, atts []models.VolumeAttachment, m models.MountSpec) (models.MountSpec, bool, error) {
	for _, att := range atts {
		if att.Source != m.Source || att.Target != m.Target {
			continue
		}
		if incarnation != "" && att.IncarnationID != "" && att.IncarnationID != incarnation {
			continue
		}
		vol, err := s.volumeMeta().ByID(ctx, att.Tenant, att.VolumeID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return models.MountSpec{}, false, fmt.Errorf("cluster: read platform volume %s: %w", att.VolumeID, err)
		}
		if out, ok := volumes.PlatformMountFromRecord(b, tenant, *vol, att, m); ok {
			return out, true, nil
		}
	}
	return models.MountSpec{}, false, nil
}

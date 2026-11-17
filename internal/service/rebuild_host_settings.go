package service

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
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
//	mounts         each must be one of the sandbox's own platform volumes on
//	               this node's backend; it is mounted as this node builds it
//	               (volumes.PlatformMountFor). Any other mount is refused.
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
	if c := s.Cluster(); c != nil {
		if p, ok := c.PlacementOf(id); ok {
			held = p.CustomHostnames
		}
	}
	refused := cluster.HostOnlySettings(placement)
	if len(spec.Mounts) > 0 && !slices.Contains(refused, "mounts") {
		mounts, ok := s.rebuildPlatformMounts(ownerRef, spec.Mounts)
		if ok {
			spec.Mounts = mounts
		} else {
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

// rebuildPlatformMounts maps every mount to the platform volume of the
// sandbox's owner it stands for, as this node builds it. ok is false when
// one is not such a volume, or this node serves none.
func (s *Service) rebuildPlatformMounts(ownerRef string, mounts []models.MountSpec) ([]models.MountSpec, bool) {
	pv := s.cfg.PlatformVolumes
	if !pv.Enabled {
		return nil, false
	}
	tenant := volumes.TenantForOwnerRef(ownerRef)
	if tenant == "" {
		scope, err := volumes.OperatorScope(s.cfg.OperatorVolumeScope, s.cfg.PATToken)
		if err != nil {
			return nil, false
		}
		tenant = scope
	}
	b := backendFromConfig(pv)
	out := make([]models.MountSpec, 0, len(mounts))
	for _, m := range mounts {
		rebuilt, ok := volumes.PlatformMountFor(b, tenant, m)
		if !ok {
			return nil, false
		}
		out = append(out, rebuilt)
	}
	return out, true
}

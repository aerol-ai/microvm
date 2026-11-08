package service

import (
	"context"
	"errors"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func allowPublicTrafficEnabled(v *bool) bool {
	return v != nil && *v
}

func sandboxAllowsPublicTraffic(sandbox *models.Sandbox) bool {
	return sandbox != nil && allowPublicTrafficEnabled(sandbox.AllowPublicTraffic)
}

// placementAllowsPublicTraffic reads the hot-row flag first: an ingress-only
// node only ever sees redacted placements with no Spec (see
// cluster.Placement.PublicTraffic). Spec still decides when present, which
// keeps rows written by older builds behaving as they did.
func placementAllowsPublicTraffic(p cluster.Placement) bool {
	if p.PublicTraffic {
		return true
	}
	if p.Spec == nil {
		return false
	}
	return allowPublicTrafficEnabled(p.Spec.AllowPublicTraffic)
}

func (s *Service) sandboxPublicURL(id string, allowPublicTraffic *bool) string {
	if !allowPublicTrafficEnabled(allowPublicTraffic) || s == nil || s.caddy == nil {
		return ""
	}
	return s.caddy.SandboxPublicURL(id)
}

// syncSandboxPublicRoute writes the sandbox's root route and its custom-domain
// routes, or deletes them for a private sandbox. A custom domain that dials an
// app port is a way into that port around its token gate, so when sandbox has
// one, the domains written are the ones stored now, read under
// customDomainRouteLocks (route_gate.go): reconcile or a start may hold a
// copy with a domain that was removed before the port became gated. Domains
// that all dial the toolbox (every create-time domain) skip the read and the
// lock.
func (s *Service) syncSandboxPublicRoute(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil || sandbox.ID == "" || s == nil || s.caddy == nil {
		return nil
	}
	if !sandboxAllowsPublicTraffic(sandbox) {
		return s.deleteSandboxPublicRoutes(ctx, sandbox)
	}
	if !hasPortCustomDomain(sandbox) {
		return s.writeSandboxPublicRoute(ctx, sandbox)
	}
	unlock := s.customDomainRouteLocks.lock(sandbox.ID)
	defer unlock()
	return s.syncSandboxPublicRouteHeld(ctx, sandbox)
}

// syncSandboxPublicRouteHeld is syncSandboxPublicRoute for a caller that
// holds customDomainRouteLocks for the sandbox (AddCustomDomain,
// RemoveCustomDomain). It always writes the stored domains.
func (s *Service) syncSandboxPublicRouteHeld(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil || sandbox.ID == "" || s == nil || s.caddy == nil {
		return nil
	}
	if !sandboxAllowsPublicTraffic(sandbox) {
		return s.deleteSandboxPublicRoutes(ctx, sandbox)
	}
	current, err := s.withCurrentCustomDomains(ctx, sandbox)
	if err != nil {
		return err
	}
	return s.writeSandboxPublicRoute(ctx, current)
}

// writeSandboxPublicRoute writes the root route and the custom-domain routes
// in the shape the ownership fence asks for: while this node cannot confirm
// it still owns the sandbox (it is paused), every one of those URLs answers
// 503 instead of proxying to a process that will not answer. The fence is
// read under rootRouteLocks, which the fence's own swap also takes (via
// syncSandboxPublicRoute), so a reconcile or start that read the fence just
// before it went up cannot land its live route after the 503.
func (s *Service) writeSandboxPublicRoute(ctx context.Context, sandbox *models.Sandbox) error {
	unlock := s.rootRouteLocks.lock(sandbox.ID)
	defer unlock()
	if s.OwnershipFenced(sandbox.ID) {
		return s.publicRoutes().UpsertFencedSandboxRoute(ctx, sandbox.ID, sandboxCustomHostnamesList(sandbox))
	}
	return s.publicRoutes().UpsertSandboxRoute(ctx, sandbox.ID, sandbox.ContainerIP, s.cfg.ToolboxPort, sandboxCustomHostnames(sandbox))
}

// enableSandboxPublicTraffic flips a private sandbox to public in place:
// installs the root <id>.<domain> route, persists flag + public_url in one
// store write, and mirrors the flip into the FSM-replicated spec so a
// failover recreate keeps the sandbox public even if every port is later
// unexposed. expose_port is the only caller — asking for a public port IS
// the opt-in (there is no standalone flag-update endpoint).
//
// Caddy-first on purpose: a crash between the route install and the store
// write leaves a route for a still-private row, which the reconcile sweep
// (cleanupPublicTrafficDisabledIngressState) removes; the reverse order
// would leave a stored-public sandbox with a dead public_url and no repair
// pass. On a store failure the route is rolled back so caddy and the store
// never disagree past this function. Safe under concurrent duplicates: the
// route install is an upsert and the store write is an absolute SET.
func (s *Service) enableSandboxPublicTraffic(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil || sandbox.ID == "" || sandboxAllowsPublicTraffic(sandbox) {
		return nil
	}
	public := true
	sandbox.AllowPublicTraffic = &public
	if err := s.syncSandboxPublicRoute(ctx, sandbox); err != nil {
		private := false
		sandbox.AllowPublicTraffic = &private
		return err
	}
	publicURL := s.sandboxPublicURL(sandbox.ID, sandbox.AllowPublicTraffic)
	if s.store != nil {
		if err := s.store.SetAllowPublicTraffic(ctx, sandbox.ID, true, publicURL); err != nil {
			_ = s.deleteSandboxPublicRoutes(ctx, sandbox)
			private := false
			sandbox.AllowPublicTraffic = &private
			return err
		}
	}
	sandbox.PublicURL = publicURL
	s.replicateSpecPatch(ctx, sandbox.ID, func(spec *models.CreateSandboxRequest) {
		spec.AllowPublicTraffic = &public
	})
	return nil
}

func (s *Service) deleteSandboxPublicRoutes(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil || sandbox.ID == "" || s == nil || s.caddy == nil {
		return nil
	}
	var firstErr error
	if err := s.publicRoutes().DeleteSandboxRoute(ctx, sandbox.ID); err != nil {
		firstErr = err
	}
	for _, cd := range sandbox.CustomDomains {
		if cd.Hostname == "" {
			continue
		}
		if err := s.publicRoutes().DeleteCustomDomainHTTPRoute(ctx, sandbox.ID, cd.Hostname); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Service) syncExposedPortRoute(ctx context.Context, sandbox *models.Sandbox, port models.ExposedPort) error {
	if !sandboxAllowsPublicTraffic(sandbox) {
		return s.deleteExposedPortRoute(ctx, sandbox, port)
	}
	return s.upsertExposedPortRoute(ctx, sandbox, port)
}

func (s *Service) cleanupPublicTrafficDisabledIngressState(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil || sandbox.ID == "" || sandboxAllowsPublicTraffic(sandbox) {
		return nil
	}
	var firstErr error
	if err := s.deleteSandboxPublicRoutes(ctx, sandbox); err != nil {
		firstErr = err
	}
	for _, port := range sandbox.ExposedPorts {
		if s.caddy != nil {
			if err := s.deleteExposedPortRoute(ctx, sandbox, port); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if s.store != nil {
			if err := s.store.DeletePort(ctx, sandbox.ID, port.Port); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := s.removeClusterExposedPort(ctx, sandbox.ID, port.Port); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, cd := range sandbox.CustomDomains {
		if cd.Hostname == "" {
			continue
		}
		if s.store != nil {
			if err := s.store.RemoveCustomDomain(ctx, sandbox.ID, cd.Hostname); err != nil && !errors.Is(err, store.ErrNotFound) && firstErr == nil {
				firstErr = err
			}
		}
		if err := s.removeClusterCustomDomain(ctx, sandbox.ID, cd.Hostname); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		sandbox.ExposedPorts = nil
		sandbox.CustomDomains = nil
	}
	return firstErr
}

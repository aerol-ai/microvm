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

func placementAllowsPublicTraffic(p cluster.Placement) bool {
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

func (s *Service) syncSandboxPublicRoute(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil || sandbox.ID == "" || s == nil || s.caddy == nil {
		return nil
	}
	if !sandboxAllowsPublicTraffic(sandbox) {
		return s.deleteSandboxPublicRoutes(ctx, sandbox)
	}
	return s.caddy.UpsertSandboxRoute(ctx, sandbox.ID, sandbox.ContainerIP, s.cfg.ToolboxPort, sandboxCustomHostnames(sandbox))
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
	if err := s.caddy.DeleteSandboxRoute(ctx, sandbox.ID); err != nil {
		firstErr = err
	}
	for _, cd := range sandbox.CustomDomains {
		if cd.Hostname == "" {
			continue
		}
		if err := s.caddy.DeleteCustomDomainHTTPRoute(ctx, sandbox.ID, cd.Hostname); err != nil && firstErr == nil {
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

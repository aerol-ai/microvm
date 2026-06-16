package service

import (
	"context"
	"errors"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func allowPublicTrafficEnabled(v *bool) bool {
	return v == nil || *v
}

func sandboxAllowsPublicTraffic(sandbox *models.Sandbox) bool {
	return sandbox == nil || allowPublicTrafficEnabled(sandbox.AllowPublicTraffic)
}

func placementAllowsPublicTraffic(p cluster.Placement) bool {
	if p.Spec == nil {
		return true
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

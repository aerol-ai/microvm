package service

import (
	"context"
	"fmt"

	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func (s *Service) isolatePortGateway() (isolateruntime.PortGateway, error) {
	if s.isolate == nil {
		return nil, fmt.Errorf("runtime %q: driver not registered: %w",
			models.RuntimeIsolate, models.ErrRuntimeNotImplemented)
	}
	pg, ok := isolateruntime.AsPortGateway(s.isolate)
	if !ok {
		return nil, fmt.Errorf("runtime %q: port gateway not available", models.RuntimeIsolate)
	}
	return pg, nil
}

func (s *Service) isolateHTTPDial(ctx context.Context, sandboxID string, guestPort int) (string, error) {
	pg, err := s.isolatePortGateway()
	if err != nil {
		return "", err
	}
	return pg.EnsureHTTPListener(ctx, sandboxID, guestPort)
}

func (s *Service) isolateHTTPUpstreamURL(ctx context.Context, sandboxID string, guestPort int) (string, error) {
	dial, err := s.isolateHTTPDial(ctx, sandboxID, guestPort)
	if err != nil {
		return "", err
	}
	return "http://" + dial, nil
}

func (s *Service) releaseIsolateHTTPListener(sandboxID string, guestPort int) {
	pg, err := s.isolatePortGateway()
	if err != nil {
		return
	}
	pg.ReleaseHTTPListener(sandboxID, guestPort)
}

func (s *Service) syncIsolateAllowedPorts(ctx context.Context, sandbox *models.Sandbox) {
	if sandbox == nil {
		return
	}
	pg, err := s.isolatePortGateway()
	if err != nil {
		return
	}
	ports := make([]int, 0, len(sandbox.ExposedPorts))
	for _, p := range sandbox.ExposedPorts {
		ports = append(ports, p.Port)
	}
	pg.SyncAllowedPorts(sandbox.ID, ports)
}

func (s *Service) installIsolateHTTPPortRoute(ctx context.Context, sandbox *models.Sandbox, guestPort int) error {
	dial, err := s.isolateHTTPDial(ctx, sandbox.ID, guestPort)
	if err != nil {
		return err
	}
	routeOpts := caddy.HTTPRouteOptions{MaskRequestHost: sandbox.MaskRequestHost}
	switch s.chooseRouteShape(sandbox, RouteKindHTTP) {
	case RouteShapeDirect:
		if err := s.caddy.UpsertPortRouteWithDial(ctx, sandbox.ID, guestPort, dial, routeOpts); err != nil {
			// isolateHTTPDial opened the loopback listener above; a failed caddy
			// upsert leaves no route pointing at it, so release it rather than
			// orphan the listener + goroutine (pr-review.md §4).
			s.releaseIsolateHTTPListener(sandbox.ID, guestPort)
			return err
		}
		_ = s.caddy.DeleteWakeHTTPPortRoute(ctx, sandbox.ID, guestPort)
		return nil
	case RouteShapeWake:
		if err := s.caddy.UpsertWakeHTTPPortRoute(ctx, sandbox.ID, s.cfg.InternalIngressAddr, guestPort); err != nil {
			s.releaseIsolateHTTPListener(sandbox.ID, guestPort)
			return err
		}
		_ = s.caddy.DeletePortRoute(ctx, sandbox.ID, guestPort)
		return nil
	case RouteShapeNone:
		_ = s.caddy.DeletePortRoute(ctx, sandbox.ID, guestPort)
		_ = s.caddy.DeleteWakeHTTPPortRoute(ctx, sandbox.ID, guestPort)
		return nil
	}
	return nil
}

func (s *Service) isolateHTTPPortRouteCleanup(ctx context.Context, sandboxID string, guestPort int) {
	_ = s.caddy.DeletePortRoute(ctx, sandboxID, guestPort)
	_ = s.caddy.DeleteWakeHTTPPortRoute(ctx, sandboxID, guestPort)
	s.releaseIsolateHTTPListener(sandboxID, guestPort)
}

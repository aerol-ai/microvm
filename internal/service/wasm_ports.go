package service

import (
	"context"
	"fmt"

	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/models"
)

func (s *Service) wasmPortGateway() (wasmruntime.PortGateway, error) {
	if s.wasm == nil {
		return nil, fmt.Errorf("runtime %q: driver not registered: %w",
			models.RuntimeWasm, models.ErrRuntimeNotImplemented)
	}
	pg, ok := wasmruntime.AsPortGateway(s.wasm)
	if !ok {
		return nil, fmt.Errorf("runtime %q: port gateway not available", models.RuntimeWasm)
	}
	return pg, nil
}

func (s *Service) wasmHTTPDial(ctx context.Context, sandboxID string, guestPort int) (string, error) {
	pg, err := s.wasmPortGateway()
	if err != nil {
		return "", err
	}
	return pg.EnsureHTTPListener(ctx, sandboxID, guestPort)
}

func (s *Service) wasmHTTPUpstreamURL(ctx context.Context, sandboxID string, guestPort int) (string, error) {
	dial, err := s.wasmHTTPDial(ctx, sandboxID, guestPort)
	if err != nil {
		return "", err
	}
	return "http://" + dial, nil
}

func (s *Service) releaseWasmHTTPListener(sandboxID string, guestPort int) {
	pg, err := s.wasmPortGateway()
	if err != nil {
		return
	}
	pg.ReleaseHTTPListener(sandboxID, guestPort)
}

func (s *Service) syncWasmAllowedPorts(ctx context.Context, sandbox *models.Sandbox) {
	if sandbox == nil {
		return
	}
	pg, err := s.wasmPortGateway()
	if err != nil {
		return
	}
	ports := make([]int, 0, len(sandbox.ExposedPorts))
	for _, p := range sandbox.ExposedPorts {
		ports = append(ports, p.Port)
	}
	pg.SyncAllowedPorts(sandbox.ID, ports)
	if syncer, ok := s.wasm.(wasmruntime.GuestListenPortSyncer); ok {
		if err := syncer.SyncGuestListenPorts(ctx, sandbox.ID, ports); err != nil {
			s.logger.Warn("failed to sync wasm guest listen ports", "sandbox_id", sandbox.ID, "error", err)
		}
	}
	if err := s.syncWasmCustomDomainRoutes(ctx, sandbox); err != nil {
		s.logger.Warn("failed to sync wasm custom-domain routes", "sandbox_id", sandbox.ID, "error", err)
	}
}

func (s *Service) installWasmHTTPPortRoute(ctx context.Context, sandbox *models.Sandbox, guestPort int) error {
	dial, err := s.wasmHTTPDial(ctx, sandbox.ID, guestPort)
	if err != nil {
		return err
	}
	switch s.chooseRouteShape(sandbox, RouteKindHTTP) {
	case RouteShapeDirect:
		if err := s.caddy.UpsertPortRouteWithDial(ctx, sandbox.ID, guestPort, dial); err != nil {
			return err
		}
		_ = s.caddy.DeleteWakeHTTPPortRoute(ctx, sandbox.ID, guestPort)
		return nil
	case RouteShapeWake:
		if err := s.caddy.UpsertWakeHTTPPortRoute(ctx, sandbox.ID, s.cfg.InternalIngressAddr, guestPort); err != nil {
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

// wasmHTTPPortRouteCleanup drops caddy routes and the host listener for one port.
func (s *Service) wasmHTTPPortRouteCleanup(ctx context.Context, sandboxID string, guestPort int) {
	_ = s.caddy.DeletePortRoute(ctx, sandboxID, guestPort)
	_ = s.caddy.DeleteWakeHTTPPortRoute(ctx, sandboxID, guestPort)
	s.releaseWasmHTTPListener(sandboxID, guestPort)
}

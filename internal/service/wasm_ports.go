package service

import (
	"context"
	"fmt"

	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/caddy"
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

// syncWasmAllowedPorts pushes the sandbox's exposed ports to the WASM
// gateway's allowed set and the guest's listeners. Like the container path
// (syncAllowedPorts) it reads the ports from the store under allowlistLocks:
// two exposes at once each pushed the ports of the row they had read
// earlier, and the later push of an older row dropped the other's port from
// both. The listener sync stays under the lock too, so a sandbox's guest is
// re-instantiated by one sync at a time.
func (s *Service) syncWasmAllowedPorts(ctx context.Context, sandbox *models.Sandbox) {
	if sandbox == nil {
		return
	}
	pg, err := s.wasmPortGateway()
	if err != nil {
		return
	}
	unlock := s.allowlistLocks.lock(sandbox.ID)
	exposed := sandbox.ExposedPorts
	if s.store != nil {
		if exposed, err = s.store.ListPorts(ctx, sandbox.ID); err != nil {
			unlock()
			// Push nothing rather than the old copy; the next push fixes it.
			s.logger.Warn("wasm allowed ports not synced: could not read the exposed ports", "sandbox_id", sandbox.ID, "error", err)
			return
		}
	}
	s.afterRouteGateRead(gateReadAllowlist)
	ports := make([]int, 0, len(exposed))
	for _, p := range exposed {
		ports = append(ports, p.Port)
	}
	pg.SyncAllowedPorts(sandbox.ID, ports)
	if syncer, ok := s.wasm.(wasmruntime.GuestListenPortSyncer); ok {
		if err := syncer.SyncGuestListenPorts(ctx, sandbox.ID, ports); err != nil {
			s.logger.Warn("failed to sync wasm guest listen ports", "sandbox_id", sandbox.ID, "error", err)
		}
	}
	unlock()
	if err := s.syncWasmCustomDomainRoutes(ctx, sandbox); err != nil {
		s.logger.Warn("failed to sync wasm custom-domain routes", "sandbox_id", sandbox.ID, "error", err)
	}
}

func (s *Service) installWasmHTTPPortRoute(ctx context.Context, sandbox *models.Sandbox, guestPort int) error {
	dial, err := s.wasmHTTPDial(ctx, sandbox.ID, guestPort)
	if err != nil {
		return err
	}
	routeOpts := caddy.HTTPRouteOptions{MaskRequestHost: sandbox.MaskRequestHost}
	switch s.chooseRouteShape(sandbox, RouteKindHTTP) {
	case RouteShapeDirect:
		if err := s.publicRoutes().UpsertPortRouteWithDial(ctx, sandbox.ID, guestPort, dial, routeOpts); err != nil {
			return err
		}
		_ = s.publicRoutes().DeleteWakeHTTPPortRoute(ctx, sandbox.ID, guestPort)
		return nil
	case RouteShapeWake:
		if err := s.publicRoutes().UpsertWakeHTTPPortRoute(ctx, sandbox.ID, s.cfg.InternalIngressAddr, guestPort); err != nil {
			return err
		}
		_ = s.publicRoutes().DeletePortRoute(ctx, sandbox.ID, guestPort)
		return nil
	case RouteShapeNone:
		_ = s.publicRoutes().DeletePortRoute(ctx, sandbox.ID, guestPort)
		_ = s.publicRoutes().DeleteWakeHTTPPortRoute(ctx, sandbox.ID, guestPort)
		return nil
	}
	return nil
}

// wasmHTTPPortRouteCleanup drops caddy routes and the host listener for one port.
func (s *Service) wasmHTTPPortRouteCleanup(ctx context.Context, sandboxID string, guestPort int) {
	_ = s.publicRoutes().DeletePortRoute(ctx, sandboxID, guestPort)
	_ = s.publicRoutes().DeleteWakeHTTPPortRoute(ctx, sandboxID, guestPort)
	s.releaseWasmHTTPListener(sandboxID, guestPort)
}

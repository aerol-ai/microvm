package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ErrWasmCustomDomainPortNotExposed is returned when a WASM sandbox custom
// domain targets a guest HTTP port that is not exposed while other HTTP ports
// already are. Attaching before the first expose_port is allowed.
var ErrWasmCustomDomainPortNotExposed = errors.New("wasm custom domain target_port is not an exposed http port")

func wasmExposedHTTPPorts(sandbox *models.Sandbox) []int {
	if sandbox == nil {
		return nil
	}
	out := make([]int, 0, len(sandbox.ExposedPorts))
	for _, ep := range sandbox.ExposedPorts {
		switch ep.Protocol {
		case "", models.ExposedPortProtocolHTTP:
			out = append(out, ep.Port)
		}
	}
	return out
}

func (s *Service) validateWasmCustomDomainTargetPort(sandbox *models.Sandbox, targetPort int) error {
	if targetPort <= 0 {
		return nil
	}
	exposed := wasmExposedHTTPPorts(sandbox)
	if len(exposed) == 0 {
		return nil
	}
	for _, p := range exposed {
		if p == targetPort {
			return nil
		}
	}
	return ErrWasmCustomDomainPortNotExposed
}

func (s *Service) wasmCustomDomainDial(ctx context.Context, sandbox *models.Sandbox, targetPort int) (string, error) {
	if sandbox == nil {
		return "", fmt.Errorf("sandbox is nil")
	}
	if targetPort <= 0 {
		return fmt.Sprintf("%s:%d", sandbox.ContainerIP, s.cfg.ToolboxPort), nil
	}
	if err := s.validateWasmCustomDomainTargetPort(sandbox, targetPort); err != nil {
		return "", err
	}
	return s.wasmHTTPDial(ctx, sandbox.ID, targetPort)
}

func (s *Service) installWasmCustomDomainHTTPRoute(ctx context.Context, sandbox *models.Sandbox, hostname string, targetPort int) error {
	dial, err := s.wasmCustomDomainDial(ctx, sandbox, targetPort)
	if err != nil {
		return err
	}
	routeOpts := caddy.HTTPRouteOptions{}
	if targetPort > 0 {
		routeOpts.MaskRequestHost = sandbox.MaskRequestHost
	}
	return s.caddy.UpsertCustomDomainHTTPRouteWithDial(ctx, sandbox.ID, hostname, dial, routeOpts)
}

// syncWasmCustomDomainRoutes re-PATCHes every attached custom hostname so WASM
// dial targets stay on the host HTTP mediator (and refresh after expose_port).
func (s *Service) syncWasmCustomDomainRoutes(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil || !s.isWasmSandbox(sandbox) {
		return nil
	}
	if !s.cfg.EnableCaddy || strings.TrimSpace(s.cfg.Domain) == "" {
		return nil
	}
	for _, cd := range sandbox.CustomDomains {
		if cd.Hostname == "" {
			continue
		}
		if err := s.installWasmCustomDomainHTTPRoute(ctx, sandbox, cd.Hostname, cd.TargetPort); err != nil {
			return fmt.Errorf("install wasm custom-domain route %q: %w", cd.Hostname, err)
		}
	}
	return nil
}

package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	goruntime "runtime"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

// bridgeSource is the docker side of bridge discovery (*docker.Client).
type bridgeSource interface {
	SandboxBridge(ctx context.Context) (string, netip.Addr, error)
}

// wireEgressGateway connects sandboxd to the egress-gateway process when
// hostname filtering is on (plans/egress-domain-filtering.md D9). sandboxd
// discovers the sandbox bridges (docker network, aerolvm0) and hands them to
// the gateway, which has no docker socket access (S5). The first connect is
// best-effort here and lazy on the first gateway-mode create.
func wireEgressGateway(ctx context.Context, cfg config.Config, svc *service.Service, docker bridgeSource, logger *slog.Logger) {
	if !cfg.EgressFQDNEnabled || goruntime.GOOS != "linux" || !cfg.IsWorker() {
		return
	}
	if cfg.ContainerPrivileged {
		logger.Warn("egress gateway disabled: privileged sandboxes can bypass it (CEO D18); hostname policies get 501")
		return
	}
	bridges := func(ctx context.Context) []egress.Bridge {
		var out []egress.Bridge
		if docker != nil {
			if name, gw, err := docker.SandboxBridge(ctx); err == nil && gw.Is4() {
				out = append(out, egress.Bridge{Name: name, GatewayIP: gw})
			} else if err != nil {
				logger.Warn("egress: docker bridge discovery failed", "error", err)
			}
		}
		if cfg.ContainerEngine == models.ContainerEngineContainerd {
			if gw, ok := firstHost(cni.DefaultBridgeSubnet); ok {
				out = append(out, egress.Bridge{Name: "aerolvm0", GatewayIP: gw})
			}
		}
		return out
	}
	svc.SetEgressGateway(egress.NewClient(cfg.EgressGatewaySocket), bridges)
	go func() {
		if err := svc.EnsureEgressGatewayReady(ctx); err != nil {
			logger.Warn("egress gateway not ready at startup; retried on the first gateway-mode create", "error", err)
		}
	}()
}

// firstHost returns the first host address of a subnet, the CNI bridge's
// gateway.
func firstHost(subnet string) (netip.Addr, bool) {
	p, err := netip.ParsePrefix(subnet)
	if err != nil || !p.Addr().Is4() {
		return netip.Addr{}, false
	}
	return p.Masked().Addr().Next(), true
}

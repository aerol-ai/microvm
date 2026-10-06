package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	goruntime "runtime"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// egressSuperviseInterval is how quickly a node whose gateway came back
// re-syncs and re-advertises egress_gateway_ready to placement.
const egressSuperviseInterval = 5 * time.Second

// bridgeSource is the docker side of bridge discovery (*docker.Client).
type bridgeSource interface {
	SandboxBridge(ctx context.Context) (docker.SandboxNetwork, error)
}

// wireEgressGateway connects sandboxd to the egress-gateway process when
// hostname filtering is on (plans/egress-domain-filtering.md D9). sandboxd
// discovers the sandbox bridges (docker network, aerolvm0) and hands them to
// the gateway, which has no docker socket access (S5). The first connect is
// supervised: retried every few seconds while down, and lazily on the
// first gateway-mode create.
func wireEgressGateway(ctx context.Context, cfg config.Config, svc *service.Service, dockerNet bridgeSource, logger *slog.Logger) {
	if !cfg.EgressFQDNEnabled || goruntime.GOOS != "linux" || !cfg.IsWorker() {
		return
	}
	if cfg.ContainerPrivileged {
		logger.Warn("egress gateway disabled: privileged sandboxes can bypass it (CEO D18); hostname policies get 501")
		return
	}
	bridges := func(ctx context.Context) []egress.Bridge {
		var out []egress.Bridge
		if dockerNet != nil {
			if sn, err := dockerNet.SandboxBridge(ctx); err == nil && sn.Gateway.Is4() {
				out = append(out, egress.Bridge{Name: sn.Name, GatewayIP: sn.Gateway, Subnet: sn.Subnet})
			} else if err != nil {
				logger.Warn("egress: docker bridge discovery failed", "error", err)
			}
		}
		if cfg.ContainerEngine == models.ContainerEngineContainerd {
			if gw, ok := firstHost(cni.DefaultBridgeSubnet); ok {
				out = append(out, egress.Bridge{Name: "aerolvm0", GatewayIP: gw, Subnet: netip.MustParsePrefix(cni.DefaultBridgeSubnet).Masked()})
			}
		}
		return out
	}
	// Bridged sandbox-to-sandbox traffic must pass the netfilter hooks for
	// the redirect to see it (CEO D18); the self-test then confirms it.
	if err := ensureForwardingSysctls(); err != nil {
		logger.Warn("egress: bridge netfilter not enabled; the gateway self-test will fail", "error", err)
	}
	svc.SetEgressGateway(egress.NewClient(cfg.EgressGatewaySocket), bridges)
	svc.SetEgressSelfTest(egress.NewProbeNet())
	go svc.SuperviseEgressGateway(ctx, egressSuperviseInterval)
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

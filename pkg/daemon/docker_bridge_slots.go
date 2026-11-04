package daemon

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/netip"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// dockerBridgeSlotHeadroom is how many ports of the sandbox bridge the slot
// pool leaves to what attaches without an admitter reservation: the RUN steps
// of an image build (dockerd's builder joins them to the default bridge), a
// container an operator starts by hand, a teardown still in flight. 23 puts
// the default docker0 pool at 1,000, the ceiling setup/config-defaults.md
// already recommends for the containerd netns pool.
const dockerBridgeSlotHeadroom = 23

// dockerBridgeInspectTimeout bounds the one docker API call the pool costs,
// at daemon start.
const dockerBridgeInspectTimeout = 5 * time.Second

// maxHostBits keeps the address arithmetic in range on any int size; a
// network that large is far past a bridge's ports anyway.
const maxHostBits = 20

// wireDockerBridgeSlots gives the admitter the docker engine's sandbox bridge
// as a slot pool (capacity.SlotLimit), so a node whose bridge is full refuses
// a docker or gVisor create with a 503 capacity error and cluster placement
// skips it, instead of dockerd failing the start on the 1,024th port.
//
// Only a worker on the docker engine with a bridged sandbox network has one:
// on the containerd engine the netns pool already counts aerolvm0's ports,
// and SB_DOCKER_NETWORK=host gives sandboxes no port or address of their own.
// The size comes from one inspect of the network here, not on the create
// path; if dockerd cannot answer yet, the pool assumes a Linux bridge, the
// default and the only shape install.sh sets up.
func wireDockerBridgeSlots(ctx context.Context, cfg config.Config, logger *slog.Logger, net bridgeSource, admitter *capacity.Admitter) {
	if admitter == nil || !cfg.IsWorker() || cfg.DockerNetwork == "host" ||
		models.ResolveContainerEngineOrDocker(cfg.ContainerEngine) != models.ContainerEngineDocker {
		return
	}
	var sn docker.SandboxNetwork
	err := errors.New("no docker client")
	if net != nil {
		inspectCtx, cancel := context.WithTimeout(ctx, dockerBridgeInspectTimeout)
		sn, err = net.SandboxBridge(inspectCtx)
		cancel()
	}
	total, limit := sizeDockerBridgeSlots(cfg, sn, err)
	if total <= 0 {
		logger.Info("docker bridge slot pool off: the sandbox network has no port or address limit",
			"network", cfg.DockerNetwork, "driver", sn.Driver)
		return
	}
	if err != nil {
		logger.Warn("docker bridge slot pool: sandbox network not inspected; sized for one Linux bridge",
			"network", cfg.DockerNetwork, "error", err)
	}
	if cfg.DockerBridgeSlots > total {
		logger.Warn("SB_DOCKER_BRIDGE_SLOTS is more than the sandbox network holds; clamped",
			"requested", cfg.DockerBridgeSlots, "slots", total, "network_limit", limit)
	}
	admitter.SetSlotLimit(capacity.SlotLimit{
		Name:     capacity.SlotPoolDockerBridge,
		Pool:     capacity.DockerBridgePool,
		Runtimes: []string{models.RuntimeDocker, models.RuntimeGvisor},
		Total:    total,
	})
	logger.Info("docker bridge slot pool configured",
		"bridge", sn.Name, "driver", sn.Driver, "subnet", sn.Subnet, "ip_range", sn.IPRange,
		"network_limit", limit, "slots", total)
}

// sizeDockerBridgeSlots returns the pool's size and the network's physical
// limit: min(1,023 ports if the network is a bridge, the usable addresses of
// its subnet and IP range). The pool is that limit minus the pause-netns
// pool's free slots (each holds a veth and an address without a
// reservation) and, unless SB_DOCKER_BRIDGE_SLOTS sets it, minus
// dockerBridgeSlotHeadroom. total=0 means no limit applies (a macvlan or
// ipvlan network with no known subnet).
func sizeDockerBridgeSlots(cfg config.Config, sn docker.SandboxNetwork, inspectErr error) (total, limit int) {
	limit = capacity.BridgeMaxPorts
	if inspectErr == nil {
		if sn.Driver != "" && sn.Driver != "bridge" {
			// macvlan, ipvlan: no bridge; only addresses bound it.
			limit = math.MaxInt
		}
		for _, p := range []netip.Prefix{sn.Subnet, sn.IPRange} {
			if n, ok := usableIPv4Addresses(p); ok {
				limit = min(limit, n)
			}
		}
	}
	if limit == math.MaxInt {
		return 0, 0
	}
	reserved := 0
	if cfg.DockerNetnsPoolEnabled {
		reserved = max(cfg.DockerNetnsPoolDepth, 0)
	}
	if cfg.DockerBridgeSlots > 0 {
		total = min(cfg.DockerBridgeSlots, limit-reserved)
	} else {
		total = limit - dockerBridgeSlotHeadroom - reserved
	}
	// A network too small for the headroom still takes one sandbox; the
	// start-failure backstop answers anything past what it really holds.
	return max(total, 1), limit
}

// usableIPv4Addresses is how many addresses docker's IPAM can hand out in p:
// all of it but the network, broadcast and gateway addresses.
func usableIPv4Addresses(p netip.Prefix) (int, bool) {
	if !p.IsValid() || !p.Addr().Is4() {
		return 0, false
	}
	hostBits := min(32-p.Bits(), maxHostBits)
	return max((1<<hostBits)-3, 0), true
}

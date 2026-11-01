package daemon

import (
	"context"
	"errors"
	"log/slog"
	goruntime "runtime"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/network/ipv6fence"
	"github.com/aerol-ai/microvm/internal/network/tap"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ipv6FenceTick paces the fence supervisor: a failed install, or a
// runtime whose bridge was not known yet, is retried within it.
const ipv6FenceTick = 5 * time.Second

// Seams for wireIPv6Fence; tests replace them.
var (
	newIPv6FenceBackend = ipv6fence.NewBackend
	ipv6FenceGOOS       = goruntime.GOOS
)

// wireIPv6Fence installs the node's IPv6 fence (internal/network/ipv6fence)
// on every worker on Linux, before the API serves, and hands the create gate
// to the service: a container or Firecracker create is refused while the
// fence is not in the kernel for its runtime. The operator file has no say
// in it: keeping sandboxes apart is not a policy a sandbox opts into. The
// supervisor retries a failed install every ipv6FenceTick and re-asserts the
// fence every ipv6fence.ReassertInterval until ctx ends.
//
// A node with the host firewall off (SB_ENABLE_NETWORK_RULES=false, local
// mode) gets no fence, as it gets no IPv4 floor between sandboxes: the
// operator turned the host firewall off, and refusing creates there would
// only break local development. Enterprise mode always gets it. IPv6 is
// still off inside every sandbox either way (the runtimes do that).
func wireIPv6Fence(ctx context.Context, cfg config.Config, svc *service.Service, dockerNet bridgeSource, logger *slog.Logger) *ipv6fence.Supervisor {
	if ipv6FenceGOOS != "linux" || !cfg.IsWorker() || svc == nil {
		return nil
	}
	if !cfg.EnableNetworkRules && !cfg.EnterpriseMode {
		logger.Warn("host firewall off (SB_ENABLE_NETWORK_RULES=false): no IPv6 fence on the sandbox networks; IPv6 is still off inside each sandbox, but nothing on the node drops it")
		return nil
	}
	sources := ipv6FenceSources(cfg, dockerNet)
	if len(sources) == 0 {
		return nil
	}
	sup := ipv6fence.NewSupervisor(newIPv6FenceBackend(), logger, sources...)
	sup.Sync(ctx, true)
	svc.SetIPv6Fence(sup)
	go sup.Run(ctx, ipv6FenceTick)
	return sup
}

// ipv6FenceSources names, per runtime, the host interfaces its sandboxes sit
// on: the container engine's bridge, and every Firecracker TAP.
func ipv6FenceSources(cfg config.Config, dockerNet bridgeSource) []ipv6fence.Source {
	var out []ipv6fence.Source
	if cfg.ContainerEngine == models.ContainerEngineContainerd {
		out = append(out, ipv6fence.Source{Runtime: models.ContainerEngineContainerd, Spec: containerdFenceSpec(cfg)})
	} else if dockerNet != nil {
		out = append(out, ipv6fence.Source{Runtime: models.ContainerEngineDocker, Spec: dockerFenceSpec(dockerNet)})
	}
	if cfg.EnableFirecracker {
		out = append(out, ipv6fence.Source{Runtime: models.RuntimeFirecracker, Spec: func(context.Context) (ipv6fence.Spec, error) {
			return ipv6fence.Spec{Links: []string{tap.NamePrefix + "*"}}, nil
		}})
	}
	return out
}

// containerdFenceSpec is the bridge the CNI conflist attaches sandboxes to,
// whatever an operator conflist calls it (containerd's stock one says
// cni0). Without the native netns pool a containerd sandbox gets no network
// at all; the bridge the generated conflist would use stands in when there
// is no conflist to read.
func containerdFenceSpec(cfg config.Config) func(context.Context) (ipv6fence.Spec, error) {
	return func(context.Context) (ipv6fence.Spec, error) {
		name, err := cni.BridgeName(cfg.ContainerdCNIConfPath)
		if err != nil {
			if cfg.ContainerdNativeNetnsPoolEnabled {
				return ipv6fence.Spec{}, err
			}
			name = cni.DefaultBridgeName
		}
		return ipv6fence.Spec{Bridges: []string{name}}, nil
	}
}

// dockerFenceSpec is the docker sandbox network's bridge (docker0, or
// br-<id> for SB_DOCKER_NETWORK).
func dockerFenceSpec(dockerNet bridgeSource) func(context.Context) (ipv6fence.Spec, error) {
	return func(ctx context.Context) (ipv6fence.Spec, error) {
		sn, err := dockerNet.SandboxBridge(ctx)
		if sn.Name == "" {
			if err == nil {
				err = errors.New("docker sandbox network has no bridge")
			}
			return ipv6fence.Spec{}, err
		}
		// A network with no IPv4 gateway still has a bridge to fence.
		return ipv6fence.Spec{Bridges: []string{sn.Name}}, nil
	}
}

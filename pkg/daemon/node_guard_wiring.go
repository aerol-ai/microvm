package daemon

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// nodeGuardSuperviseInterval is how quickly a node guard that failed to
// install is retried; the re-assert runs at its own, slower pace
// (service.nodeGuardReassertInterval).
const nodeGuardSuperviseInterval = 5 * time.Second

// configureHostMediatedNodeGuard tells this process's dial guard (isolate
// egress) and the WASM workers it starts which node ports host-mediated
// sandboxes may still reach (service.HostMediatedNodePorts). It runs before
// any runtime is wired: a worker's environment is fixed when it spawns, and
// a worker started without it allows no node port at all (fail closed).
func configureHostMediatedNodeGuard(cfg config.Config, logger *slog.Logger) {
	ports := service.HostMediatedNodePorts(cfg)
	egresspolicy.SetNodeAllowedPorts(ports)
	if err := os.Setenv(egresspolicy.NodePortsEnv, egresspolicy.FormatNodePorts(ports)); err != nil {
		logger.Warn("node guard: WASM workers will allow no node port", "error", err)
	}
	if len(cfg.SandboxNodePortsAllow) > 0 {
		logger.Warn("SB_SANDBOX_NODE_PORTS_ALLOW opens these node ports to every sandbox on this node", "ports", cfg.SandboxNodePortsAllow)
	}
}

// configureEgressRanges installs the node's extra deny floor and private
// ranges (SB_EGRESS_DENY_FLOOR_CIDRS, SB_EGRESS_PRIVATE_DEFAULT_CIDRS, C24)
// in this process, where isolate dials and the host-firewall floor is
// built, and writes them back to the environment in their checked form for
// the WASM workers, which read them at start (egresspolicy.LoadRangesFromEnv).
// Like the node ports, it runs before any runtime is wired: a worker's
// environment is fixed when it spawns. The egress gateway is its own
// process and reads the same settings from its own environment.
func configureEgressRanges(cfg config.Config, logger *slog.Logger) {
	egresspolicy.SetRanges(cfg.EgressDenyFloorCIDRs, cfg.EgressPrivateDefaultCIDRs)
	for env, val := range map[string]string{
		egresspolicy.DenyFloorEnv:     egresspolicy.FormatRanges(cfg.EgressDenyFloorCIDRs),
		egresspolicy.PrivateRangesEnv: egresspolicy.FormatRanges(cfg.EgressPrivateDefaultCIDRs),
		// As read: a value config took as false ("yes") must not turn
		// into anything else in a worker.
		egresspolicy.BlockPrivateEnv: strconv.FormatBool(cfg.EgressBlockPrivateByDefault),
	} {
		if err := os.Setenv(env, val); err != nil {
			logger.Error("egress: WASM workers may not get this setting", "setting", env, "error", err)
		}
	}
	if len(cfg.EgressDenyFloorCIDRs) > 0 || len(cfg.EgressPrivateDefaultCIDRs) > 0 {
		logger.Info("egress: sandboxes cannot reach the extra deny floor, and reach the extra private ranges only through a policy that opens one",
			"deny_floor", egresspolicy.FormatRanges(cfg.EgressDenyFloorCIDRs), "private_ranges", egresspolicy.FormatRanges(cfg.EgressPrivateDefaultCIDRs))
	}
}

// wireNodeGuard installs the node guard on every container and Firecracker
// runtime before the API serves, so no sandbox starts without it, and keeps
// it in place. It also keeps the egress deny floor in place, which
// wireEgressOperator installed at boot: a runtime where that failed is
// retried at the guard's pace, and its creates are refused until it is in.
// Only nodes that own sandboxes need either.
func wireNodeGuard(ctx context.Context, cfg config.Config, svc *service.Service) {
	if !cfg.IsWorker() {
		return
	}
	svc.ApplyNodeGuard(ctx)
	go svc.SuperviseNodeGuard(ctx, nodeGuardSuperviseInterval)
	go svc.SuperviseEgressFloor(ctx, nodeGuardSuperviseInterval)
}

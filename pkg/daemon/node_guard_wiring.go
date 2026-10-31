package daemon

import (
	"context"
	"log/slog"
	"os"
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

// wireNodeGuard installs the node guard on every container and Firecracker
// runtime before the API serves, so no sandbox starts without it, and keeps
// it in place. Only nodes that own sandboxes need it.
func wireNodeGuard(ctx context.Context, cfg config.Config, svc *service.Service) {
	if !cfg.IsWorker() {
		return
	}
	svc.ApplyNodeGuard(ctx)
	go svc.SuperviseNodeGuard(ctx, nodeGuardSuperviseInterval)
}

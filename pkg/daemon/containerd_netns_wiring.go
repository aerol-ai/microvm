package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/network/hostnet"
	"github.com/aerol-ai/microvm/internal/network/netns"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

type containerdNetnsPool struct {
	refiller *netns.Refiller
	pool     *netns.Pool
	host     *netns.Host
}

var ensureForwardingSysctls = hostnet.EnsureForwardingSysctls

func (p *containerdNetnsPool) Stop() {
	if p == nil {
		return
	}
	if p.refiller != nil {
		p.refiller.Stop()
	}
}

// wireContainerdNativeNetnsPool seeds the SQLite-backed netns pool, runs boot
// reconcile, starts the refill ticker, and wires the driver handoff.
func wireContainerdNativeNetnsPool(ctx context.Context, cfg config.Config, logger *slog.Logger, st *store.Store, driver *cntr.Driver) (*containerdNetnsPool, error) {
	if cfg.ContainerEngine != models.ContainerEngineContainerd || !cfg.ContainerdNativeNetnsPoolEnabled {
		return nil, nil
	}
	if driver == nil || st == nil {
		return nil, fmt.Errorf("containerd native netns pool: driver and store are required")
	}
	pool := netns.New(st)
	now := time.Now()
	// Total capacity is decoupled from the warm depth (mirrors the firecracker
	// TAP pool). Seeding only `depth` slots — as this once did — hard-capped every
	// node at `depth` (default 4) concurrent sandboxes, because cold creates also
	// reserve from this pool and it never grows. Seed the full size; the refiller
	// below only pre-realizes `depth` of them. Guard size >= depth so the refiller
	// can always reach its warm target even under an operator misconfiguration.
	poolSize := cfg.ContainerdNetnsPoolSize
	if poolSize < cfg.ContainerdNetnsPoolDepth {
		poolSize = cfg.ContainerdNetnsPoolDepth
	}
	if err := pool.Seed(ctx, netns.SeedConfig{PoolSize: poolSize}, now); err != nil {
		return nil, fmt.Errorf("seed containerd netns pool: %w", err)
	}
	// Generate the bridge+host-local conflist (bridge, IPAM, outbound NAT) if
	// absent — nothing else ships it, and without it the first CNI ADD fails on
	// a missing conf. Size the bridge MTU to the host uplink so egress isn't
	// throughput-capped (jumbo uplink) or blackholed via PMTUD (sub-1500 uplink).
	if err := cni.EnsureBridgeConflist(cfg.ContainerdCNIConfPath, cni.ConflistOptions{
		Name:   "aerolvm",
		Bridge: "aerolvm0",
		MTU:    cni.UplinkMTU(),
	}); err != nil {
		return nil, fmt.Errorf("ensure cni conflist: %w", err)
	}
	runner, err := cni.NewExecRunner(cni.Config{
		PluginDir: cfg.ContainerdCNIPluginDir,
		ConfPath:  cfg.ContainerdCNIConfPath,
	})
	if err != nil {
		return nil, fmt.Errorf("cni runner: %w", err)
	}
	if err := ensureForwardingSysctls(); err != nil {
		return nil, fmt.Errorf("host forwarding sysctls: %w", err)
	}
	host := &netns.Host{Runner: runner}
	live := func(ctx context.Context, sandboxID string) bool {
		if driver == nil {
			return false
		}
		state, err := driver.Inspect(ctx, sandboxID)
		if err != nil || state == nil {
			return false
		}
		return state.Status == models.SandboxStatusStarted
	}
	if reaped, err := pool.Reconcile(ctx, host, live, nil, now); err != nil {
		return nil, fmt.Errorf("reconcile containerd netns pool: %w", err)
	} else if reaped > 0 {
		logger.Warn("containerd netns pool reconcile reaped orphans", "count", reaped)
	}
	driver.SetNetnsHandoff(netns.NewRuntimeHandoff(pool, host))
	refiller := netns.NewRefiller(pool, host, cfg.ContainerdNetnsPoolDepth, cfg.ContainerdNetnsPoolRefillInterval)
	go refiller.Run(ctx)
	logger.Info("containerd native netns pool enabled",
		"pool_size", poolSize,
		"warm_depth", cfg.ContainerdNetnsPoolDepth,
		"refill_interval", cfg.ContainerdNetnsPoolRefillInterval,
		"cni_plugin_dir", cfg.ContainerdCNIPluginDir,
		"cni_conf", cfg.ContainerdCNIConfPath,
	)
	return &containerdNetnsPool{refiller: refiller, pool: pool, host: host}, nil
}

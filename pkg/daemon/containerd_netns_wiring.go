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
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// maxBridgePorts is how many interfaces one Linux bridge can hold
// (capacity.BridgeMaxPorts). Each containerd netns slot uses one.
const maxBridgePorts = capacity.BridgeMaxPorts

type containerdNetnsPool struct {
	refiller *netns.Refiller
	pool     *netns.Pool
	host     netns.HostManager
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

// netnsOwnerProber is the slice of the containerd driver the boot reconcile
// needs to decide whether a slot's owner is gone.
type netnsOwnerProber interface {
	SandboxContainerExists(ctx context.Context, sandboxID string) (bool, error)
}

// netnsSlotOwnerLive answers "does this slot still belong to its sandbox?"
// for the boot reconcile. Only a confirmed-missing container means no: the
// reconcile then runs CNI DEL in the slot's netns and deletes it, so a false
// "dead" cuts a running sandbox off the network and lets the slot (and, for
// a stopped sandbox, the netns path its spec still pins) go to someone else.
// It used to be "Inspect succeeded and the task is running", which also said
// dead for every stopped sandbox, for every gVisor sandbox (Inspect fails to
// read their IP from the netns), and on any transient containerd error.
func netnsSlotOwnerLive(prober netnsOwnerProber, logger *slog.Logger) netns.LiveSandbox {
	return func(ctx context.Context, sandboxID string) bool {
		if prober == nil {
			return false
		}
		exists, err := prober.SandboxContainerExists(ctx, sandboxID)
		if err != nil {
			if logger != nil {
				logger.Warn("containerd netns reconcile: owner check failed; keeping its slot",
					"sandbox_id", sandboxID, "error", err)
			}
			return true
		}
		return exists
	}
}

// wireContainerdNativeNetnsPool seeds the SQLite-backed netns pool, runs boot
// reconcile, starts the refill ticker, and wires the driver handoff.
func wireContainerdNativeNetnsPool(ctx context.Context, cfg config.Config, logger *slog.Logger, st *store.Store, driver *cntr.Driver) (*containerdNetnsPool, error) {
	return wireNetnsPool(ctx, cfg, logger, st, driver, nil)
}

// wireNetnsPool is wireContainerdNativeNetnsPool with the root helper in
// privilege mode split: the pool's bookkeeping stays here, and every
// namespace build, teardown and read goes to the helper (helperNetnsHost),
// which also wrote the CNI config and set the forwarding sysctls at boot
// (resolveSplitBridgeSubnet). nil is single mode: all of it in process.
func wireNetnsPool(ctx context.Context, cfg config.Config, logger *slog.Logger, st *store.Store, driver *cntr.Driver, helper netnsHelper) (*containerdNetnsPool, error) {
	if cfg.ContainerEngine != models.ContainerEngineContainerd || !cfg.ContainerdNativeNetnsPoolEnabled {
		return nil, nil
	}
	if driver == nil || st == nil {
		return nil, fmt.Errorf("containerd native netns pool: driver and store are required")
	}
	pool := netns.New(st)
	pool.SetLogger(logger)
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
	if poolSize > maxBridgePorts {
		// Every realized slot attaches one veth to the aerolvm0 bridge, and
		// a Linux bridge takes at most 1023 ports. Slots past that fail CNI
		// ADD with "exchange full" instead of refusing cleanly for capacity,
		// so an operator raising the size must know where the wall is.
		logger.Warn("containerd netns pool is larger than one bridge can hold; slots past the bridge limit cannot be realized",
			"pool_size", poolSize, "bridge_port_limit", maxBridgePorts,
			"hint", "keep SB_CONTAINERD_NETNS_POOL_SIZE at or below the bridge limit (setup/config-defaults.md)")
	}
	subnet := containerdBridgeSubnet(cfg)
	if hosts := bridgeHosts(subnet); poolSize > hosts {
		// host-local IPAM runs out of addresses before the pool runs out of
		// slots; the slots past it fail CNI ADD.
		logger.Warn("containerd netns pool is larger than the sandbox range holds; slots past it cannot be realized",
			"pool_size", poolSize, "subnet", subnet, "addresses", hosts,
			"hint", "use a larger SB_CONTAINERD_BRIDGE_SUBNET or a smaller SB_CONTAINERD_NETNS_POOL_SIZE")
	}
	if err := pool.Seed(ctx, netns.SeedConfig{PoolSize: poolSize}, now); err != nil {
		return nil, fmt.Errorf("seed containerd netns pool: %w", err)
	}
	var host netns.HostManager
	var exists netns.NetnsExists
	if helper != nil {
		h := newHelperNetnsHost(helper, subnet, logger)
		if fw, ok := helper.(firewallHelper); ok && splitFirewallOn(cfg) {
			h.fw = fw
		}
		host, exists = h, h.exists
	} else {
		inProcess, err := inProcessNetnsHost(cfg, subnet)
		if err != nil {
			return nil, err
		}
		host = inProcess
	}
	if reaped, err := pool.Reconcile(ctx, host, netnsSlotOwnerLive(driver, logger), exists, now); err != nil {
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
		"root_helper", helper != nil,
	)
	return &containerdNetnsPool{refiller: refiller, pool: pool, host: host}, nil
}

// inProcessNetnsHost is single mode's: sandboxd writes the CNI config,
// sets the forwarding sysctls and runs CNI itself, as root.
func inProcessNetnsHost(cfg config.Config, subnet string) (*netns.Host, error) {
	// Generate the bridge+host-local conflist (bridge, IPAM, outbound NAT) if
	// absent — nothing else ships it, and without it the first CNI ADD fails on
	// a missing conf. Size the bridge MTU to the host uplink so egress isn't
	// throughput-capped (jumbo uplink) or blackholed via PMTUD (sub-1500 uplink).
	if err := cni.EnsureBridgeConflist(cfg.ContainerdCNIConfPath, cni.ConflistOptions{
		Name:   "aerolvm",
		Bridge: "aerolvm0",
		Subnet: subnet,
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
	return &netns.Host{Runner: runner}, nil
}

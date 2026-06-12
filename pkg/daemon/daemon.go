// Package daemon holds the full sandboxd boot sequence as a single reusable
// entrypoint, Run. The open-source cmd/sandboxd calls Run with a no-op control
// plane (controlplane.Noop()); a managed build calls the same Run with a
// provider backed by the private fleet client. Keeping boot in one exported
// function is what lets the managed binary reuse the entire daemon without
// forking main().
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/tap"
	"github.com/aerol-ai/microvm/internal/observability"
	vmmpool "github.com/aerol-ai/microvm/internal/pool/vmm"
	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/internal/version"
	api "github.com/aerol-ai/microvm/pkg/api"
	"github.com/aerol-ai/microvm/pkg/api/ingressproxy"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/oci"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"github.com/aerol-ai/microvm/pkg/sshgateway"
)

// FleetConfig is the subset of daemon configuration a control-plane provider
// needs, projected out of the internal config so a managed build can construct
// its provider without importing internal/config (which Go forbids across
// modules). It mirrors the SB_FLEET_* settings.
type FleetConfig struct {
	Enabled         bool
	Endpoint        string
	Token           string
	ContractRefresh time.Duration
}

// ProviderFactory builds the control-plane provider from the resolved fleet
// config. The managed build supplies one (wiring the private avmctl client);
// the open-source build passes nil, which yields controlplane.Noop(). It
// receives ctx so a provider can start background work (e.g. contract refresh)
// bound to the daemon lifecycle.
type ProviderFactory func(ctx context.Context, fc FleetConfig) (controlplane.Provider, error)

// Run loads configuration and executes the full daemon boot sequence, blocking
// until ctx is cancelled (SIGINT/SIGTERM in the standard wrapper), then performs
// graceful shutdown. Every fatal boot failure is returned as a wrapped error
// rather than calling os.Exit; the thin main() wrapper turns a non-nil return
// into the exit(1) the historical main() did, so observable behavior is
// unchanged (process dies on boot failure) while the boot-failure paths stay
// testable. Returning also lets the deferred cleanup (store/mount/otel
// shutdown) run on failure, which os.Exit skipped. The returned error covers
// every boot phase; it is nil at graceful shutdown.
//
// makeProvider supplies the control-plane capabilities. nil (the open-source
// default) means controlplane.Noop(): every non-PAT token rejected, every usage
// report a no-op, every create admitted, no enforcement loop.
func Run(ctx context.Context, logger *slog.Logger, makeProvider ProviderFactory) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	cp := controlplane.Noop()
	if makeProvider != nil {
		cp, err = makeProvider(ctx, FleetConfig{
			Enabled:         cfg.FleetControlPlaneEnabled,
			Endpoint:        cfg.FleetControlPlaneEndpoint,
			Token:           cfg.FleetControlPlaneToken,
			ContractRefresh: cfg.FleetControlPlaneContractRefresh,
		})
		if err != nil {
			return fmt.Errorf("build control plane provider: %w", err)
		}
	}
	cp = cp.WithDefaults()

	// Derive a cancellable child so a fatal failure in a background server
	// goroutine (HTTP/ingress ListenAndServe) can trigger graceful shutdown by
	// unblocking the <-ctx.Done() wait below — exactly as the old main() did
	// with the cancel from signal.NotifyContext.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	logger.Info("starting sandboxd", "version", version.Version, "addr", cfg.ListenAddr())

	otelTracesShutdown, err := observability.StartOTELTraces(ctx, logger, observability.OTELTracesConfig{
		Enabled:     cfg.OTELTracesEnabled,
		Endpoint:    cfg.OTELTracesEndpoint,
		SampleRatio: cfg.OTELTracesSampleRatio,
		ServiceName: cfg.OTELServiceName,
		NodeID:      cfg.NodeID,
		NodeRole:    cfg.NodeRole,
	})
	if err != nil {
		logger.Warn("failed to start otel trace exporter", "error", err)
	} else if otelTracesShutdown != nil {
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := otelTracesShutdown(shutdownCtx); err != nil {
				logger.Warn("otel trace shutdown failed", "error", err)
			}
		}()
	}

	otelShutdown, err := observability.StartOTELMetrics(ctx, logger, observability.OTELMetricsConfig{
		Enabled:     cfg.OTELMetricsEnabled,
		Endpoint:    cfg.OTELMetricsEndpoint,
		Interval:    cfg.OTELMetricsInterval,
		ServiceName: cfg.OTELServiceName,
		NodeID:      cfg.NodeID,
		NodeRole:    cfg.NodeRole,
	})
	if err != nil {
		logger.Warn("failed to start otel metrics exporter", "error", err)
	} else if otelShutdown != nil {
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := otelShutdown(shutdownCtx); err != nil {
				logger.Warn("otel metrics shutdown failed", "error", err)
			}
		}()
	}

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer db.Close()

	rules, err := netrules.New(cfg.EnableNetworkRules)
	if err != nil {
		return fmt.Errorf("create netrules manager: %w", err)
	}

	dockerClient, err := docker.New(logger, cfg, rules)
	if err != nil {
		return fmt.Errorf("create docker client: %w", err)
	}
	configureMirror(logger, cfg, dockerClient)
	configureAOCRPullAuth(logger, cfg, dockerClient)

	caddyClient := caddy.New(cfg)

	cipher, err := secrets.NewCipher(cfg.CredentialEncryptionKey, cfg.CredentialEncryptionKeyPath)
	if err != nil {
		return fmt.Errorf("initialize credential cipher: %w", err)
	}

	mountManager, err := mounts.New(logger, mounts.Config{
		RootDir:     cfg.MountsRootPath,
		CredDir:     cfg.MountsCredentialsRuntimeDir,
		WaitTimeout: cfg.MountWaitTimeout,
	})
	if err != nil {
		return fmt.Errorf("initialize mount manager: %w", err)
	}
	defer mountManager.Close()

	host, err := capacity.DetectHost()
	if err != nil {
		// Detection failure is non-fatal — operator can override via env. We
		// log the cause so this isn't silent.
		logger.Warn("host capacity detection failed; using overrides if set",
			"error", err,
		)
	}
	// Keep the detected disk total separate from the admission budget so we
	// can log it for observability without changing placement behavior on
	// deployments that never configured SB_HOST_DISK_GB. Disk admission stays
	// opt-in: DiskTotalGB only carries the operator's declared budget.
	detectedDiskTotalGB := host.DiskTotalGB
	if cfg.HostCPUCoresOverride > 0 {
		host.CPUCores = cfg.HostCPUCoresOverride
	}
	if cfg.HostMemoryMBOverride > 0 {
		host.MemoryTotalMB = cfg.HostMemoryMBOverride
	}
	host.DiskTotalGB = max(cfg.HostDiskGB, 0)
	host.GPUCount = cfg.HostGPUCount
	host.GPUVendor = cfg.HostGPUVendor
	host.SupportedRuntimes = cfg.HostSupportedRuntimes
	if len(host.SupportedRuntimes) == 0 {
		host.SupportedRuntimes = []string{models.RuntimeDocker}
	}
	if cfg.EnableFirecracker {
		host.SupportedRuntimes = appendRuntimeIfMissing(host.SupportedRuntimes, models.RuntimeFirecracker)
	}
	// Phase 5: the per-VMM RSS sampler is constructed up front when
	// firecracker is enabled so admission can be wired against it from
	// the start (capacity holds the RSSSource by reference, not value).
	// The sampler's Run goroutine is started later inside the
	// EnableFirecracker block, after the driver is constructed —
	// keeping the goroutine lifecycle next to the rest of the
	// firecracker boot block. On docker-only hosts the sampler is nil
	// and capacity falls back to nominal accounting (the watermark
	// check is gated on rss != nil).
	//
	// rssSource is a typed nil-safe wrapper: if we passed the
	// *RSSSampler directly into the interface arg, a nil pointer would
	// satisfy the interface (non-nil interface, nil value) and the
	// admitter's `rss != nil` guard would lie — a watermark check
	// would then dereference the nil pointer and panic. Materialising
	// the interface as a true nil keeps that gate honest.
	var (
		rssSampler *fcruntime.RSSSampler
		rssSource  capacity.RSSSource
	)
	if cfg.EnableFirecracker {
		rssSampler = fcruntime.NewRSSSampler(logger)
		rssSource = rssSampler
	}
	admitter := capacity.NewWithRSSSource(host, capacity.Limits{
		CPUReservationRatio:       cfg.CPUReservationRatio,
		MemoryReservationRatio:    cfg.MemoryReservationRatio,
		DiskReservationRatio:      cfg.DiskReservationRatio,
		MemoryFloorRatio:          cfg.MemoryFloorRatio,
		CPUOverProvisionFactor:    cfg.CPUOverProvisionFactor,
		MemoryOverProvisionFactor: cfg.MemoryOverProvisionFactor,
		RSSWatermarkRatio:         cfg.FirecrackerRSSWatermarkRatio,
	}, capacity.NewProcMeminfoProbe(), rssSource)
	logger.Info("capacity admission configured",
		"host_cpu_cores", host.CPUCores,
		"host_memory_mb", host.MemoryTotalMB,
		"host_disk_gb", host.DiskTotalGB,
		"host_disk_detected_gb", detectedDiskTotalGB,
		"host_disk_free_gb", host.DiskFreeGB,
		"host_gpu_count", host.GPUCount,
		"host_gpu_vendor", host.GPUVendor,
		"host_supported_runtimes", host.SupportedRuntimes,
		"cpu_reservation_ratio", cfg.CPUReservationRatio,
		"memory_reservation_ratio", cfg.MemoryReservationRatio,
		"disk_reservation_ratio", cfg.DiskReservationRatio,
		"memory_floor_ratio", cfg.MemoryFloorRatio,
		"cpu_overprovision_factor", cfg.CPUOverProvisionFactor,
		"memory_overprovision_factor", cfg.MemoryOverProvisionFactor,
		"rss_watermark_ratio", cfg.FirecrackerRSSWatermarkRatio,
	)

	// dockerClient is passed twice: as the runtime.Runtime driver (the
	// abstraction service uses for sandbox lifecycle) and as the concrete
	// *docker.Client used for the daemon /events stream. They point at the
	// same instance today; the split exists so a future non-Docker runtime
	// can replace the first without touching the second.
	svc := service.New(cfg, logger, db, dockerClient, dockerClient, caddyClient, cipher, mountManager, admitter)
	// Wire the control-plane usage reporter into the service's background loops
	// (reconcile / event monitor / netstats / live sampler). Under
	// controlplane.Noop() this is the no-op reporter, so the open-source build
	// emits nothing and pays no cost.
	svc.SetUsageReporter(cp.Reporter)
	// Wire the managed create-gate. Under Noop() this is the allow-all admitter,
	// so the open-source build never gates a create.
	svc.SetFleetAdmitter(cp.Admitter)
	// Start the standing-driven enforcement loop. EnforcementFor binds the loop
	// to the service as its FleetController; under Noop() the factory yields a
	// no-op whose Start does nothing. Runs on the daemon's cancellable ctx so it
	// stops on shutdown. Started here (right after the service exists) rather than
	// alongside the other reconcilers because the FleetController it drives is the
	// service itself.
	cp.EnforcementFor(svc).Start(ctx)

	// Native Firecracker runtime is opt-in per host. When enabled, we
	// seed the per-host network slot pool from
	// SB_FIRECRACKER_TAP_BASE_CIDR / SB_FIRECRACKER_TAP_POOL_SIZE and
	// register the driver with the service. Seed is idempotent; a warm
	// restart preserves existing slot↔sandbox assignments. Errors here
	// are fatal at boot — the config validator already required the
	// fields, so any failure is operational (CIDR doesn't fit the pool,
	// SQLite write failed) and worth crashing for rather than swallowing.
	if cfg.EnableFirecracker {
		pool := tap.New(db)
		if err := pool.Seed(context.Background(), tap.SeedConfig{
			BaseCIDR: cfg.FirecrackerTapBaseCIDR,
			PoolSize: cfg.FirecrackerTapPoolSize,
		}, time.Now()); err != nil {
			return fmt.Errorf("firecracker tap pool seed: %w", err)
		}
		// OCI rootfs builder: depends on skopeo, umoci, mkfs.ext4 being
		// installed and on $PATH. The validator already required these
		// binary paths when EnableFirecracker=true; pkg/oci.New stat-
		// checks them again at construction so a typo'd path crashes
		// the daemon at boot rather than on first Create.
		ociBuilder, err := oci.New(oci.Config{
			SkopeoBin: cfg.FirecrackerSkopeoBin,
			UmociBin:  cfg.FirecrackerUmociBin,
			Mkfs4Bin:  cfg.FirecrackerMkfs4Bin,
			WorkDir:   filepath.Join(cfg.FirecrackerRunDir, "oci-work"),
		})
		if err != nil {
			return fmt.Errorf("firecracker oci builder init: %w", err)
		}
		// Phase 5: start the per-VMM RSS sampler now that we know
		// firecracker is on. Run is a blocking ticker loop, so it goes in
		// a goroutine; ctx cancellation (SIGINT/SIGTERM at top of main)
		// stops it. Interval ≤ 0 makes Run return immediately, which is
		// the safe behaviour if an operator zeroes the env var — the
		// sampler then never flips Ready() and admission stays on
		// nominal accounting.
		go rssSampler.Run(ctx, cfg.FirecrackerRSSSamplerInterval)
		logger.Info("firecracker rss sampler started",
			"interval", cfg.FirecrackerRSSSamplerInterval,
			"watermark_ratio", cfg.FirecrackerRSSWatermarkRatio)
		fcDriver := fcruntime.New(fcruntime.FromDaemonConfig(cfg), logger)
		fcDriver.SetPool(&firecrackerPoolAdapter{inner: pool})
		fcDriver.SetRootfsBuilder(&firecrackerRootfsAdapter{inner: ociBuilder})
		fcDriver.SetTapHost(&firecrackerTapHostAdapter{inner: tap.NewHost(cfg.FirecrackerIPBinary)})
		fcDriver.SetVsockDialer(fcruntime.NewLinuxVsockDialer())
		// Phase 5: hand the sampler to the driver so Create / WarmSpawn
		// / tryAcquireWarm / Destroy can Register/Unregister per-VMM
		// pids. Without this call the sampler stays empty and the
		// effective-memory admission axis would always read 0 RSS —
		// the same "no data, allow" cold-start behaviour the watermark
		// check already protects against.
		fcDriver.SetRSSSampler(rssSampler)
		// Phase 6 PR-A: warm-spawn corruption notifier. WarmSpawn runs
		// outside any service-side call, so the runtime needs a back-
		// channel to flip a corrupt template to unhealthy + kick rebuild.
		// *Service satisfies firecracker.TemplateHealthNotifier
		// structurally (one method, MarkSnapshotCorrupt). Wiring is
		// unconditional when firecracker is enabled — the cold-load path
		// has its own service-side intercept and doesn't depend on this.
		fcDriver.SetTemplateHealthNotifier(svc)
		// Template pipeline (plans/snapshot-clone-fast-boot.md Phase 2):
		// templateBuilderAdapter reuses the same *oci.Builder the per-
		// create path uses, so a template build and a non-template
		// CreateSandbox share OCI binaries, workdir, and validation
		// constraints. templateResolverAdapter lets the driver look up
		// the template's rootfs path through the service layer without
		// the runtime package importing internal/service.
		svc.SetTemplateBuilder(&templateBuilderAdapter{inner: ociBuilder})
		fcDriver.SetTemplateResolver(&templateResolverAdapter{svc: svc})
		// Phase 3 snapshot pipeline: the snapshotter is the driver
		// itself (it owns the transient VMM seams); the CID allocator
		// wraps the same TAP pool used for per-sandbox slots, keyed by
		// "template:<id>" so the pool's per-id PK gives idempotent
		// reservation across daemon restarts. Wiring both unlocks the
		// transition into status=snapshotting and the eventual ready
		// terminal state; leaving either nil keeps templates at
		// ready_no_snapshot (cold-boot only).
		svc.SetTemplateSnapshotter(&firecrackerTemplateSnapshotterAdapter{driver: fcDriver})
		svc.SetTemplateCIDAllocator(&firecrackerCIDAllocatorAdapter{pool: pool})
		svc.SetFirecrackerRuntime(fcDriver)
		logger.Info("firecracker runtime enabled",
			"tap_base_cidr", cfg.FirecrackerTapBaseCIDR,
			"tap_pool_size", cfg.FirecrackerTapPoolSize,
			"use_jailer", cfg.UseJailer)

		// Phase 4 warm-VMM pool wiring. Gated on FirecrackerVMMPoolEnabled
		// so a daemon rebuilt from this branch with the flag unset behaves
		// identically to today — every snapshot-load Create still pays the
		// spawn + LoadSnapshot wall-clock. With the flag on, the refill
		// goroutine keeps DepthDefault paused-and-loaded VMMs per
		// warmable template, and Driver.Create's tryAcquireWarm consumes
		// them ahead of the cold-spawn fallback.
		//
		// Three adapters bridge the import-cycle wall:
		//
		//   - PoolSpawner satisfies vmmpool.Spawner against the driver's
		//     WarmSpawn (firecracker package depends on vmmpool, not vice
		//     versa).
		//
		//   - vmmTemplateListerAdapter satisfies vmmpool.TemplateLister by
		//     reading the service's template list and projecting only the
		//     fields the refill loop needs.
		//
		//   - fcDriver.SetWarmPool wires the runtime's Acquire path
		//     against the same Pool.
		//
		// The refill goroutine runs for the lifetime of the daemon; ctx
		// cancellation from the SIGINT/SIGTERM handler at the top of main
		// is what stops it. vmmPool.Close on graceful shutdown drains any
		// still-warm handles so the host doesn't get orphan firecracker
		// processes.
		if cfg.FirecrackerVMMPoolEnabled {
			vmmPool := vmmpool.New(db, logger)
			vmmPool.SetDefaultDepth(cfg.FirecrackerVMMPoolDepthDefault)
			fcDriver.SetWarmPool(vmmPool)
			lister := &vmmTemplateListerAdapter{svc: svc}
			spawner := fcruntime.NewPoolSpawner(fcDriver)
			refillCfg := vmmpool.RefillConfig{
				RefillInterval: cfg.FirecrackerVMMPoolRefillInterval,
				GCInterval:     cfg.FirecrackerVMMPoolGCInterval,
				GCTTL:          cfg.FirecrackerVMMPoolGCTTL,
				SpawnTimeout:   30 * time.Second,
			}
			go vmmPool.Run(ctx, refillCfg, lister, spawner)
			defer func() {
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer shutdownCancel()
				if drained := vmmPool.Close(shutdownCtx, 5*time.Second); drained > 0 {
					logger.Info("firecracker vmm pool drained on shutdown", "handles", drained)
				}
			}()
			logger.Info("firecracker vmm pool enabled",
				"depth_default", cfg.FirecrackerVMMPoolDepthDefault,
				"refill_interval", cfg.FirecrackerVMMPoolRefillInterval,
				"gc_interval", cfg.FirecrackerVMMPoolGCInterval,
				"gc_ttl", cfg.FirecrackerVMMPoolGCTTL)
		}
	}

	if cfg.EnableWasm {
		wasmPool := wireWasmRuntime(ctx, cfg, logger, svc, db)
		if wasmPool != nil {
			defer func() {
				if drained := wasmPool.Close(); drained > 0 {
					logger.Info("wasm warm pool drained on shutdown", "slots", drained)
				}
			}()
		}
	}

	// Cluster startup. Server-role nodes host Raft/FSM. Worker/ingress-only
	// nodes start a lightweight agent: gossip + owner-forward receiver +
	// control-plane RPC, but no Raft transport and no placement FSM copy.
	if cfg.EnableCluster {
		var (
			clusterClient cluster.Client
			err           error
		)
		if cfg.IsServer() {
			clusterClient, err = cluster.New(cfg, logger, admitter)
		} else {
			clusterClient, err = cluster.NewAgent(cfg, logger, admitter)
		}
		if err != nil {
			return fmt.Errorf("start cluster mode: %w", err)
		}
		defer func() {
			if err := clusterClient.Close(); err != nil {
				logger.Warn("cluster shutdown returned error", "error", err)
			}
		}()
		svc.AttachCluster(clusterClient)
		// The owner watcher needs a hook back into the service to recreate
		// sandboxes whose placements were reassigned to this node after a
		// dead-owner eviction. Wired here (after both objects exist) to keep
		// the cluster→service direction one-way through the SandboxRecreator
		// interface, avoiding an import cycle.
		if withRecreator, ok := clusterClient.(interface {
			AttachRecreator(cluster.SandboxRecreator)
		}); ok {
			withRecreator.AttachRecreator(svc)
		}
		// Phase 6 PR-D: template-aware placement. The capacity lease
		// cache asks the service for the local "ready" template
		// inventory at every heartbeat tick; the result is overlaid
		// onto the snapshot peers gossip. Single-node mode and
		// non-Firecracker nodes naturally degrade — the callback
		// stays nil and placement's unknown-allow rule does the rest.
		// When the callback reports known=true with an empty slice,
		// peers treat that as an authoritative "no local templates"
		// rather than legacy unknown. Gated on EnableFirecracker so
		// nodes that never serve templates don't pay the (cached)
		// SQLite read.
		if cfg.EnableFirecracker {
			if withTemplates, ok := clusterClient.(interface {
				SetLocalTemplateIDsProvider(func() ([]string, bool))
			}); ok {
				withTemplates.SetLocalTemplateIDsProvider(func() ([]string, bool) {
					return svc.LocalReadyTemplateInventory(context.Background())
				})
			}
		}
		if cfg.EnableWasm {
			if withModules, ok := clusterClient.(interface {
				SetLocalWasmModuleIDsProvider(func() ([]string, bool))
			}); ok {
				withModules.SetLocalWasmModuleIDsProvider(func() ([]string, bool) {
					return svc.LocalReadyWasmModuleInventory(context.Background())
				})
			}
		}
		logger.Info("cluster mode enabled",
			"node_id", clusterClient.SelfNodeID(),
			"api_url", clusterClient.SelfAPIURL(),
			"node_role", cfg.NodeRole,
			"control_plane_server", cfg.IsServer(),
			"gossip_bind", cfg.GossipBindAddr,
			"bootstrap", cfg.ClusterBootstrap,
			"peers", cfg.BootstrapPeers,
		)
	}

	// Bootstrap caddy-l4 at boot so the first L4 exposure isn't paying for
	// it. Best-effort by design: a cold-started caddy may still be coming
	// up, in which case the next ExposePort(tcp|tls) will retry under the
	// service's single-flight latch. Logging rather than exiting keeps the
	// daemon serving HTTP exposures even when L4 is misconfigured.
	//
	// Ingress nodes run caddy-l4 for SNI passthrough and raw TCP ingress;
	// worker/mixed nodes run it as the L4 termination side of the owner-local
	// path. Pure server nodes never serve sandbox traffic, so the L4 listener
	// would be wasted bind() syscalls.
	if cfg.IsWorker() || cfg.IsIngress() {
		if err := svc.EnsureLayer4Ready(ctx); err != nil {
			logger.Warn("failed to ensure caddy layer4 app at startup; will retry on first L4 exposure", "error", err)
		}
	}
	// Bootstrap the netstats poller at boot so the first /network/usage call
	// doesn't pay for it. Best-effort by design — failure here just means
	// counters stay at zero until the next attempt at lazy bootstrap.
	// Worker-only: pure ingress/server nodes own no sandboxes, so per-sandbox
	// netstats numbers would always be zero.
	if cfg.IsWorker() {
		if err := svc.EnsureNetstatsReady(ctx); err != nil {
			logger.Warn("failed to start netstats poller at startup", "error", err)
		}
		svc.ReplayReservations(ctx)
	}

	// Cluster ownership replay. After local reservations are restored, tell
	// the cluster which sandboxes this node owns so the FSM stays consistent
	// across restarts. Best-effort: a missing leader on cold start is retried
	// in the background. Only worker (and mixed) nodes can own sandboxes —
	// pure server/ingress nodes have nothing to assert.
	if cfg.EnableCluster {
		if cfg.IsWorker() {
			if !replayClusterOwnership(ctx, svc, logger) {
				startClusterOwnershipReplayRetry(ctx, svc, logger)
			}
		}
		if cfg.IsIngress() {
			svc.StartClusterIngressReconcile(ctx)
		}
	}

	// Bypass-flip rollback marker (D5 of plans/warm-direct-route-bypass.md).
	// HTTP routes installed under SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED=true point
	// straight at the container IP. Toggling the flag back to false does not
	// rewrite those routes on its own — a running serverless sandbox would
	// keep bypassing the wake-aware ingress proxy forever, defeating the
	// rollback. The marker file at ${dir(DBPath)}/bypass_last_enabled records
	// what the previous run used; if that says true and we now see false,
	// force one pass that republishes every serverless HTTP route through
	// installHTTPPortRoute (which reads the new cfg value via chooseRouteShape).
	// Worker-only: pure ingress/server nodes own no caddy routes for sandboxes.
	if cfg.IsWorker() {
		markerPath := filepath.Join(filepath.Dir(cfg.DBPath), "bypass_last_enabled")
		prevEnabled := readBypassMarker(markerPath)
		if prevEnabled && !cfg.HTTPWakeDirectBypassEnabled {
			logger.Info("bypass rollback detected; forcing http wake-shape reconcile",
				"marker_path", markerPath,
			)
			if err := svc.ForceReconcileHTTPWakeShape(ctx); err != nil {
				logger.Warn("force reconcile http wake shape failed", "error", err)
			}
		}
		if err := writeBypassMarker(markerPath, cfg.HTTPWakeDirectBypassEnabled); err != nil {
			logger.Warn("write bypass marker failed; rollback detection may misfire next boot",
				"marker_path", markerPath, "error", err)
		}
	}

	// Start the Caddy admin write coalescer on worker nodes so
	// installHTTPPortRoute's Flush path has the periodic-drain safety
	// net for any stranded ops (Flush callers whose ctx cancelled
	// before drain finished). Worker-only: non-worker nodes don't
	// install per-sandbox Caddy routes. See
	// plans/warm-direct-route-bypass.md D6/D12.
	if cfg.IsWorker() {
		svc.StartCaddyCoalescer(ctx)
	}

	// AutoReconcile / lifecycle sweep / event monitor / built-image GC are all
	// worker-side concerns — they reach into Docker, sandbox rows, and
	// per-container caddy routes. Pure server/ingress nodes have neither
	// docker nor sandbox state to reconcile.
	if cfg.IsWorker() {
		if cfg.AutoReconcile {
			if err := svc.Reconcile(ctx); err != nil {
				logger.Warn("initial reconcile failed", "error", err)
			}
			svc.StartReconcileLoop(ctx)
		}
		svc.StartLifecycleSweep(ctx)
		svc.StartEventMonitor(ctx)
		svc.StartBuiltImageGC(ctx)
		// Opt-in live CPU/memory sampler. No-op unless a usage reporter is wired
		// (managed build) and SB_FLEET_LIVE_SAMPLE_INTERVAL > 0; the reserved
		// axes are emitted from the reconcile/event/netstats loops regardless.
		svc.StartLiveUsageSampler(ctx)
		// Firecracker template janitor (plans/snapshot-clone-fast-boot.md
		// Phase 2). No-op when SB_ENABLE_FIRECRACKER=false or the GC
		// enable knob is off; per-tick cancellation is wired off ctx like
		// the other long-running sweeps above.
		svc.StartTemplateGC(ctx)
		if cfg.EnableWasm {
			svc.StartWasmModuleGC(ctx)
			svc.StartWasmPeriodicCheckpoint(ctx)
			svc.StartWasmDurablePushSweep(ctx)
		}
		svc.StartPendingImageGC(ctx)
		startAutoImportReconciler(ctx, logger, cfg, db, svc)
		startSnapshotPushReconciler(ctx, logger, cfg, db, svc, dockerClient)
		startTemplateArtifactPushReconciler(ctx, logger, cfg, db, svc, dockerClient)
		// Phase 6 PR 6-B.2: consumer-side puller. Symmetric with the
		// pusher above — once attached, EnsureTemplateLocal in the
		// resolver fetches missing artifacts from AOCR before a clone
		// boots. Gated on EnableFirecracker (templates only exist on
		// Firecracker nodes); does NOT require SnapshotPushEnabled
		// because a node may be configured to consume cluster artifacts
		// without producing any.
		attachTemplateArtifactPuller(logger, cfg, svc, dockerClient)
		// Phase 6 PR-E: opt-in template rotation. No-op unless both
		// FirecrackerTemplateRotationInterval and FirecrackerTemplateMaxAge
		// are set; default config leaves rotation off so operators have
		// to consciously enable rebuild-storm prevention.
		startTemplateRotationReconciler(ctx, logger, cfg, db, svc)
		// Phase 6 PR-A scanner: close the crash-mid-rebuild gap.
		// MarkSnapshotCorrupt flips a row to unhealthy and kicks an
		// async rebuild; if sandboxd died between the flip and the
		// rebuild completing, the row would be stuck unhealthy forever.
		// Gated on EnableFirecracker so non-Firecracker deployments
		// don't pay the (cheap) scan. Called after the snapshotter +
		// CID allocator wiring above (line ~290) so the rekicked
		// rebuilds find a working snapshot pipeline.
		if cfg.EnableFirecracker {
			svc.RekickUnhealthyTemplatesAtStart(ctx)
		}
		if cfg.AutoImportEnabled {
			// Wire the post-pull trigger: when the docker client finishes a
			// successful pull that BOTH used the mirror AND carried private
			// creds, the observer flips the sandbox row's auto_import_pending
			// flag. The reconciler then picks it up on its next sweep, calls
			// AOCR ImportAPI, and clears the flag on success. Worker-only:
			// non-worker nodes never pull sandbox images.
			dockerClient.SetPullObserver(func(obsCtx context.Context, sandboxID string) {
				// Use a fresh short-deadline context: the pull's ctx may be
				// cancelled before this fires (Docker ack races container
				// start), and a SQLite UPDATE is local and quick.
				flagCtx, flagCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer flagCancel()
				if err := db.SetAutoImportPending(flagCtx, sandboxID, true); err != nil {
					logger.Warn("auto-import: flag pending failed; reconciler will not retry",
						"sandbox_id", sandboxID, "error", err)
				}
			})
		}
	}

	if cfg.EnableSSHGateway && cfg.IsWorker() {
		gw, err := sshgateway.New(logger, sshgateway.Config{
			ListenAddr:  cfg.SSHListenAddr,
			HostKeyPath: cfg.SSHHostKeyPath,
			ToolboxPort: cfg.ToolboxPort,
		}, svc, dockerClient)
		if err != nil {
			return fmt.Errorf("create ssh gateway: %w", err)
		}
		go func() {
			if err := gw.Start(ctx); err != nil {
				logger.Warn("ssh gateway stopped", "error", err)
			}
		}()
	}

	// cp.Validator is the second-token (non-PAT) validation path. Under
	// controlplane.Noop() it rejects every non-PAT token, so the server
	// behaves exactly as the PAT-only build did before this seam existed.
	server := api.NewServer(logger, svc, dockerClient, cfg, cfg.PATToken, cp.Validator)
	logger.Info("dashboard available", "url", "http://"+cfg.ListenAddr()+"/ui")
	// Mount the same API handler onto the cluster-internal mTLS listener so
	// peers can reverse-proxy owner API calls over the cert-pinned channel
	// (not just leader-forwarded raft applies). Noop and TLS-disabled
	// Cluster instances drop the handler on the floor — the public path
	// keeps working unchanged.
	if cfg.EnableCluster {
		svc.Cluster().AttachInternalHandler(server.Handler())
	}
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("sandboxd stopped unexpectedly", "error", err)
			cancel()
		}
	}()

	// Wake-aware HTTP ingress proxy: a loopback-only listener Caddy
	// dials when forwarding a wake-aware port route. Stood up when
	// serverless OR custom-domains is enabled (and Caddy is in front —
	// without Caddy nothing routes to this listener). Both features
	// share the same mux so they share one loopback listener.
	var ingressServer *http.Server
	if (cfg.EnableServerless || cfg.EnableCustomDomains) && cfg.EnableCaddy {
		ingressMux := http.NewServeMux()
		if cfg.EnableServerless {
			ingressproxy.RegisterRoutes(ingressMux, ingressproxy.Deps{
				Resolver:             svc,
				Logger:               logger,
				MaxBufferBytes:       cfg.HTTPWakeMaxBuffer,
				UpstreamReadyTimeout: cfg.HTTPWakeUpstreamReadyTimeout,
				MaxPendingPerSandbox: cfg.HTTPWakeMaxPendingPerSandbox,
				MaxPendingGlobal:     cfg.HTTPWakeMaxPendingGlobal,
				MaxBufferBytesGlobal: cfg.HTTPWakeMaxBufferBytesGlobal,
			})
		}
		// Caddy on-demand TLS ask callback (plans/custom-domains.md).
		// db.ResolveCustomDomain is a PK lookup; the LRU negative cache
		// in the handler keeps SNI floods from hitting SQLite per packet.
		// Boot-time EnsureOnDemandTLS is best-effort — if Caddy is not
		// yet reachable we log and continue; the next AddCustomDomain
		// call surface still works because the handler is mounted, and
		// an operator-driven reconcile can re-install the policy later.
		if cfg.EnableCustomDomains {
			// Cluster-aware resolver: try the in-process FSM hostname index
			// first (PK lookup, no I/O) and fall back to the SQLite store on
			// miss. Under Noop the cluster lookup always returns ("", false)
			// so single-node mode keeps the existing PK-lookup behavior.
			// Under Cluster/Agent a hit short-circuits the disk read and
			// keeps the on-demand TLS ask path fully in-memory across the
			// cluster.
			// Daemon-wide ACME budget (OV5A): a per-node sliding window
			// over Let's Encrypt's per-account new-orders limit (300 / 3h
			// by default). One misconfigured tenant adding 100 custom
			// domains can drain the LE window for the whole cluster, so
			// every TLSAsk that would trigger a new issuance passes
			// through Reserve; a nil budget is allowed but disables the
			// brake — we wire one whenever custom domains are on.
			acmeBudget := service.NewACMEBudget(service.ACMEBudgetConfig{
				Capacity: cfg.ACMEDaemonBudgetCapacity,
				Window:   cfg.ACMEDaemonBudgetWindow,
				Fraction: cfg.ACMEDaemonBudgetFraction,
				Logger:   logger,
			})
			askHandler := ingressproxy.NewTLSAskHandler(ingressproxy.TLSAskDeps{
				Resolver:    clusterAwareDomainResolver{cluster: svc.Cluster(), store: db},
				BaseDomain:  cfg.Domain,
				NegCacheTTL: 60 * time.Second,
				NegCacheCap: 10000,
				Logger:      logger,
				Budget:      acmeBudget,
				Tracker:     ingressproxy.DefaultIssuanceTracker(),
			})
			ingressproxy.RegisterTLSAsk(ingressMux, askHandler)
			svc.AttachCustomDomainCacheEvicter(askHandler)
			askURL := "http://" + cfg.InternalIngressAddr + ingressproxy.TLSAskPath
			if err := caddyClient.EnsureOnDemandTLS(ctx, askURL, cfg.TLSOnDemandBurst, cfg.TLSOnDemandInterval); err != nil {
				logger.Warn("failed to install caddy on-demand TLS policy; will retry on next reconcile",
					"error", err, "ask_url", askURL)
			} else {
				logger.Info("caddy on-demand TLS policy installed",
					"ask_url", askURL, "burst", cfg.TLSOnDemandBurst, "interval", cfg.TLSOnDemandInterval)
			}
		}
		ingressServer = &http.Server{
			Addr:              cfg.InternalIngressAddr,
			Handler:           ingressMux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		logger.Info("ingress proxy listening",
			"addr", cfg.InternalIngressAddr,
			"serverless", cfg.EnableServerless,
			"custom_domains", cfg.EnableCustomDomains)
		go func() {
			if err := ingressServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("ingress proxy stopped unexpectedly", "error", err)
				cancel()
			}
		}()
		if cfg.EnableServerless {
			if err := svc.StartL4WakeProxy(ctx); err != nil {
				logger.Error("l4 wake proxy failed to start", "error", err)
				cancel()
			} else {
				logger.Info("wake-aware l4 proxy listening", "addr", cfg.InternalL4WakeAddr, "socket_dir", cfg.InternalL4WakeDir)
			}
		}
	}

	<-ctx.Done()
	logger.Info("shutting down sandboxd")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()
	if cfg.EnableWasm {
		if err := svc.DrainWasmSandboxes(shutdownCtx); err != nil {
			logger.Warn("wasm drain checkpoint failed", "error", err)
		}
	}
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("graceful shutdown failed", "error", err)
	}
	if ingressServer != nil {
		if err := ingressServer.Shutdown(shutdownCtx); err != nil {
			logger.Warn("ingress proxy graceful shutdown failed", "error", err)
		}
	}
	// Drain any pending Caddy admin writes before the process exits so
	// the last batch of route changes is not silently dropped. No-op on
	// nodes that never started the coalescer.
	svc.StopCaddyCoalescer()
	return nil
}

func replayClusterOwnership(ctx context.Context, svc *service.Service, logger *slog.Logger) bool {
	count, err := svc.ReplayClusterOwnership(ctx)
	if err != nil {
		logger.Warn("cluster: ownership replay failed; will retry", "error", err)
		return false
	}
	if count > 0 {
		logger.Info("cluster: ownership replay completed", "sandboxes", count)
	}
	return true
}

// clusterOwnershipReplayTick is the retry interval for ownership replay.
// Tests shrink it so the goroutine body is exercised without a 10s wait.
var clusterOwnershipReplayTick = 10 * time.Second

func startClusterOwnershipReplayRetry(ctx context.Context, svc *service.Service, logger *slog.Logger) {
	logger.Warn("cluster: scheduling ownership replay retry")
	go func() {
		t := time.NewTicker(clusterOwnershipReplayTick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				replayCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				ok := replayClusterOwnership(replayCtx, svc, logger)
				cancel()
				if ok {
					return
				}
			}
		}
	}()
}

// configureMirror loads the upstream wrap-key ring (if a path is set) and
// hands a built MirrorConfig to the docker client. Disabled-by-default:
// MirrorHost empty or upstream list empty means rewriting stays off and the
// docker client pulls from upstream registries directly.
//
// Wrap-key absence is a soft failure: we log a clear warning and configure
// the mirror without a ring. Public images still mirror cleanly (anonymous
// auth); private images will 401 against the mirror until the operator
// installs the key. This keeps the node bootable on a misconfigured wrap
// path rather than gating all pulls behind one secret.
func configureMirror(logger *slog.Logger, cfg config.Config, c *docker.Client) {
	if strings.TrimSpace(cfg.MirrorHost) == "" || len(cfg.MirrorUpstreams) == 0 {
		return
	}
	upstreams := make([]docker.MirrorUpstream, 0, len(cfg.MirrorUpstreams))
	for _, m := range cfg.MirrorUpstreams {
		upstreams = append(upstreams, docker.MirrorUpstream{Host: m.Host, Shortname: m.Shortname})
	}
	mcfg := docker.MirrorConfig{
		Host:      cfg.MirrorHost,
		PushHost:  cfg.MirrorPushHost,
		Upstreams: upstreams,
	}

	var ring *secrets.UpstreamWrapKeyRing
	if cfg.UpstreamWrapKeyPath != "" {
		r, err := secrets.LoadUpstreamWrapKeyRing(cfg.UpstreamWrapKeyPath)
		if err != nil {
			logger.Warn("mirror: upstream wrap key unavailable; private images via the mirror will 401 until the key is installed",
				"path", cfg.UpstreamWrapKeyPath, "error", err)
		} else {
			ring = r
		}
	} else {
		logger.Info("mirror: no upstream wrap key path configured; private-image pulls via the mirror are not supported on this node",
			"hint", "set SB_UPSTREAM_WRAP_KEY_PATH to enable wrapped-credential auth")
	}

	c.ConfigureMirror(mcfg, ring)
	logger.Info("mirror configured",
		"host", mcfg.Host,
		"push_host", mcfg.PushHost,
		"upstreams", len(mcfg.Upstreams),
		"wrap_key_loaded", ring != nil,
	)
}

// configureAOCRPullAuth installs the cluster-PAT credential the docker client
// uses to pull cluster-owned artifacts (snapshots + Firecracker templates) from
// AOCR's `cluster/<id>/*` namespace. It reuses the same host/cluster/PAT config
// as the producer-side snapshot and template pushers, so one credential covers
// push and pull symmetrically.
//
// Deliberately independent of SnapshotPushEnabled: a consume-only node (one that
// never produces artifacts but must pull snapshots/templates on failover or
// cross-node placement) still needs the pull credential. ConfigureAOCRPullAuth
// is a no-op when cluster_id or the PAT path is unset, so a node with no AOCR
// wiring keeps pulling anonymously exactly as before.
//
// This call itself runs once at boot and adds nothing to the create path. The
// only per-create cost it introduces lands later, in resolveAOCRPullAuth: a
// single node-local PAT file read, and only on a cache-miss pull of an AOCR
// `cluster/...` ref (warm pulls, non-AOCR refs, and caller-supplied creds all
// skip it). The fresh read is deliberate — it makes PAT rotation a file write.
func configureAOCRPullAuth(logger *slog.Logger, cfg config.Config, c *docker.Client) {
	clusterID := strings.TrimSpace(cfg.AutoImportClusterID)
	patPath := strings.TrimSpace(cfg.AutoImportClusterPATPath)
	if clusterID == "" || patPath == "" {
		return
	}
	// Cluster artifact refs target the AOCR push vhost (MirrorPushHost), with
	// ImageDistributionAOCRHost as the fallback both pushers also use. Pass both
	// so a ref under either host is recognized; ConfigureAOCRPullAuth dedups and
	// drops empties.
	hosts := []string{cfg.MirrorPushHost, cfg.ImageDistributionAOCRHost}
	c.ConfigureAOCRPullAuth(hosts, clusterID, patPath)
	logger.Info("aocr pull auth configured",
		"cluster_id", clusterID,
		"hosts", strings.Join(nonEmptyHosts(hosts), ","),
	)
}

// nonEmptyHosts is a tiny log helper: it filters blank host entries so the
// boot log line shows only the hosts actually in play.
func nonEmptyHosts(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if strings.TrimSpace(h) != "" {
			out = append(out, h)
		}
	}
	return out
}

// startAutoImportReconciler builds the F21 auto-import importer + reconciler
// and starts a ticker goroutine if the feature is enabled. When disabled (or
// when the importer fails to build) we log and return without scheduling
// anything — the rest of the daemon runs unchanged. The reconciler depends on
// the cluster client for replicated CreateSandboxRequest lookup; in
// standalone mode the noop cluster returns nil for every spec and the
// reconciler's `retryOne` will clear the flag with reason `no spec`. That's
// the right behavior: without a replicated spec there's no recreate path that
// could benefit from the import anyway.
func startAutoImportReconciler(ctx context.Context, logger *slog.Logger, cfg config.Config, db *store.Store, svc *service.Service) {
	if !cfg.AutoImportEnabled {
		return
	}
	pat, err := os.ReadFile(cfg.AutoImportClusterPATPath)
	if err != nil {
		logger.Warn("auto-import: PAT file unreadable; feature stays off until next restart",
			"path", cfg.AutoImportClusterPATPath, "error", err)
		return
	}
	importer, err := service.NewAutoImporter(service.AutoImportConfig{
		Enabled:         true,
		HooksBaseURL:    cfg.AutoImportHooksBaseURL,
		ClusterID:       cfg.AutoImportClusterID,
		ClusterPAT:      string(bytesTrimSpace(pat)),
		RetentionSuffix: cfg.AutoImportRetentionSuffix,
		RequestTimeout:  cfg.AutoImportRequestTimeout,
	})
	if err != nil {
		logger.Warn("auto-import: importer build failed; feature stays off",
			"error", err)
		return
	}
	resolver := autoImportSpecResolver{svc: svc}
	r := service.NewAutoImportReconciler(importer, db, resolver, logger, cfg.AutoImportMaxInFlight)
	if r == nil {
		// Should not happen when importer is non-nil, but defensive: don't
		// start a goroutine that has nothing to do.
		return
	}
	// Wire the spec write-back so successful imports flip the replicated
	// CreateSandboxRequest to ImageDistributionAOCRImported and point
	// ImageRegistryRef at the new cluster-side ref. Subsequent failovers
	// then pull through the cluster PAT, fully decoupled from the original
	// upstream credential.
	r.SetSpecMutator(svc)
	logger.Info("auto-import reconciler started",
		"hooks_url", importer.Endpoint(),
		"interval", cfg.AutoImportReconcileInterval,
		"max_in_flight", cfg.AutoImportMaxInFlight,
	)
	go func() {
		t := time.NewTicker(cfg.AutoImportReconcileInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				stats, err := r.RunOnce(ctx)
				if err != nil {
					logger.Warn("auto-import reconcile sweep failed", "error", err)
					continue
				}
				if stats.Scanned == 0 {
					continue
				}
				logger.Info("auto-import reconcile sweep",
					"scanned", stats.Scanned,
					"succeeded", stats.Succeeded,
					"failed", stats.Failed,
					"skipped", stats.Skipped,
				)
			}
		}
	}()
}

// startSnapshotPushReconciler builds the optional AOCR snapshot pusher +
// reconciler and starts a ticker goroutine if the feature is enabled. When
// disabled (or when the pusher fails to build) we log and return without
// scheduling anything — the snapshot path runs unchanged.
//
// Push host falls back to ImageDistributionAOCRHost when MirrorPushHost is
// unset; both have non-empty defaults so the destination is always
// resolvable. Auth reuses the auto-import cluster PAT path (re-read on
// every push so rotation works without a restart).
func startSnapshotPushReconciler(ctx context.Context, logger *slog.Logger, cfg config.Config, db *store.Store, svc *service.Service, dockerClient *docker.Client) {
	if !cfg.SnapshotPushEnabled {
		return
	}
	host := strings.TrimSpace(cfg.MirrorPushHost)
	if host == "" {
		host = strings.TrimSpace(cfg.ImageDistributionAOCRHost)
	}
	pusher, err := service.NewSnapshotPusher(service.SnapshotPushConfig{
		Enabled:   true,
		Host:      host,
		ClusterID: cfg.AutoImportClusterID,
		PATPath:   cfg.AutoImportClusterPATPath,
	}, dockerClient, logger)
	if err != nil {
		logger.Warn("snapshot push: pusher build failed; feature stays off",
			"error", err)
		return
	}
	r := service.NewSnapshotPushReconciler(pusher, db, logger, cfg.SnapshotPushMaxInFlight)
	if r == nil {
		return
	}
	svc.AttachSnapshotPusher(pusher, r)
	wasmPusher, err := service.NewWasmCheckpointPusher(service.SnapshotPushConfig{
		Enabled:   true,
		Host:      host,
		ClusterID: cfg.AutoImportClusterID,
		PATPath:   cfg.AutoImportClusterPATPath,
	}, logger)
	if err != nil {
		logger.Warn("wasm checkpoint push: pusher build failed; feature stays off",
			"error", err)
	} else {
		svc.AttachWasmCheckpointPusher(wasmPusher)
		logger.Info("wasm checkpoint push enabled", "host", host, "cluster_id", cfg.AutoImportClusterID)
	}
	logger.Info("snapshot push reconciler started",
		"host", host,
		"cluster_id", cfg.AutoImportClusterID,
		"interval", cfg.SnapshotPushReconcileInterval,
		"max_in_flight", cfg.SnapshotPushMaxInFlight,
	)
	go func() {
		t := time.NewTicker(cfg.SnapshotPushReconcileInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				stats, err := r.RunOnce(ctx)
				if err != nil {
					logger.Warn("snapshot push reconcile sweep failed", "error", err)
					continue
				}
				if stats.Scanned == 0 {
					continue
				}
				logger.Info("snapshot push reconcile sweep",
					"scanned", stats.Scanned,
					"succeeded", stats.Succeeded,
					"failed", stats.Failed,
					"skipped", stats.Skipped,
				)
			}
		}
	}()
}

// startTemplateRotationReconciler kicks off the Phase 6 PR-E rotation
// ticker. Opt-in: gated on EnableFirecracker AND a non-zero rotation
// interval AND a non-zero max-age. When either knob is zero we log and
// return — a "rotation interval set but max-age zero" config would
// scan every tick and find nothing, which is operator confusion we
// don't want to silently absorb.
//
// Mirrors startTemplateArtifactPushReconciler in shape so a single
// mental model covers both reconcilers: build → AttachX → goroutine
// driving RunOnce off a ticker.
func startTemplateRotationReconciler(ctx context.Context, logger *slog.Logger, cfg config.Config, db *store.Store, svc *service.Service) {
	if !cfg.EnableFirecracker {
		return
	}
	rotCfg := service.TemplateRotationConfig{
		Interval: cfg.FirecrackerTemplateRotationInterval,
		MaxAge:   cfg.FirecrackerTemplateMaxAge,
	}
	if cfg.FirecrackerTemplateRotationInterval > 0 && cfg.FirecrackerTemplateMaxAge == 0 {
		logger.Warn("template rotation: interval set but max-age is zero; rotation will not run",
			"interval", cfg.FirecrackerTemplateRotationInterval)
		return
	}
	if !rotCfg.IsEnabled() {
		return
	}
	adapter := &service.TemplateRotationStoreAdapter{Store: db}
	r, err := service.NewTemplateRotationReconciler(rotCfg, adapter, svc, logger)
	if err != nil {
		logger.Warn("template rotation: reconciler build failed; feature stays off",
			"error", err)
		return
	}
	if r == nil {
		return
	}
	logger.Info("template rotation reconciler started",
		"interval", rotCfg.Interval, "max_age", rotCfg.MaxAge)
	go func() {
		t := time.NewTicker(rotCfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				stats, err := r.RunOnce(ctx)
				if err != nil {
					logger.Warn("template rotation sweep failed", "error", err)
					continue
				}
				if stats.Scanned == 0 {
					continue
				}
				logger.Info("template rotation sweep",
					"scanned", stats.Scanned,
					"marked", stats.Marked,
					"skipped", stats.Skipped,
				)
			}
		}
	}()
}

// attachTemplateArtifactPuller wires the Phase 6 PR 6-B.2 consumer-side
// puller. No ticker — the puller fires on-demand from the resolver's
// EnsureTemplateLocal call. Returns early when Firecracker is off (no
// templates to pull) or when the templates dir is unset (the puller
// constructor would refuse anyway).
//
// Templates dir is the only producer-side config the puller actually
// needs: there's no PAT or cluster_id, because the puller uses whatever
// auth the daemon already has configured for the AOCR host (the same
// flow the AOCR-imported image distribution mode uses). This keeps
// pull-only nodes deployable without a sandboxd cluster PAT.
func attachTemplateArtifactPuller(logger *slog.Logger, cfg config.Config, svc *service.Service, dockerClient *docker.Client) {
	if !cfg.EnableFirecracker {
		return
	}
	if strings.TrimSpace(cfg.FirecrackerTemplatesDir) == "" {
		return
	}
	adapter := service.NewTemplateArtifactPullDockerAdapter(dockerClient)
	puller, err := service.NewTemplateArtifactPuller(adapter, cfg.FirecrackerTemplatesDir, logger)
	if err != nil {
		logger.Warn("template pull: puller build failed; feature stays off",
			"error", err)
		return
	}
	svc.AttachTemplateArtifactPuller(puller)
	logger.Info("template pull adapter attached",
		"templates_dir", cfg.FirecrackerTemplatesDir)
}

// startTemplateArtifactPushReconciler builds the optional AOCR template
// artifact pusher + reconciler (Phase 6 PR 6-B.1) and starts a ticker
// goroutine if the feature is enabled. Gated on EnableFirecracker AND
// SnapshotPushEnabled — templates only exist on Firecracker nodes, and
// the push pipeline reuses the snapshot-push auth/host/cluster config
// (no new config surface). When either gate is off we log and return;
// the template build path stays byte-identical to today.
//
// Reuses SnapshotPushReconcileInterval and SnapshotPushMaxInFlight as
// the cadence and fanout knobs — operator-tunable template-specific
// cadence is out of scope for this PR. A separate ticker keeps the
// two reconcilers independent so a stuck template push can't starve
// snapshot pushes.
func startTemplateArtifactPushReconciler(ctx context.Context, logger *slog.Logger, cfg config.Config, db *store.Store, svc *service.Service, dockerClient *docker.Client) {
	if !cfg.EnableFirecracker || !cfg.SnapshotPushEnabled {
		return
	}
	host := strings.TrimSpace(cfg.MirrorPushHost)
	if host == "" {
		host = strings.TrimSpace(cfg.ImageDistributionAOCRHost)
	}
	pusher, err := service.NewTemplateArtifactPusher(service.SnapshotPushConfig{
		Enabled:   true,
		Host:      host,
		ClusterID: cfg.AutoImportClusterID,
		PATPath:   cfg.AutoImportClusterPATPath,
	}, dockerClient, cfg.FirecrackerTemplatesDir, logger)
	if err != nil {
		logger.Warn("template push: pusher build failed; feature stays off",
			"error", err)
		return
	}
	r := service.NewTemplateArtifactPushReconciler(pusher, db, logger, cfg.SnapshotPushMaxInFlight)
	if r == nil {
		return
	}
	svc.AttachTemplateArtifactPusher(pusher, r)
	logger.Info("template push reconciler started",
		"host", host,
		"cluster_id", cfg.AutoImportClusterID,
		"interval", cfg.SnapshotPushReconcileInterval,
		"max_in_flight", cfg.SnapshotPushMaxInFlight,
	)
	go func() {
		t := time.NewTicker(cfg.SnapshotPushReconcileInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				stats, err := r.RunOnce(ctx)
				if err != nil {
					logger.Warn("template push reconcile sweep failed", "error", err)
					continue
				}
				if stats.Scanned == 0 {
					continue
				}
				logger.Info("template push reconcile sweep",
					"scanned", stats.Scanned,
					"succeeded", stats.Succeeded,
					"failed", stats.Failed,
					"skipped", stats.Skipped,
				)
			}
		}
	}()
}

// autoImportSpecResolver adapts the service+cluster surface to the
// AutoImportSpecResolver interface. The replicated CreateSandboxRequest lives
// in the cluster FSM (via cluster.SpecOf); we go through svc.Cluster() so the
// adapter works under both Noop (standalone) and Cluster/Agent modes.
type autoImportSpecResolver struct {
	svc *service.Service
}

func (r autoImportSpecResolver) GetSandboxSpec(sandboxID string) (*models.CreateSandboxRequest, bool) {
	c := r.svc.Cluster()
	if c == nil {
		return nil, false
	}
	spec := c.SpecOf(sandboxID)
	if spec == nil {
		return nil, false
	}
	return spec, true
}

// clusterAwareDomainResolver answers TLS-ask lookups from the cluster FSM
// first and falls back to the local store on miss. The cluster path is an
// in-memory map lookup (placementFSM.customHostnameIndex) so the hot path
// for an SNI flood does not hit SQLite once the FSM is populated. The
// store fallback covers two cases: (a) Noop / single-node mode where the
// cluster always reports miss, and (b) the brief window after a leader
// change before the local FSM has caught up on a fresh peer.
//
// We return store.ErrNotFound on miss so the handler's existing branching
// (negative-cache + 403) treats both backends identically. A nil cluster
// can't happen in practice (svc.Cluster() always returns at least Noop),
// but we null-check defensively rather than panic from the ask path.
type clusterAwareDomainResolver struct {
	cluster cluster.Client
	store   *store.Store
}

func (r clusterAwareDomainResolver) ResolveCustomDomain(ctx context.Context, hostname string) (string, error) {
	if r.cluster != nil {
		if id, ok := r.cluster.ResolveCustomDomain(hostname); ok {
			return id, nil
		}
	}
	return r.store.ResolveCustomDomain(ctx, hostname)
}

// bytesTrimSpace is a tiny helper so we don't pull `strings` for one call —
// PAT files commonly include a trailing newline.
func bytesTrimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// readBypassMarker returns true iff the marker file exists AND its content
// is "true". A missing or unreadable marker reads as false — first boot
// after a daemon upgrade looks identical to "previous run had bypass off",
// which is the safer default (no force-reconcile, no surprise route
// churn). The marker is plain text, not JSON or expvar, so an operator
// can `cat` it during incident response without booting the daemon.
func readBypassMarker(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return string(bytesTrimSpace(data)) == "true"
}

func appendRuntimeIfMissing(runtimes []string, runtimeName string) []string {
	runtimeName = strings.TrimSpace(runtimeName)
	if runtimeName == "" {
		return runtimes
	}
	for _, existing := range runtimes {
		if strings.TrimSpace(existing) == runtimeName {
			return runtimes
		}
	}
	return append(runtimes, runtimeName)
}

// writeBypassMarker persists the current bypass flag for the next boot's
// rollback check. Uses a tmp-then-rename so a daemon crash mid-write
// cannot leave a truncated marker that would later be misread as
// `false` (and silently mask a true→false flip on the next boot).
func writeBypassMarker(path string, enabled bool) error {
	value := "false"
	if enabled {
		value = "true"
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(value+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// firecrackerPoolAdapter wraps a *tap.Pool so it satisfies the
// fcruntime.TapPool interface. The interface and the concrete pool are
// in different packages on purpose (the firecracker runtime test binary
// stays light — it doesn't need a real SQLite store), and this thin
// adapter is the single conversion point between the two Slot shapes.
// Adding/renaming a Slot field requires touching both ends; the linter
// will catch a mismatch at compile time.
type firecrackerPoolAdapter struct {
	inner *tap.Pool
}

func (a *firecrackerPoolAdapter) Allocate(ctx context.Context, sandboxID string, now time.Time) (*fcruntime.TapSlot, error) {
	s, err := a.inner.Allocate(ctx, sandboxID, now)
	if err != nil {
		return nil, err
	}
	return adaptTapSlot(s), nil
}

func (a *firecrackerPoolAdapter) Release(ctx context.Context, sandboxID string) error {
	return a.inner.Release(ctx, sandboxID)
}

func (a *firecrackerPoolAdapter) Get(ctx context.Context, sandboxID string) (*fcruntime.TapSlot, error) {
	s, err := a.inner.Get(ctx, sandboxID)
	if err != nil || s == nil {
		return nil, err
	}
	return adaptTapSlot(s), nil
}

// firecrackerRootfsAdapter wraps *pkg/oci.Builder so it satisfies the
// fcruntime.RootfsBuilder interface. Same import-cycle isolation
// reason as firecrackerPoolAdapter: the runtime test binary stays
// independent of pkg/oci's subprocess machinery.
type firecrackerRootfsAdapter struct {
	inner *oci.Builder
}

func (a *firecrackerRootfsAdapter) Build(ctx context.Context, req fcruntime.RootfsBuildRequest) (*fcruntime.RootfsResult, error) {
	res, err := a.inner.Build(ctx, oci.BuildRequest{
		ImageRef:   req.ImageRef,
		OutPath:    req.OutPath,
		MinSizeMiB: req.MinSizeMiB,
		Tag:        req.Tag,
	})
	if err != nil {
		return nil, err
	}
	return fcruntime.NewRootfsResult(res.RootfsPath, res.StagingDir, res.SizeBytes, res.CleanupDir), nil
}

// firecrackerTapHostAdapter wraps *tap.Host so it satisfies
// fcruntime.TapHost. Translates between the package-local Slot and
// the runtime-package mirror. Same shape as firecrackerPoolAdapter.
type firecrackerTapHostAdapter struct {
	inner *tap.Host
}

func (a *firecrackerTapHostAdapter) Ensure(ctx context.Context, slot fcruntime.TapSlot) error {
	return a.inner.Ensure(ctx, tap.Slot{
		TapName:  slot.TapName,
		CIDR:     slot.CIDR,
		HostIP:   slot.HostIP,
		GuestIP:  slot.GuestIP,
		VsockCID: slot.VsockCID,
	})
}

func (a *firecrackerTapHostAdapter) Remove(ctx context.Context, tapName string) error {
	return a.inner.Remove(ctx, tapName)
}

func adaptTapSlot(s *tap.Slot) *fcruntime.TapSlot {
	if s == nil {
		return nil
	}
	return &fcruntime.TapSlot{
		TapName:  s.TapName,
		CIDR:     s.CIDR,
		HostIP:   s.HostIP,
		GuestIP:  s.GuestIP,
		VsockCID: s.VsockCID,
	}
}

// templateBuilderAdapter wraps *pkg/oci.Builder so it satisfies
// service.TemplateBuilder. Same import-cycle isolation reason as the
// rootfs adapter above — internal/service does not import pkg/oci, so
// the translation lives at the wiring layer where both packages are
// already in scope.
type templateBuilderAdapter struct {
	inner *oci.Builder
}

func (a *templateBuilderAdapter) Build(ctx context.Context, req service.TemplateBuildRequest) (*service.TemplateBuildResult, error) {
	res, err := a.inner.Build(ctx, oci.BuildRequest{
		ImageRef:   req.ImageRef,
		OutPath:    req.OutPath,
		MinSizeMiB: req.MinSizeMiB,
		Tag:        req.Tag,
	})
	if err != nil {
		return nil, err
	}
	return &service.TemplateBuildResult{
		RootfsPath: res.RootfsPath,
		StagingDir: res.StagingDir,
		SizeBytes:  res.SizeBytes,
	}, nil
}

// templateResolverAdapter satisfies fcruntime.TemplateResolver by
// looking up the template row through the service layer. The runtime
// driver can't import internal/service directly (cycle: service depends
// on the runtime package), so the daemon-level wiring layer brokers the
// call. A template that hasn't reached READY is rejected here rather
// than at the driver so the driver returns a structured error to the
// API caller instead of staging a half-built rootfs.
type templateResolverAdapter struct {
	svc *service.Service
}

func (a *templateResolverAdapter) Resolve(ctx context.Context, id string) (*fcruntime.TemplateResolution, error) {
	t, err := a.svc.GetTemplate(ctx, id)
	if err != nil {
		return nil, err
	}
	// ready and ready_no_snapshot expose a usable rootfs; only the
	// former carries snapshot artifacts. unhealthy (Phase 6 PR-A) is
	// "snapshot worked once and is now corrupt" — has_snapshot is cleared
	// by MarkTemplateUnhealthy so the driver naturally falls back to
	// cold-build at driver.go:577 until the async rebuild restores
	// status=ready. Anything else (pending/building/failed) has no
	// rootfs the driver can boot from.
	if t.Status != models.TemplateStatusReady &&
		t.Status != models.TemplateStatusReadyNoSnapshot &&
		t.Status != models.TemplateStatusUnhealthy {
		return nil, fmt.Errorf("template %q is %s, not ready", id, t.Status)
	}
	if t.RootfsPath == "" {
		return nil, fmt.Errorf("template %q is %s but has no rootfs path", id, t.Status)
	}
	// Phase 6 PR 6-B.2: if the row was pushed from another node and our
	// local files are missing, fetch+extract from AOCR under a per-
	// template single-flight before handing the paths to the driver.
	// EnsureTemplateLocal is a fast no-op when the puller is not
	// attached (single-node mode), when registry_ref is blank (this
	// node was the producer), or when the files are already on disk.
	// Boot-path call-out: on the first miss for a template this blocks
	// on docker pull of the template OCI image (rootfs.ext4 layer is
	// the bulk — bounded by image size + link speed). The atomic.Bool
	// latch makes every subsequent create against the same template a
	// single load.
	if err := a.svc.EnsureTemplateLocal(ctx, t); err != nil {
		return nil, fmt.Errorf("template %q: ensure local: %w", id, err)
	}
	return &fcruntime.TemplateResolution{
		RootfsPath:         t.RootfsPath,
		HasSnapshot:        t.HasSnapshot,
		HasOverlay:         t.HasOverlay,
		SnapshotMemoryPath: t.SnapshotMemoryPath,
		SnapshotStatePath:  t.SnapshotStatePath,
		SnapshotChecksum:   t.SnapshotChecksum,
		SnapshotVsockCID:   t.SnapshotVsockCID,
	}, nil
}

// firecrackerTemplateSnapshotterAdapter satisfies
// service.TemplateSnapshotter by forwarding to *fcruntime.Driver. The
// snapshotter and the runtime driver share the same VMM/network seams,
// so it's the natural home for the transient-VMM lifecycle that snapshot
// capture needs; the adapter exists only so the service package never
// imports the runtime package directly (which would be a cycle through
// service.SetFirecrackerRuntime).
type firecrackerTemplateSnapshotterAdapter struct {
	driver *fcruntime.Driver
}

func (a *firecrackerTemplateSnapshotterAdapter) SnapshotTemplate(ctx context.Context, req service.TemplateSnapshotRequest) (*service.TemplateSnapshotResult, error) {
	res, err := a.driver.SnapshotTemplate(ctx, fcruntime.TemplateSnapshotRequest{
		TemplateID:    req.TemplateID,
		RootfsPath:    req.RootfsPath,
		OutMemoryPath: req.OutMemoryPath,
		OutStatePath:  req.OutStatePath,
		GuestCID:      req.GuestCID,
		MemoryMB:      req.MemoryMB,
		VCPU:          req.VCPU,
	})
	if err != nil {
		return nil, err
	}
	return &service.TemplateSnapshotResult{
		MemorySizeBytes: res.MemorySizeBytes,
		StateSizeBytes:  res.StateSizeBytes,
		Checksum:        res.Checksum,
	}, nil
}

// firecrackerCIDAllocatorAdapter satisfies service.TemplateCIDAllocator
// by reusing the per-sandbox TAP pool with a synthetic "template:<id>"
// sandbox key. The pool's per-id PK gives idempotent reservation: a
// second AllocateForTemplate on the same id returns the same CID rather
// than burning a slot. PR-A's "one clone per template per host" limit
// is what makes this safe — a future per-template CID pool lands in
// Phase 4 alongside the warm pool.
type firecrackerCIDAllocatorAdapter struct {
	pool *tap.Pool
}

func (a *firecrackerCIDAllocatorAdapter) AllocateForTemplate(ctx context.Context, templateID string) (uint32, error) {
	slot, err := a.pool.Allocate(ctx, "template:"+templateID, time.Now())
	if err != nil {
		return 0, err
	}
	return slot.VsockCID, nil
}

func (a *firecrackerCIDAllocatorAdapter) ReleaseForTemplate(ctx context.Context, templateID string) error {
	return a.pool.Release(ctx, "template:"+templateID)
}

// vmmTemplateListerAdapter satisfies vmmpool.TemplateLister by walking
// the service's template list and projecting only the snapshot
// artifacts the refill goroutine needs. Filters to templates whose
// snapshot is actually loadable (status=ready AND HasSnapshot AND
// non-empty artifact paths) so the refill loop never wastes a Spawn
// on a row the runtime would reject.
//
// The vmmpool package can't import internal/service (cycle: service
// would then import vmmpool through the runtime adapter), so this
// daemon-level adapter brokers the call.
type vmmTemplateListerAdapter struct {
	svc *service.Service
}

func (a *vmmTemplateListerAdapter) ListWarmableTemplates(ctx context.Context) ([]vmmpool.TemplateWarmInput, error) {
	templates, err := a.svc.ListTemplates(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]vmmpool.TemplateWarmInput, 0, len(templates))
	for _, t := range templates {
		if t.Status != models.TemplateStatusReady || !t.HasSnapshot {
			continue
		}
		if t.SnapshotMemoryPath == "" || t.SnapshotStatePath == "" {
			continue
		}
		out = append(out, vmmpool.TemplateWarmInput{
			TemplateID:         t.ID,
			SnapshotMemoryPath: t.SnapshotMemoryPath,
			SnapshotStatePath:  t.SnapshotStatePath,
			SnapshotChecksum:   t.SnapshotChecksum,
			VsockCID:           t.SnapshotVsockCID,
		})
	}
	return out, nil
}

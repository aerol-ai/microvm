package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/observability"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/internal/version"
	api "github.com/aerol-ai/microvm/pkg/api"
	"github.com/aerol-ai/microvm/pkg/api/ingressproxy"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"github.com/aerol-ai/microvm/pkg/sshgateway"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	logger.Info("starting sandboxd", "version", version.Version, "addr", cfg.ListenAddr())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

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
		logger.Error("failed to open store", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	rules, err := netrules.New(cfg.EnableNetworkRules)
	if err != nil {
		logger.Error("failed to create netrules manager", "error", err)
		os.Exit(1)
	}

	dockerClient, err := docker.New(logger, cfg, rules)
	if err != nil {
		logger.Error("failed to create docker client", "error", err)
		os.Exit(1)
	}
	configureMirror(logger, cfg, dockerClient)

	caddyClient := caddy.New(cfg)

	cipher, err := secrets.NewCipher(cfg.CredentialEncryptionKey, cfg.CredentialEncryptionKeyPath)
	if err != nil {
		logger.Error("failed to initialize credential cipher", "error", err)
		os.Exit(1)
	}

	mountManager, err := mounts.New(logger, mounts.Config{
		RootDir:     cfg.MountsRootPath,
		CredDir:     cfg.MountsCredentialsRuntimeDir,
		WaitTimeout: cfg.MountWaitTimeout,
	})
	if err != nil {
		logger.Error("failed to initialize mount manager", "error", err)
		os.Exit(1)
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
	admitter := capacity.New(host, capacity.Limits{
		CPUReservationRatio:       cfg.CPUReservationRatio,
		MemoryReservationRatio:    cfg.MemoryReservationRatio,
		DiskReservationRatio:      cfg.DiskReservationRatio,
		MemoryFloorRatio:          cfg.MemoryFloorRatio,
		CPUOverProvisionFactor:    cfg.CPUOverProvisionFactor,
		MemoryOverProvisionFactor: cfg.MemoryOverProvisionFactor,
	}, capacity.NewProcMeminfoProbe())
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
	)

	// dockerClient is passed twice: as the runtime.Runtime driver (the
	// abstraction service uses for sandbox lifecycle) and as the concrete
	// *docker.Client used for the daemon /events stream. They point at the
	// same instance today; the split exists so a future non-Docker runtime
	// can replace the first without touching the second.
	svc := service.New(cfg, logger, db, dockerClient, dockerClient, caddyClient, cipher, mountManager, admitter)

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
			logger.Error("failed to start cluster mode", "error", err)
			os.Exit(1)
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
		svc.StartPendingImageGC(ctx)
		startAutoImportReconciler(ctx, logger, cfg, db, svc)
		startSnapshotPushReconciler(ctx, logger, cfg, db, svc, dockerClient)
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
			logger.Error("failed to create ssh gateway", "error", err)
			os.Exit(1)
		}
		go func() {
			if err := gw.Start(ctx); err != nil {
				logger.Warn("ssh gateway stopped", "error", err)
			}
		}()
	}

	server := api.NewServer(logger, svc, dockerClient, cfg, cfg.PATToken)
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

func startClusterOwnershipReplayRetry(ctx context.Context, svc *service.Service, logger *slog.Logger) {
	logger.Warn("cluster: scheduling ownership replay retry")
	go func() {
		t := time.NewTicker(10 * time.Second)
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

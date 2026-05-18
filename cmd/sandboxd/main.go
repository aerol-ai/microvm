package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/internal/version"
	api "github.com/aerol-ai/microvm/pkg/api"
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
	if cfg.HostCPUCoresOverride > 0 {
		host.CPUCores = cfg.HostCPUCoresOverride
	}
	if cfg.HostMemoryMBOverride > 0 {
		host.MemoryTotalMB = cfg.HostMemoryMBOverride
	}
	host.DiskTotalGB = cfg.HostDiskGB
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
	// across restarts. Best-effort: a missing leader on cold start is logged
	// and recovered by the next reconcile or the next mutating call. Only
	// worker (and mixed) nodes can own sandboxes — pure server/ingress nodes
	// have nothing to assert.
	if cfg.EnableCluster {
		if cfg.IsWorker() {
			states, err := localSandboxStates(ctx, svc, logger)
			if err != nil {
				logger.Warn("cluster: could not list local sandbox states for ownership replay", "error", err)
			} else if err := svc.Cluster().AssertOwnership(ctx, states); err != nil {
				logger.Warn("cluster: AssertOwnership returned error at boot; reconcile will retry", "error", err)
			}
		}
		if cfg.IsIngress() {
			svc.StartClusterIngressReconcile(ctx)
		}
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

	<-ctx.Done()
	logger.Info("shutting down sandboxd")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("graceful shutdown failed", "error", err)
	}
}

// localSandboxStates returns boot-replay payloads for every sandbox in the
// local store. Each entry carries the persisted Sandbox's identity, a derived
// CreateSandboxRequest, and the set of currently-exposed (port, protocol)
// intents — enough for AssertOwnership to backfill spec + ports for sandboxes
// that pre-date the spec-replication features.
//
// Registry credentials are unsealed via svc.UnsealRegistry so the backfilled
// spec carries the original auth — required for failover to re-pull a private
// image on a new owner. A decrypt failure on a single sandbox is logged and
// the spec falls back to nil-Registry rather than aborting boot for the
// whole fleet.
func localSandboxStates(ctx context.Context, svc *service.Service, logger *slog.Logger) ([]cluster.LocalSandboxState, error) {
	sandboxes, err := svc.ListSandboxes(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := make([]cluster.LocalSandboxState, 0, len(sandboxes))
	for _, sb := range sandboxes {
		if sb == nil || sb.ID == "" {
			continue
		}
		spec := specFromSandbox(svc, sb, logger)
		// Seal credentials and redact the spec BEFORE handing it to the
		// cluster — the cluster layer never sees plaintext registry passwords.
		// On seal failure we still ship the placement (without secrets) so
		// the cluster knows about the sandbox; the next failover-recreate
		// will be unable to pull a private image, which the recreator logs
		// loudly, but losing replication entirely would be worse.
		var sealed []byte
		if spec != nil {
			recipient := ""
			if c := svc.Cluster(); c != nil {
				recipient = c.SelfNodeID()
			}
			s, err := svc.SealClusterSecretsForRecipient(*spec, recipient)
			if err != nil {
				logger.Warn("cluster: seal secrets at boot replay failed; placement will ship without sealed bag",
					"sandbox_id", sb.ID, "err", err)
			} else {
				sealed = s
				redacted := service.RedactClusterSecrets(*spec)
				spec = &redacted
			}
		}
		out = append(out, cluster.LocalSandboxState{
			ID:            sb.ID,
			Spec:          spec,
			SealedSecrets: sealed,
			ExposedPorts:  portsFromSandbox(sb),
		})
	}
	return out, nil
}

// specFromSandbox derives a CreateSandboxRequest from a persisted Sandbox row.
// Used only for the pre-cluster backfill path — new sandboxes get their full
// spec replicated at create time via clusterCreateWrap.
func specFromSandbox(svc *service.Service, sb *models.Sandbox, logger *slog.Logger) *models.CreateSandboxRequest {
	if sb == nil {
		return nil
	}
	spec := &models.CreateSandboxRequest{
		Image:            sb.Image,
		CPU:              sb.CPU,
		MemoryMB:         sb.MemoryMB,
		DiskGB:           sb.DiskGB,
		Env:              sb.Env,
		OSUser:           sb.OSUser,
		NetworkBlockAll:  sb.NetworkBlockAll,
		ContainerCommand: sb.ContainerCommand,
		Runtime:          sb.Runtime,
		GPUs:             sb.GPUs,
	}
	// Lifecycle on Sandbox is value-typed; spec wants a pointer so the JSON
	// "omitempty" stays meaningful for fresh creates that didn't pass one.
	lc := sb.Lifecycle
	spec.Lifecycle = &lc

	// Sealed only when the original create supplied a private registry. A
	// decrypt failure here is non-fatal: we keep the spec but drop Registry,
	// matching the legacy behaviour where the new owner relies on its image
	// cache. Loud-warn so the misconfiguration shows up in logs.
	auth, err := svc.UnsealRegistry(sb.RegistryAuthSealed)
	if err != nil {
		logger.Warn("cluster: unseal registry auth failed; spec backfill will omit credentials",
			"sandbox_id", sb.ID, "err", err)
	} else {
		spec.Registry = auth
	}
	return spec
}

// portsFromSandbox extracts the routing intents the sandbox currently has
// exposed. Raw TCP includes HostPort so cluster ingress can keep a stable
// public port across owner-aware routers and failover recreates when possible.
func portsFromSandbox(sb *models.Sandbox) map[int]cluster.ExposedPortRoute {
	if sb == nil || len(sb.ExposedPorts) == 0 {
		return nil
	}
	out := make(map[int]cluster.ExposedPortRoute, len(sb.ExposedPorts))
	for _, p := range sb.ExposedPorts {
		if p.Port <= 0 {
			continue
		}
		out[p.Port] = cluster.ExposedPortRoute{
			Protocol:  p.Protocol,
			HostPort:  p.HostPort,
			PublicURL: p.PublicURL,
		}
	}
	return out
}

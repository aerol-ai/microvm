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

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/internal/version"
	api "github.com/aerol-ai/microvm/pkg/api"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
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
	admitter := capacity.New(host, capacity.Limits{
		CPUReservationRatio:       cfg.CPUReservationRatio,
		MemoryReservationRatio:    cfg.MemoryReservationRatio,
		MemoryFloorRatio:          cfg.MemoryFloorRatio,
		CPUOverProvisionFactor:    cfg.CPUOverProvisionFactor,
		MemoryOverProvisionFactor: cfg.MemoryOverProvisionFactor,
	}, capacity.NewProcMeminfoProbe())
	logger.Info("capacity admission configured",
		"host_cpu_cores", host.CPUCores,
		"host_memory_mb", host.MemoryTotalMB,
		"cpu_reservation_ratio", cfg.CPUReservationRatio,
		"memory_reservation_ratio", cfg.MemoryReservationRatio,
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
	// Bootstrap caddy-l4 at boot so the first L4 exposure isn't paying for
	// it. Best-effort by design: a cold-started caddy may still be coming
	// up, in which case the next ExposePort(tcp|tls) will retry under the
	// service's single-flight latch. Logging rather than exiting keeps the
	// daemon serving HTTP exposures even when L4 is misconfigured.
	if err := svc.EnsureLayer4Ready(ctx); err != nil {
		logger.Warn("failed to ensure caddy layer4 app at startup; will retry on first L4 exposure", "error", err)
	}
	// Bootstrap the netstats poller at boot so the first /network/usage call
	// doesn't pay for it. Best-effort by design — failure here just means
	// counters stay at zero until the next attempt at lazy bootstrap.
	if err := svc.EnsureNetstatsReady(ctx); err != nil {
		logger.Warn("failed to start netstats poller at startup", "error", err)
	}
	svc.ReplayReservations(ctx)

	if cfg.AutoReconcile {
		if err := svc.Reconcile(ctx); err != nil {
			logger.Warn("initial reconcile failed", "error", err)
		}
		svc.StartReconcileLoop(ctx)
	}
	svc.StartLifecycleSweep(ctx)
	svc.StartEventMonitor(ctx)

	if cfg.EnableSSHGateway {
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

	server := api.NewServer(logger, svc, cfg.PATToken)
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

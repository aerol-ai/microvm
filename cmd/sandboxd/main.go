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

	"github.com/aerolai/sandbox-library/internal/config"
	"github.com/aerolai/sandbox-library/internal/service"
	"github.com/aerolai/sandbox-library/internal/store"
	"github.com/aerolai/sandbox-library/internal/version"
	api "github.com/aerolai/sandbox-library/pkg/api"
	"github.com/aerolai/sandbox-library/pkg/caddy"
	"github.com/aerolai/sandbox-library/pkg/docker"
	"github.com/aerolai/sandbox-library/pkg/docker/netrules"
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
	svc := service.New(cfg, logger, db, dockerClient, caddyClient)

	if cfg.AutoReconcile {
		if err := svc.Reconcile(ctx); err != nil {
			logger.Warn("initial reconcile failed", "error", err)
		}
	}
	svc.StartIdleMonitor(ctx)

	server := api.NewServer(logger, svc, cfg.APIToken)
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

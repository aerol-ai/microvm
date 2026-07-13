package daemon

import (
	"context"
	"log/slog"
	"strings"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// containerdEngineWiring holds containerd-only background workers torn down on
// daemon shutdown.
type containerdEngineWiring struct {
	netns  *containerdNetnsPool
	warm   *containerdpool.Pool
	driver *cntr.Driver
	logger *slog.Logger
}

func (w *containerdEngineWiring) Stop() {
	if w == nil {
		return
	}
	if w.netns != nil {
		w.netns.Stop()
	}
	drainContainerdWarmPool(w.warm, w.logger)
}

func wireContainerdWarmPool(ctx context.Context, cfg config.Config, logger *slog.Logger, driver *cntr.Driver, admitter *capacity.Admitter) *containerdpool.Pool {
	if !cfg.ContainerdPoolEffective() {
		if cfg.ContainerdPoolEnabled && !cfg.DockerReadySocketEnabled {
			logger.Warn("containerd warm pool disabled: SB_DOCKER_READY_SOCKET_ENABLED=false")
		}
		return nil
	}
	if driver == nil {
		return nil
	}
	pool := containerdpool.New(logger)
	pool.SetDefaultDepth(cfg.ContainerdPoolDepth)
	pool.SetMaxImages(cfg.ContainerdPoolMaxImages)
	pool.SetIdleTTL(cfg.ContainerdPoolIdleTTL)

	parkShape := dockerpool.ParkShape{
		CPU:      models.DefaultCPU,
		MemoryMB: models.DefaultMemoryMB,
		DiskGB:   models.DefaultDiskGB,
		Runtime:  cfg.Runtime,
	}
	gate := &capacity.ParkGate{
		Admitter: admitter,
		GuardShape: capacity.Request{
			CPU:      parkShape.CPU,
			MemoryMB: parkShape.MemoryMB,
			DiskGB:   parkShape.DiskGB,
			Runtime:  parkShape.Runtime,
		},
	}
	pool.SetParkReleaser(gate.ReleasePark)
	driver.SetWarmPool(pool)

	// Image-ID cache (docker StartImageIDCacheWarmer) is intentionally NOT
	// ported: containerd GetImage is a local metadata read, so the Tier-1
	// docker cache rider does not pay for itself here (plans/containerd-engine.md
	// §9.2). Re-measure only if a cold-create profile shows ResolveImage as hot.

	images := cfg.ContainerdPoolImages
	if len(images) == 0 {
		images = []string{"alpine:3.20"}
	}
	for _, image := range images {
		image = strings.TrimSpace(image)
		if image == "" {
			continue
		}
		pool.PinTarget(containerdpool.Key{
			Image:   image,
			Runtime: cfg.Runtime,
		})
	}

	if purged, err := driver.PurgeParkedContainers(ctx); err != nil {
		logger.Warn("containerd warm pool boot purge failed", "error", err)
	} else if purged > 0 {
		logger.Info("containerd warm pool boot purge", "containers", purged)
	}

	spawner := &cntr.PoolSpawner{Driver: driver}
	pool.SetSpawner(spawner)
	refillCfg := dockerpool.RefillConfig{
		RefillInterval: cfg.ContainerdPoolRefillInterval,
		SpawnTimeout:   cfg.DockerRuntimeWaitTimeout,
		IdleTTL:        cfg.ContainerdPoolIdleTTL,
		ParkShape:      parkShape,
	}
	go dockerpool.RunRefill(ctx, pool, refillCfg, spawner, gate, logger)

	logger.Info("containerd warm pool enabled",
		"depth", cfg.ContainerdPoolDepth,
		"max_images", cfg.ContainerdPoolMaxImages,
		"refill_interval", cfg.ContainerdPoolRefillInterval)
	return pool
}

func drainContainerdWarmPool(pool *containerdpool.Pool, logger *slog.Logger) {
	if pool == nil {
		return
	}
	if drained := pool.Close(); drained > 0 {
		if logger != nil {
			logger.Info("containerd warm pool drained on shutdown", "slots", drained)
		}
	}
}

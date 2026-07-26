package daemon

import (
	"context"
	"log/slog"
	"strings"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func wireDockerWarmPool(ctx context.Context, cfg config.Config, logger *slog.Logger, dockerClient *docker.Client, admitter *capacity.Admitter) *dockerpool.Pool {
	if !cfg.DockerPoolEffective() {
		if cfg.DockerPoolEnabled && !cfg.DockerReadySocketEnabled {
			logger.Warn("docker warm pool disabled: SB_DOCKER_READY_SOCKET_ENABLED=false")
		}
		return nil
	}
	pool := dockerpool.New(logger)
	pool.SetDefaultDepth(cfg.DockerPoolDepth)
	pool.SetMaxImages(cfg.DockerPoolMaxImages)
	pool.SetIdleTTL(cfg.DockerPoolIdleTTL)

	parkShape := dockerpool.ParkShape{
		CPU:      models.DefaultCPU,
		MemoryMB: models.DefaultMemoryMB,
		DiskGB:   models.DefaultDiskGB,
		Runtime:  models.RuntimeDocker,
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
	dockerClient.SetWarmPool(pool)

	images := cfg.DockerPoolImages
	if len(images) == 0 {
		images = []string{"alpine:3.20"}
	}
	for _, image := range images {
		image = strings.TrimSpace(image)
		if image == "" {
			continue
		}
		pool.PinTarget(dockerpool.Key{
			Image:   image,
			Runtime: cfg.Runtime,
		})
	}

	// Purge leftovers from a previous daemon run BEFORE the refill loop
	// starts parking: the purge sweeps by label, so running it afterwards
	// can destroy freshly parked slots the pool still tracks as live,
	// stranding their park reservations.
	if purged, err := dockerClient.PurgeParkedContainers(ctx); err != nil {
		logger.Warn("docker warm pool boot purge failed", "error", err)
	} else if purged > 0 {
		logger.Info("docker warm pool boot purge", "containers", purged)
	}

	spawner := &docker.PoolSpawner{Client: dockerClient}
	// Wire the spawner before anything can Acquire: slot discards inside the
	// pool need it to destroy containers, and RunRefill's own SetSpawner
	// happens on the goroutine's schedule, not ours.
	pool.SetSpawner(spawner)
	refillCfg := dockerpool.RefillConfig{
		RefillInterval: cfg.DockerPoolRefillInterval,
		SpawnTimeout:   cfg.DockerRuntimeWaitTimeout,
		IdleTTL:        cfg.DockerPoolIdleTTL,
		ParkShape:      parkShape,
	}
	go dockerpool.RunRefill(ctx, pool, refillCfg, spawner, gate, logger)

	// Keep the image-ID TTL cache permanently warm for pool-eligible images
	// so sparse creates never pay the ~45ms engine resolve. Interval must
	// stay below imageIDCacheTTL (asserted inside StartImageIDCacheWarmer).
	dockerClient.StartImageIDCacheWarmer(ctx, pool, cfg.DockerPoolRefillInterval, logger)

	logger.Info("docker warm pool enabled",
		"depth", cfg.DockerPoolDepth,
		"max_images", cfg.DockerPoolMaxImages,
		"refill_interval", cfg.DockerPoolRefillInterval)
	return pool
}

func drainDockerWarmPool(pool *dockerpool.Pool, logger *slog.Logger) {
	if pool == nil {
		return
	}
	if drained := pool.Close(); drained > 0 {
		if logger != nil {
			logger.Info("docker warm pool drained on shutdown", "slots", drained)
		}
	}
}

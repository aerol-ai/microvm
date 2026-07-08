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

	spawner := &docker.PoolSpawner{Client: dockerClient}
	refillCfg := dockerpool.RefillConfig{
		RefillInterval: cfg.DockerPoolRefillInterval,
		SpawnTimeout:   cfg.DockerRuntimeWaitTimeout,
		IdleTTL:        cfg.DockerPoolIdleTTL,
		ParkShape:      parkShape,
	}
	go dockerpool.RunRefill(ctx, pool, refillCfg, spawner, gate, logger)

	if purged, err := dockerClient.PurgeParkedContainers(ctx); err != nil {
		logger.Warn("docker warm pool boot purge failed", "error", err)
	} else if purged > 0 {
		logger.Info("docker warm pool boot purge", "containers", purged)
	}

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
		logger.Info("docker warm pool drained on shutdown", "slots", drained)
	}
}

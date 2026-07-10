package daemon

import (
	"context"
	"log/slog"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker"
)

// wireDockerNetnsPool starts the image-agnostic pause-netns warm pool
// (SB_DOCKER_NETNS_POOL_ENABLED). Unlike the per-image warm pool it has no
// capacity gate: a pause container holds a netns and ~1MB of memory, so
// slots are not admission-relevant.
func wireDockerNetnsPool(ctx context.Context, cfg config.Config, logger *slog.Logger, dockerClient *docker.Client) *docker.NetnsPool {
	if !cfg.DockerNetnsPoolEnabled {
		return nil
	}
	pool := dockerClient.StartNetnsPool(ctx, logger,
		cfg.DockerNetnsPoolDepth,
		cfg.DockerNetnsPoolPauseImage,
		cfg.DockerNetnsPoolRefillInterval)
	logger.Info("docker netns pool enabled",
		"depth", cfg.DockerNetnsPoolDepth,
		"pause_image", cfg.DockerNetnsPoolPauseImage,
		"refill_interval", cfg.DockerNetnsPoolRefillInterval)
	return pool
}

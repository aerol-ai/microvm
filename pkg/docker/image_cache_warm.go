package docker

import (
	"context"
	"log/slog"
	"time"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
)

// StartImageIDCacheWarmer runs a background ticker that re-resolves every
// pool-eligible image into the TTL cache. RefillInterval must be strictly
// less than imageIDCacheTTL — otherwise sparse creates (one per 15s+) go
// cold between ticks. The inspect is timing-free and generation-fenced so
// it never records a boot-path docker_image stage and never re-installs a
// stale ID after an in-band Flush.
func (c *Client) StartImageIDCacheWarmer(ctx context.Context, pool *dockerpool.Pool, interval time.Duration, logger *slog.Logger) {
	if c == nil || pool == nil || interval <= 0 {
		return
	}
	if interval >= imageIDCacheTTL {
		if logger != nil {
			logger.Error("docker image-ID cache warmer disabled: refill interval must be < cache TTL",
				"refill_interval", interval,
				"cache_ttl", imageIDCacheTTL)
		}
		return
	}
	go c.runImageIDCacheWarmer(ctx, pool, interval, logger)
}

func (c *Client) runImageIDCacheWarmer(ctx context.Context, pool *dockerpool.Pool, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	c.warmImageIDCacheOnce(ctx, pool, logger)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.warmImageIDCacheOnce(ctx, pool, logger)
		}
	}
}

func (c *Client) warmImageIDCacheOnce(ctx context.Context, pool *dockerpool.Pool, logger *slog.Logger) {
	if c == nil || pool == nil {
		return
	}
	// Piggyback map hygiene on the warm tick — the cache has no timer of its
	// own, and refs that left the pool set would otherwise linger expired.
	c.imageIDs.Prune()
	for _, key := range pool.ListTargets() {
		image := key.Image
		if image == "" {
			continue
		}
		_, ok, err := c.resolveImageIDForWarm(ctx, image)
		if err != nil {
			if logger != nil {
				logger.Debug("docker image-ID cache warm failed", "image", image, "error", err)
			}
			continue
		}
		if !ok && logger != nil {
			logger.Debug("docker image-ID cache warm dropped stale put", "image", image)
		}
	}
}

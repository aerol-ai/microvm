package wasm

import (
	"context"
	"log/slog"
	"time"
)

// RefillConfig holds timing knobs for the background refill loop.
type RefillConfig struct {
	RefillInterval time.Duration
	SpawnTimeout   time.Duration
}

// Run starts the refill loop until ctx is cancelled. No-op when pool or spawner is nil.
func (p *Pool) Run(ctx context.Context, cfg RefillConfig, spawner Spawner) {
	if p == nil || spawner == nil {
		return
	}
	if cfg.RefillInterval <= 0 {
		cfg.RefillInterval = 5 * time.Second
	}
	if cfg.SpawnTimeout <= 0 {
		cfg.SpawnTimeout = 30 * time.Second
	}
	p.SetSpawner(spawner)

	ticker := time.NewTicker(cfg.RefillInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.refillTick(ctx, cfg.SpawnTimeout)
		}
	}
}

func (p *Pool) refillTick(parent context.Context, spawnTimeout time.Duration) {
	targets := p.ListTargets()
	for _, t := range targets {
		budget := p.SpawnBudget(t.Digest)
		for i := 0; i < budget; i++ {
			p.MarkSpawning(t.Digest)
			ctx, cancel := context.WithTimeout(parent, spawnTimeout)
			slot, err := p.WarmOne(ctx, t.Digest, t.Path)
			cancel()
			if err != nil {
				p.UnmarkSpawning(t.Digest)
				if p.metrics != nil {
					p.metrics.RecordSpawnFail()
				}
				p.logger.Warn("wasm pool refill: warm failed",
					"digest", t.Digest, "error", err)
				break
			}
			p.RecordLoaded(slot)
			if p.metrics != nil {
				p.metrics.RecordRefill()
			}
			p.logger.Debug("wasm pool refill: slot ready",
				"digest", t.Digest, "slot_id", slot.ID)
		}
	}
}

// RunRefill is a convenience wrapper matching daemon wiring style.
func RunRefill(ctx context.Context, pool *Pool, cfg RefillConfig, spawner Spawner, logger *slog.Logger) {
	if logger != nil {
		logger.Info("wasm warm pool refill started",
			"interval", cfg.RefillInterval,
			"spawn_timeout", cfg.SpawnTimeout)
	}
	pool.Run(ctx, cfg, spawner)
}

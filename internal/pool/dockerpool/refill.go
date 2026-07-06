package dockerpool

import (
	"context"
	"log/slog"
	"time"
)

// RefillConfig holds timing knobs for the background refill loop.
type RefillConfig struct {
	RefillInterval time.Duration
	SpawnTimeout   time.Duration
	IdleTTL        time.Duration
	ParkShape      ParkShape
}

// Run starts the refill loop until ctx is cancelled.
func (p *Pool) Run(ctx context.Context, cfg RefillConfig, spawner Spawner, gate RefillGate) {
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
	idleTicker := time.NewTicker(cfg.RefillInterval)
	defer ticker.Stop()
	defer idleTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.refillTick(ctx, cfg, spawner, gate)
		case <-p.refillKick:
			p.refillTick(ctx, cfg, spawner, gate)
		case <-idleTicker.C:
			if cfg.IdleTTL > 0 {
				p.ReapIdle(time.Now().UTC())
			}
		}
	}
}

func (p *Pool) refillTick(parent context.Context, cfg RefillConfig, spawner Spawner, gate RefillGate) {
	targets := p.ListTargets()
	for _, key := range targets {
		ks := key.KeyString()
		budget := p.SpawnBudget(ks)
		for i := 0; i < budget; i++ {
			if gate != nil && !gate.CanPark(cfg.ParkShape) {
				return
			}
			slotID, err := NewSlotID()
			if err != nil {
				p.logger.Warn("docker pool refill: slot id", "error", err)
				break
			}
			if gate != nil {
				if err := gate.ParkReservation(slotID, cfg.ParkShape); err != nil {
					p.logger.Debug("docker pool refill: capacity refused park", "error", err)
					break
				}
			}
			p.MarkSpawning(ks)
			ctx, cancel := context.WithTimeout(parent, cfg.SpawnTimeout)
			slot, err := spawner.Park(ctx, slotID, key)
			cancel()
			if err != nil {
				p.UnmarkSpawning(ks)
				if p.metrics != nil {
					p.metrics.RecordSpawnFail()
				}
				if gate != nil {
					gate.ReleasePark(slotID)
				}
				p.logger.Warn("docker pool refill: park failed", "key", ks, "error", err)
				break
			}
			p.RecordLoaded(slot)
			if p.metrics != nil {
				p.metrics.recordRefill()
			}
		}
	}
}

// RunRefill is a convenience wrapper matching daemon wiring style.
func RunRefill(ctx context.Context, pool *Pool, cfg RefillConfig, spawner Spawner, gate RefillGate, logger *slog.Logger) {
	if logger != nil {
		logger.Info("docker warm pool refill started",
			"interval", cfg.RefillInterval,
			"spawn_timeout", cfg.SpawnTimeout)
	}
	pool.Run(ctx, cfg, spawner, gate)
}

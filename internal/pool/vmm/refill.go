package vmm

// refill.go is the Phase 4 PR-B background goroutine that drives the
// state machine PR 4-A laid down. One ticker per Pool walks every
// template the Pool knows about, computes the spawn budget
// (desired_depth - non_released_slots), and asks the Spawner to
// produce that many paused-and-loaded firecracker VMMs.
//
// A second, slower ticker reaps 'released' rows whose released_at is
// older than the GC TTL. Reap is split from refill so the refill tick
// stays cheap on a busy host — the GC sweep does I/O for every reaped
// row (firecracker process Shutdown, runDir delete), and queueing that
// behind the spawn budget would slow the boot path the pool exists to
// speed up.
//
// Concurrency model:
//
//   - One goroutine per Pool, started by Run. It owns both tickers.
//   - Per-template work runs serially inside the tick — the Spawner
//     itself may be slow (firecracker spawn + LoadSnapshot can take
//     hundreds of ms), so a tick that wanted to spawn 5 slots across
//     2 templates takes ~5 × per-spawn-cost wall-clock. The ticker
//     skips the next tick if the previous one is still running rather
//     than queueing up overlapping passes; a stuck Spawner doesn't
//     wedge the whole loop, it just stops refilling for the affected
//     template's interval.
//   - Slot-id generation lives in this file rather than in Pool. The
//     pool is a typed substrate; the loop is the only thing that
//     mints new ids and so the id-generation policy stays right next
//     to the only caller.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"
)

// TemplateLister is the seam the refill loop uses to discover which
// templates are eligible for warming and where their snapshot
// artifacts live on disk. Declared as an interface so:
//
//   - The vmm package keeps its "imports only store + stdlib"
//     discipline. main.go injects an adapter that calls into the
//     template service or store.
//
//   - Tests inject a fake returning a fixed list, so the refill
//     loop is exercisable on darwin without a real template
//     pipeline.
//
// Implementations MUST return only templates whose snapshot is ready
// and whose artifact paths exist on disk. A template in 'pending' or
// 'failed' should be filtered out before the loop sees it — the
// Spawner would just fail on it, and we'd rather not waste a tick.
type TemplateLister interface {
	// ListWarmableTemplates returns the active templates the refill
	// loop should consider on this tick. Order is unimportant; the
	// loop walks the slice and uses Pool.DepthFor(templateID) to
	// decide which templates to warm.
	ListWarmableTemplates(ctx context.Context) ([]TemplateWarmInput, error)
}

// TemplateWarmInput is the per-template artifact the refill loop
// hands to the Spawner. Lifted from store.Template's snapshot fields
// so this package stays at arm's length from the template store row
// shape.
type TemplateWarmInput struct {
	TemplateID         string
	SnapshotMemoryPath string
	SnapshotStatePath  string
	SnapshotChecksum   string
	VsockCID           uint32
	HasOverlay         bool
}

// RefillConfig is the timing knobs the refill loop reads on
// construction. Both fields must be positive; Run panics with a
// clear message rather than silently picking a default — the daemon
// already does this validation at boot in main.go, and reaching this
// code with zero values would be a wiring bug worth surfacing.
//
// SpawnTimeout bounds an individual Spawner.Spawn call. Cold-spawn +
// LoadSnapshot on a healthy host should land well under 1s; the
// default 30s in main.go is the operator-side ceiling that catches a
// hung firecracker without wedging the loop.
type RefillConfig struct {
	RefillInterval time.Duration
	GCInterval     time.Duration
	GCTTL          time.Duration
	SpawnTimeout   time.Duration
}

// Run starts the refill + GC loops. It blocks until ctx is cancelled,
// then returns. The Spawner and TemplateLister seams are caller-
// provided so production wires them to the firecracker adapter and
// the template store; tests inject fakes.
//
// Returns immediately (without launching anything) when Spawner or
// Lister is nil — that's the "pool disabled" config in main.go: when
// SB_FIRECRACKER_VMM_POOL_ENABLED=false, main.go passes nil and Run
// is a no-op rather than panicking.
func (p *Pool) Run(ctx context.Context, cfg RefillConfig, lister TemplateLister, spawner Spawner) {
	if spawner == nil || lister == nil {
		p.logger.Info("vmm pool: refill loop disabled (spawner or lister not wired)")
		return
	}
	if cfg.RefillInterval <= 0 || cfg.GCInterval <= 0 || cfg.GCTTL <= 0 {
		panic(fmt.Sprintf("vmm pool: RefillConfig requires positive durations, got %+v", cfg))
	}
	if cfg.SpawnTimeout <= 0 {
		cfg.SpawnTimeout = 30 * time.Second
	}

	refillTicker := time.NewTicker(cfg.RefillInterval)
	gcTicker := time.NewTicker(cfg.GCInterval)
	defer refillTicker.Stop()
	defer gcTicker.Stop()

	// refillBusy is the single-flight latch that drops the next tick
	// when the previous one is still running. atomic.Bool because the
	// ticker fires on this same goroutine, but the tick handler itself
	// could observably race with a future on-demand RefillOnce call
	// (PR 4-C may add one for tests).
	var refillBusy atomic.Bool

	// Fire an immediate refill so the pool warms up promptly after
	// boot rather than waiting RefillInterval. The "first refill
	// happens at t=0, not t=RefillInterval" property matters for
	// integration tests that want to observe a warmed pool without
	// sleeping for a full interval.
	if released, err := p.releaseOrphanedRowsAtStart(ctx, time.Now().UTC()); err != nil {
		p.logger.Warn("vmm pool: startup orphan repair failed", "error", err)
	} else if released > 0 {
		p.logger.Info("vmm pool: released orphaned startup rows", "count", released)
	}
	p.runRefillOnce(ctx, lister, spawner, cfg.SpawnTimeout, &refillBusy)

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("vmm pool: refill loop exiting")
			return
		case <-refillTicker.C:
			p.runRefillOnce(ctx, lister, spawner, cfg.SpawnTimeout, &refillBusy)
		case <-gcTicker.C:
			p.runGCOnce(ctx, cfg.GCTTL)
		}
	}
}

// runRefillOnce is one pass of the refill ticker. Exported via Pool
// for tests that want a deterministic single tick instead of driving
// the real ticker; production callers go through Run.
//
// The busy latch is honored so two consecutive ticks (or a ticker
// tick + a test-driven manual call) don't pile up overlapping passes
// that would double-spawn.
func (p *Pool) runRefillOnce(ctx context.Context, lister TemplateLister, spawner Spawner, spawnTimeout time.Duration, busy *atomic.Bool) {
	if !busy.CompareAndSwap(false, true) {
		// Previous tick still running — skip rather than queue. The
		// next ticker.C delivery will pick up the work; if the
		// previous tick was wedged, it stays wedged but doesn't
		// fan out.
		recordRefillTickDropped()
		return
	}
	defer busy.Store(false)

	tickStart := time.Now()
	defer func() { recordRefillTick(time.Since(tickStart)) }()

	templates, err := lister.ListWarmableTemplates(ctx)
	if err != nil {
		p.logger.Warn("vmm pool: list templates failed", "error", err)
		return
	}
	for _, tpl := range templates {
		if ctx.Err() != nil {
			return
		}
		p.refillTemplate(ctx, tpl, spawner, spawnTimeout)
	}
	// Publish current per-template depth gauges at the end of the
	// tick so dashboards see the post-refill state, not the pre-
	// refill snapshot. The query is a single GROUP BY per template
	// behind the template_status index, so the cost is negligible
	// compared to the spawns we just issued.
	for _, tpl := range templates {
		if ctx.Err() != nil {
			return
		}
		stats, err := p.Stats(ctx, tpl.TemplateID)
		if err != nil {
			p.logger.Warn("vmm pool: publish stats query failed",
				"template_id", tpl.TemplateID, "error", err)
			continue
		}
		publishSlotStats(tpl.TemplateID, stats)
	}
}

// refillTemplate computes the spawn budget for a single template and
// issues that many serial Spawn calls. Per-spawn errors don't abort
// the whole pass — a failing spawner for one template shouldn't
// starve other templates' refills.
//
// "Serial" rather than "parallel" is deliberate: the pool is
// per-host, the host's CPU budget for spawning firecracker processes
// is finite, and a fanout could storm a host's I/O during a deploy
// when every template's pool is suddenly empty. PR 4-C may revisit
// with a bounded-parallel form if we measure spawn latency dominating
// the warm-up tail.
func (p *Pool) refillTemplate(ctx context.Context, tpl TemplateWarmInput, spawner Spawner, spawnTimeout time.Duration) {
	desired := p.DepthFor(tpl.TemplateID)
	if desired <= 0 {
		return
	}
	if !p.tapCapacityAllowsRefill(ctx, tpl.TemplateID, desired) {
		return
	}
	have, err := p.ListNonReleased(ctx, tpl.TemplateID)
	if err != nil {
		p.logger.Warn("vmm pool: list non-released failed",
			"template_id", tpl.TemplateID, "error", err)
		return
	}
	budget := desired - len(have)
	if budget <= 0 {
		return
	}
	recordRefillShortfall(tpl.TemplateID, budget)
	p.logger.Info("vmm pool: refill tick",
		"template_id", tpl.TemplateID, "desired", desired,
		"have", len(have), "budget", budget)

	for range budget {
		if ctx.Err() != nil {
			return
		}
		p.spawnOne(ctx, tpl, spawner, spawnTimeout)
	}
}

func (p *Pool) tapCapacityAllowsRefill(ctx context.Context, templateID string, desired int) bool {
	stats, err := p.st.GetFirecrackerTapPoolStats(ctx)
	if err != nil {
		p.logger.Warn("vmm pool: tap capacity check failed",
			"template_id", templateID, "error", err)
		return false
	}
	if stats.Total == 0 {
		// The policy package's unit tests exercise the VMM pool without
		// seeding a TAP pool. Production daemon wiring always seeds TAPs
		// before enabling Firecracker, so zero total means "capacity guard
		// not applicable" rather than "deny every policy-only test refill".
		return true
	}
	minFree := desired * 2
	if stats.Free < minFree {
		p.logger.Info("vmm pool: refill skipped by tap capacity guard",
			"template_id", templateID,
			"desired", desired,
			"tap_total", stats.Total,
			"tap_allocated", stats.Allocated,
			"tap_free", stats.Free,
			"min_free", minFree)
		return false
	}
	return true
}

// spawnOne mints a fresh slot id, reserves the row in 'spawning',
// invokes Spawner.Spawn under a per-spawn deadline, then either
// promotes the row to 'loaded' (on success) or 'released' with
// last_error set (on failure). On failure, the handle (if any) gets
// Shutdown'd best-effort — the contract says the Spawner leaves no
// leaks, but defense in depth is cheap.
//
// The state-machine guarantees come from the store layer: a partial
// Spawn that doesn't reach RecordLoaded leaves the row visible as
// 'spawning' to the GC sweep, which will reap it after the TTL.
func (p *Pool) spawnOne(parentCtx context.Context, tpl TemplateWarmInput, spawner Spawner, spawnTimeout time.Duration) {
	slotID, err := generateSlotID()
	if err != nil {
		p.logger.Warn("vmm pool: generate slot id failed", "error", err)
		return
	}
	now := time.Now().UTC()
	if err := p.RecordSpawning(parentCtx, slotID, tpl.TemplateID, now); err != nil {
		p.logger.Warn("vmm pool: record spawning failed",
			"template_id", tpl.TemplateID, "slot_id", slotID, "error", err)
		return
	}

	spawnCtx, cancel := context.WithTimeout(parentCtx, spawnTimeout)
	defer cancel()
	spawnStart := time.Now()
	handle, err := spawner.Spawn(spawnCtx, slotID, SnapshotInputs{
		TemplateID:         tpl.TemplateID,
		SnapshotMemoryPath: tpl.SnapshotMemoryPath,
		SnapshotStatePath:  tpl.SnapshotStatePath,
		SnapshotChecksum:   tpl.SnapshotChecksum,
		VsockCID:           tpl.VsockCID,
		HasOverlay:         tpl.HasOverlay,
	})
	recordSpawnLatency(time.Since(spawnStart))
	if err != nil {
		recordSpawnOutcome(spawnOutcomeSpawnError)
		// Spawn failed: mark released with the error preserved.
		if mErr := p.RecordFailed(parentCtx, slotID, err.Error(), time.Now().UTC()); mErr != nil {
			p.logger.Warn("vmm pool: mark failed after spawn error failed",
				"slot_id", slotID, "spawn_error", err, "mark_error", mErr)
		} else {
			p.logger.Warn("vmm pool: spawn failed",
				"template_id", tpl.TemplateID, "slot_id", slotID, "error", err)
		}
		// Defense in depth — the contract says no leaked handle on
		// error, but if one came back anyway, drop it.
		if handle != nil {
			_ = handle.Shutdown(context.Background(), 3*time.Second)
		}
		return
	}

	// Promote the row to 'loaded' with the artifact references the
	// Acquire path needs. Use the parent context, not spawnCtx — the
	// spawn already succeeded; we don't want a slow SQLite write to
	// race the spawn timeout we just released.
	if err := p.RecordLoaded(parentCtx, slotID, handle.APISocket(), handle.RunDir(), tpl.VsockCID, time.Now().UTC()); err != nil {
		recordSpawnOutcome(spawnOutcomeRecordError)
		// Loaded-record failed but the VMM process is up. Tear it
		// down — leaving a process whose row says 'spawning' would
		// confuse the GC sweep (and worse, the next Acquire is
		// blocked from picking it because the row never moves to
		// 'loaded').
		p.logger.Warn("vmm pool: record loaded failed",
			"slot_id", slotID, "error", err)
		_ = handle.Shutdown(context.Background(), 3*time.Second)
		_ = p.RecordFailed(parentCtx, slotID, "record loaded failed: "+err.Error(), time.Now().UTC())
		return
	}
	recordSpawnOutcome(spawnOutcomeSuccess)

	// Park the handle alongside the row so AcquireWithHandle can
	// retrieve it. Order matters: register AFTER RecordLoaded so the
	// Acquire path's row-level state ('loaded') and the in-memory
	// map both flip in the same instant (modulo the brief
	// inter-statement window). If we registered first, an Acquire
	// racing between RecordLoaded and registerHandle would see the
	// row as still 'spawning' and skip the slot — harmless but
	// wasteful.
	p.registerHandle(slotID, handle)

	p.logger.Info("vmm pool: slot loaded",
		"template_id", tpl.TemplateID, "slot_id", slotID,
		"api_socket", handle.APISocket(), "vsock_cid", tpl.VsockCID)
}

// runGCOnce is one pass of the GC ticker. Exported via Pool for tests
// to drive deterministically. The TTL gating lives inside
// ReapReleased (the store-level WHERE released_at <= ?); this method
// is the time-source seam.
func (p *Pool) runGCOnce(ctx context.Context, ttl time.Duration) {
	cutoff := time.Now().UTC().Add(-ttl)
	deleted, err := p.ReapReleased(ctx, cutoff)
	if err != nil {
		p.logger.Warn("vmm pool: gc reap failed", "error", err, "cutoff", cutoff)
		return
	}
	if deleted > 0 {
		p.logger.Info("vmm pool: gc reaped released slots", "deleted", deleted, "cutoff", cutoff)
	}
}

// generateSlotID returns "vmms-<16 hex>". Same shape as the template
// IDs in internal/service/template.go (different prefix so a glance
// at the id distinguishes pool slots from templates and sandboxes).
//
// Returns an error from crypto/rand only if the system PRNG is
// catastrophically unavailable; we surface it rather than panic so
// the refill loop can log and continue rather than tear the daemon
// down for what's almost always a transient kernel error.
func generateSlotID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate slot id: %w", err)
	}
	return "vmms-" + hex.EncodeToString(buf), nil
}

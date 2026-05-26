package vmm

// metrics.go is the Phase 4 PR-C expvar exporter for the warm-VMM pool.
// All metrics are package-level expvars so the existing observability
// scrape (internal/observability/expvar.go iterates every var with the
// "aerolvm_" prefix) picks them up without further wiring.
//
// Why expvar + scaleobs and not OTEL: the rest of the daemon's hot-path
// metrics (create latency, ingress, capacity, raft) already use this
// stack — the operator-side scrape, Grafana dashboards, and alert rules
// in setup/ all consume the same /debug/vars surface. The OTEL path
// (internal/observability/otel.go) layers on top of the same expvar
// vars, so a single set of declarations gives both surfaces.
//
// Label cardinality: every label that touches a metric on the hot path
// (acquire/spawn outcome) comes from a small fixed enum local to this
// file. The per-template gauges are the only template_id-keyed metric;
// per-host template count is bounded by operator config so the map
// stays small. Outcome strings are interned constants rather than
// derived from errors, so a sudden flurry of distinct error messages
// can't blow up the map cardinality.
//
// The publish hook (publishSlotStats) is called at the tail of every
// refill tick — depth gauges drift only as fast as the refill cadence,
// which is exactly the resolution dashboards and alerts care about
// (sub-tick changes are noise relative to the refill interval).

import (
	"expvar"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/scaleobs"
)

// Outcome label constants. Defined as typed strings so a typo at the
// call site is a compile error and so the set of legal values is
// trivial to grep.
type acquireOutcome string

const (
	acquireOutcomeHit    acquireOutcome = "hit"
	acquireOutcomeMiss   acquireOutcome = "miss"
	acquireOutcomeOrphan acquireOutcome = "orphan"
	acquireOutcomeError  acquireOutcome = "error"
)

type spawnOutcome string

const (
	spawnOutcomeSuccess     spawnOutcome = "success"
	spawnOutcomeSpawnError  spawnOutcome = "spawn_error"
	spawnOutcomeRecordError spawnOutcome = "record_error"
)

var (
	// Counter: per-outcome Acquire call count. "hit" includes both
	// fresh hits and idempotent re-Acquire by the same sandbox.
	// "miss" is the expected empty-pool path that triggers cold spawn;
	// "orphan" is the post-restart edge case where the row says
	// 'loaded' but no in-memory handle remains; "error" catches any
	// store-level failure.
	acquireTotal = expvar.NewMap("aerolvm_vmm_pool_acquire_total")

	// Histogram: AcquireWithHandle wall-clock. The hit path is the
	// boot-time win the pool exists for — operators tracking p50/p99
	// latency look here. Misses are bucketed too so the cold-fallback
	// cost is visible separately if needed via the acquire_total label.
	acquireLatency = scaleobs.NewDurationBuckets(
		"aerolvm_vmm_pool_acquire_latency_seconds_bucket",
		// Override defaults: pool hits should land in the sub-ms to
		// few-ms range; defaults start at 5ms which would collapse
		// every hit into the lowest bucket and hide the distribution.
		100*time.Microsecond,
		500*time.Microsecond,
		1*time.Millisecond,
		2*time.Millisecond,
		5*time.Millisecond,
		10*time.Millisecond,
		25*time.Millisecond,
		100*time.Millisecond,
		1*time.Second,
	)

	// Counter: per-outcome Spawn call count. spawn_error is the
	// Spawner returning an error; record_error is the rarer case where
	// the spawn succeeded but the post-spawn store write failed and we
	// had to tear the handle down.
	spawnTotal = expvar.NewMap("aerolvm_vmm_pool_spawn_total")

	// Histogram: per-spawn wall-clock. Includes the spawner call and
	// the store writes; aimed at sizing the refill interval (if p99
	// spawn latency creeps past the refill interval, the loop will be
	// continuously behind).
	spawnLatency = scaleobs.NewDurationBuckets(
		"aerolvm_vmm_pool_spawn_latency_seconds_bucket",
		10*time.Millisecond,
		50*time.Millisecond,
		100*time.Millisecond,
		250*time.Millisecond,
		500*time.Millisecond,
		1*time.Second,
		2*time.Second,
		5*time.Second,
		30*time.Second,
	)

	// Histogram: full-tick wall-clock for one runRefillOnce pass.
	// A tick that consistently runs longer than the refill interval is
	// the "back-pressured" signal — the latch will start dropping
	// ticks and the pool will fail to keep up with churn.
	refillTickLatency = scaleobs.NewDurationBuckets(
		"aerolvm_vmm_pool_refill_tick_latency_seconds_bucket",
		1*time.Millisecond,
		10*time.Millisecond,
		100*time.Millisecond,
		500*time.Millisecond,
		1*time.Second,
		5*time.Second,
		30*time.Second,
	)

	// Counter: rows the GC sweep actually deleted. Distinct from
	// rows-eligible-but-deletion-failed (logged but not metric'd here
	// because the failure modes aren't typed cleanly).
	gcReapedTotal = expvar.NewInt("aerolvm_vmm_pool_gc_reaped_total")

	// Counter: refill ticks dropped by the busy latch. A non-zero
	// rate is the operator signal to either bump RefillInterval or
	// investigate why spawn latency exceeds the interval.
	refillTicksDropped = expvar.NewInt("aerolvm_vmm_pool_refill_ticks_dropped_total")

	// Counter: per-status, per-template depth that the publish hook
	// snapshots after each refill tick. Two-level expvar.Map so the
	// observability scraper emits one sample per (template_id, status)
	// pair via the existing key/key2 label convention in
	// internal/observability/expvar.go.
	slotGauges = expvar.NewMap("aerolvm_vmm_pool_slots")

	// Gauge: live SpawnedHandle count in the in-memory map. Useful as
	// a sanity-check against (sum over slotGauges) — they should
	// agree on the loaded-row count modulo the brief window between
	// RecordLoaded and registerHandle.
	handlesInMemory = expvar.NewInt("aerolvm_vmm_pool_handles_in_memory")

	// Counter: per-template depth shortfall observed at refill-tick
	// time (desired - have, clamped at 0). A persistently non-zero
	// shortfall under steady load means the configured depth is too
	// small for the create rate.
	refillShortfall = expvar.NewMap("aerolvm_vmm_pool_refill_shortfall_total")
)

// recordAcquireOutcome bumps the outcome counter and the latency
// bucket. Always called from AcquireWithHandle with the time.Since
// from the start of the call — the bucket distinguishes hit vs. miss
// latency only by reading the counter alongside.
func recordAcquireOutcome(outcome acquireOutcome, elapsed time.Duration) {
	acquireTotal.Add(string(outcome), 1)
	acquireLatency.Observe(elapsed)
}

// recordSpawnOutcome bumps the spawn outcome counter. The latency
// bucket is recorded separately by recordSpawnLatency so the timer
// can span only the Spawner.Spawn call when callers want spawner-only
// timing, but in PR 4-C the single spawnOne wrapper records both.
func recordSpawnOutcome(outcome spawnOutcome) {
	spawnTotal.Add(string(outcome), 1)
}

func recordSpawnLatency(elapsed time.Duration) {
	spawnLatency.Observe(elapsed)
}

func recordRefillTick(elapsed time.Duration) {
	refillTickLatency.Observe(elapsed)
}

func recordRefillTickDropped() {
	refillTicksDropped.Add(1)
}

func recordReaped(n int) {
	if n > 0 {
		gcReapedTotal.Add(int64(n))
	}
}

func recordRefillShortfall(templateID string, shortfall int) {
	if shortfall <= 0 || templateID == "" {
		return
	}
	scaleobs.Add(refillShortfall, templateID, int64(shortfall))
}

// publishSlotStats writes the per-status counts for templateID into
// slotGauges. Idempotent: a second call with different counts
// overwrites, so dashboards see the latest tick's view rather than a
// running max. The Released bucket is published too — high Released
// counts that aren't decreasing tick-over-tick mean the GC isn't
// keeping up.
//
// Called at the tail of each refill tick (cheap — one GROUP BY scan
// per template) so the gauges drift at refill-cadence resolution.
func publishSlotStats(templateID string, stats Stats) {
	if templateID == "" {
		return
	}
	tplKey := scaleobs.Key(templateID)
	sub, _ := slotGauges.Get(tplKey).(*expvar.Map)
	if sub == nil {
		sub = new(expvar.Map).Init()
		slotGauges.Set(tplKey, sub)
	}
	setGauge(sub, "spawning", int64(stats.Spawning))
	setGauge(sub, "loaded", int64(stats.Loaded))
	setGauge(sub, "allocated", int64(stats.Allocated))
	setGauge(sub, "released", int64(stats.Released))
	setGauge(sub, "total", int64(stats.Total))
}

func setGauge(m *expvar.Map, key string, value int64) {
	v := new(expvar.Int)
	v.Set(value)
	m.Set(key, v)
}

// metricsClassifyAcquireError maps a non-sentinel Acquire error into a
// stable label. Kept narrow — Acquire's error surface is just the
// store call, and the labels here are dashboard reasons rather than
// programmatic discriminators.
func metricsClassifyAcquireError(err error) acquireOutcome {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "no loaded slot") {
		// Defensive — Acquire returns ErrNoLoadedSlot directly so this
		// path is dead code today, but a future wrapper that loses the
		// sentinel would otherwise log as "error" and obscure the
		// miss rate.
		return acquireOutcomeMiss
	}
	return acquireOutcomeError
}

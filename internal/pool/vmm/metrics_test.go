package vmm

import (
	"context"
	"errors"
	"expvar"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// expvar metrics are package-level globals. Tests that assert on their
// values share state across the test binary, so each assertion compares
// a before/after delta rather than expecting an absolute value. The
// same pattern is used in internal/cluster/metrics_test.go and
// pkg/capacity/admission_test.go.

func intValue(v expvar.Var) int64 {
	if v == nil {
		return 0
	}
	n, _ := strconv.ParseInt(v.String(), 10, 64)
	return n
}

func mapInt(m *expvar.Map, key string) int64 {
	return intValue(m.Get(key))
}

// nestedMapInt reads a key under a two-level expvar.Map (the shape
// publishSlotStats writes for slotGauges). Returns 0 when either
// level is missing — keeps the call sites short rather than forcing
// each test to nil-check the inner map.
func nestedMapInt(m *expvar.Map, outer, inner string) int64 {
	sub, ok := m.Get(outer).(*expvar.Map)
	if !ok || sub == nil {
		return 0
	}
	return intValue(sub.Get(inner))
}

func TestMetrics_AcquireOutcomes(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()

	hitBefore := mapInt(acquireTotal, "hit")
	missBefore := mapInt(acquireTotal, "miss")
	orphanBefore := mapInt(acquireTotal, "orphan")

	// Miss — empty pool, AcquireWithHandle should record outcome="miss".
	if _, _, err := p.AcquireWithHandle(ctx, "tpl-a", "sb-miss", now); err != ErrNoLoadedSlot {
		t.Fatalf("expected ErrNoLoadedSlot, got %v", err)
	}
	if got := mapInt(acquireTotal, "miss") - missBefore; got != 1 {
		t.Fatalf("miss counter delta = %d, want 1", got)
	}

	// Set up a loaded slot WITH a registered handle for the hit path.
	if err := p.RecordSpawning(ctx, "vmms-hit", "tpl-a", now); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordLoaded(ctx, "vmms-hit", "/api", "/dir", 3, now); err != nil {
		t.Fatal(err)
	}
	p.registerHandle("vmms-hit", &stubHandle{api: "/api", run: "/dir"})

	if _, _, err := p.AcquireWithHandle(ctx, "tpl-a", "sb-hit", now); err != nil {
		t.Fatalf("hit acquire: %v", err)
	}
	if got := mapInt(acquireTotal, "hit") - hitBefore; got != 1 {
		t.Fatalf("hit counter delta = %d, want 1", got)
	}

	// Orphan — loaded row but no handle in the in-memory map. Simulates
	// the post-daemon-restart edge case.
	if err := p.RecordSpawning(ctx, "vmms-orphan", "tpl-a", now); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordLoaded(ctx, "vmms-orphan", "/api", "/dir", 4, now); err != nil {
		t.Fatal(err)
	}
	// Intentionally NOT calling registerHandle for vmms-orphan.
	if _, _, err := p.AcquireWithHandle(ctx, "tpl-a", "sb-orphan", now); err != ErrNoLoadedSlot {
		t.Fatalf("expected ErrNoLoadedSlot for orphan, got %v", err)
	}
	if got := mapInt(acquireTotal, "orphan") - orphanBefore; got != 1 {
		t.Fatalf("orphan counter delta = %d, want 1", got)
	}
}

func TestMetrics_AcquireLatencyObserved(t *testing.T) {
	// Don't assert specific bucket counts (other tests run before this
	// one may have populated buckets); just verify that AcquireWithHandle
	// bumps the overall Count by exactly the number of calls.
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()
	before := acquireLatency.Count()

	// One miss observation.
	_, _, _ = p.AcquireWithHandle(ctx, "tpl-none", "sb-x", now)
	if got := acquireLatency.Count() - before; got != 1 {
		t.Fatalf("acquireLatency.Count delta = %d, want 1", got)
	}
}

func TestMetrics_SpawnOutcomesAndLatency(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	p.SetDepth("tpl-a", 2)
	spawner := &fakeSpawner{}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-a", VsockCID: 3}}}

	successBefore := mapInt(spawnTotal, "success")
	latencyBefore := spawnLatency.Count()

	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)

	if got := mapInt(spawnTotal, "success") - successBefore; got != 2 {
		t.Fatalf("success counter delta = %d, want 2", got)
	}
	if got := spawnLatency.Count() - latencyBefore; got != 2 {
		t.Fatalf("spawnLatency.Count delta = %d, want 2", got)
	}
}

func TestMetrics_SpawnErrorOutcome(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	p.SetDepth("tpl-a", 2)
	spawner := &fakeSpawner{spawnErr: errFakeSpawn}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-a", VsockCID: 3}}}

	before := mapInt(spawnTotal, "spawn_error")
	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)
	if got := mapInt(spawnTotal, "spawn_error") - before; got != 2 {
		t.Fatalf("spawn_error counter delta = %d, want 2", got)
	}
}

func TestMetrics_RefillTickLatencyAndShortfall(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	p.SetDepth("tpl-a", 3)
	spawner := &fakeSpawner{}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-a", VsockCID: 3}}}

	tickBefore := refillTickLatency.Count()
	shortfallBefore := mapInt(refillShortfall, "tpl_a")

	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)

	if got := refillTickLatency.Count() - tickBefore; got != 1 {
		t.Fatalf("refillTickLatency.Count delta = %d, want 1", got)
	}
	if got := mapInt(refillShortfall, "tpl_a") - shortfallBefore; got != 3 {
		t.Fatalf("refillShortfall delta = %d, want 3 (desired=3, have=0)", got)
	}
}

func TestMetrics_RefillTicksDropped(t *testing.T) {
	// Drive runRefillOnce with the latch already held to confirm the
	// drop counter advances. No spawner needed — the latch check fires
	// before the spawner gets called.
	p, _ := newTestPool(t)
	var busy atomic.Bool
	busy.Store(true)
	before := intValue(refillTicksDropped)
	p.runRefillOnce(context.Background(), &fakeLister{}, &fakeSpawner{}, time.Second, &busy)
	if got := intValue(refillTicksDropped) - before; got != 1 {
		t.Fatalf("refillTicksDropped delta = %d, want 1", got)
	}
}

func TestMetrics_GCReapedCounter(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()

	// Two aged released rows.
	for _, id := range []string{"vmms-r1", "vmms-r2"} {
		if err := p.RecordSpawning(ctx, id, "tpl-a", now.Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := p.RecordFailed(ctx, id, "boom", now.Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	before := intValue(gcReapedTotal)
	p.runGCOnce(ctx, time.Hour)
	if got := intValue(gcReapedTotal) - before; got != 2 {
		t.Fatalf("gcReapedTotal delta = %d, want 2", got)
	}
}

func TestMetrics_SlotGaugesPublishedAtTickTail(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	p.SetDepth("tpl-gauges", 2)
	spawner := &fakeSpawner{}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-gauges", VsockCID: 3}}}

	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)

	// Two slots got spawned and recorded as 'loaded', and the publish
	// step at the tail of runRefillOnce wrote them into slotGauges.
	if got := nestedMapInt(slotGauges, "tpl_gauges", "loaded"); got != 2 {
		t.Fatalf("slotGauges[tpl_gauges][loaded] = %d, want 2", got)
	}
	if got := nestedMapInt(slotGauges, "tpl_gauges", "total"); got != 2 {
		t.Fatalf("slotGauges[tpl_gauges][total] = %d, want 2", got)
	}
}

func TestMetrics_HandlesGaugeTracksRegisterAndAcquire(t *testing.T) {
	p, _ := newTestPool(t)
	before := intValue(handlesInMemory)

	p.registerHandle("vmms-h1", &stubHandle{})
	p.registerHandle("vmms-h2", &stubHandle{})
	if got := intValue(handlesInMemory) - before; got != 2 {
		t.Fatalf("handlesInMemory after 2 registers = +%d, want +2", got)
	}

	// Re-register the same slotID — must NOT double-count.
	p.registerHandle("vmms-h1", &stubHandle{})
	if got := intValue(handlesInMemory) - before; got != 2 {
		t.Fatalf("handlesInMemory after dup register = +%d, want +2 (idempotent)", got)
	}

	if _, ok := p.takeHandle("vmms-h1"); !ok {
		t.Fatal("takeHandle returned !ok for registered slot")
	}
	if got := intValue(handlesInMemory) - before; got != 1 {
		t.Fatalf("handlesInMemory after take = +%d, want +1", got)
	}

	if drained := p.Close(context.Background(), 0); drained != 1 {
		t.Fatalf("Close drained = %d, want 1", drained)
	}
	if got := intValue(handlesInMemory) - before; got != 0 {
		t.Fatalf("handlesInMemory after Close = +%d, want +0", got)
	}
}

// stubHandle is a minimal SpawnedHandle for the handles-gauge tests.
// Distinct from the fakeHandle in refill_test.go because that one
// requires a parent *fakeSpawner just to count shutdowns, which is
// noise for the gauge tests.
type stubHandle struct {
	api string
	run string
}

func (h *stubHandle) APISocket() string                                 { return h.api }
func (h *stubHandle) RunDir() string                                    { return h.run }
func (h *stubHandle) Pid() int                                          { return 0 }
func (h *stubHandle) Shutdown(_ context.Context, _ time.Duration) error { return nil }

// errFakeSpawn is the sentinel test error for the spawn-failure case.
var errFakeSpawn = &stringError{msg: "fake spawn failure"}

type stringError struct{ msg string }

func (e *stringError) Error() string { return e.msg }

func TestMetrics_ClassifyAcquireError(t *testing.T) {
	// nil → empty string (no outcome)
	if got := metricsClassifyAcquireError(nil); got != "" {
		t.Fatalf("nil error → %q, want empty", got)
	}
	// error containing "no loaded slot" → miss (defensive path)
	if got := metricsClassifyAcquireError(errors.New("vmm pool: no loaded slot for template")); got != acquireOutcomeMiss {
		t.Fatalf("'no loaded slot' error → %q, want miss", got)
	}
	// any other error → error outcome
	if got := metricsClassifyAcquireError(errors.New("sqlite: database is closed")); got != acquireOutcomeError {
		t.Fatalf("generic error → %q, want error", got)
	}
}

func TestMetrics_RecordRefillShortfall_NoOp(t *testing.T) {
	before := mapInt(refillShortfall, "tpl_noop")
	// Zero shortfall → no increment.
	recordRefillShortfall("tpl-noop", 0)
	if got := mapInt(refillShortfall, "tpl_noop") - before; got != 0 {
		t.Fatalf("zero shortfall bumped counter by %d", got)
	}
	// Negative shortfall → no increment.
	recordRefillShortfall("tpl-noop", -1)
	if got := mapInt(refillShortfall, "tpl_noop") - before; got != 0 {
		t.Fatalf("negative shortfall bumped counter by %d", got)
	}
	// Empty templateID → no increment.
	before2 := intValue(refillShortfall)
	recordRefillShortfall("", 5)
	if intValue(refillShortfall) != before2 {
		t.Fatal("empty templateID should be a no-op")
	}
}

func TestMetrics_PublishSlotStats_EmptyTemplateID(t *testing.T) {
	before := intValue(slotGauges)
	// Empty templateID → early return; slotGauges must not change.
	publishSlotStats("", Stats{Loaded: 3})
	if intValue(slotGauges) != before {
		t.Fatal("publishSlotStats with empty templateID should be a no-op")
	}
}

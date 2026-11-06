package dockerpool

import (
	"context"
	"errors"
	"expvar"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// review923FailDestroy is the reviewer's spawner: the engine refuses every
// teardown.
type review923FailDestroy struct {
	fakeSpawner
	calls int
}

func (s *review923FailDestroy) DestroyParked(context.Context, *ParkedSlot) error {
	s.calls++
	return errors.New("engine unavailable")
}

// Review 2 finding 8 (#952-#954): deleting a pool entry must not forget a
// parked container whose teardown failed, nor release the capacity it still
// uses.
func TestReview923PoolDeleteMustRetainFailedCleanup(t *testing.T) {
	p := New(nil)
	spawner := &review923FailDestroy{}
	p.SetSpawner(spawner)
	released := false
	p.SetParkReleaser(func(string) { released = true })
	key := testKey()
	p.SetConfigured([]Configured{{Key: key, Depth: 1}})
	parkSlot(p, "park-review", key)
	p.SetConfigured(nil)
	if released && !p.HasReady(key) {
		t.Fatal("failed parked-container deletion lost inventory and released its live capacity")
	}
}

// flakySpawner fails the first `fail` teardowns of each slot, then succeeds.
// It records every slot it was asked to destroy, as passed.
type flakySpawner struct {
	mu    sync.Mutex
	fail  int
	tries map[string]int
	seen  []*ParkedSlot
}

func (f *flakySpawner) Park(context.Context, string, Key) (*ParkedSlot, error) {
	return nil, errors.New("not implemented")
}

func (f *flakySpawner) DestroyParked(ctx context.Context, slot *ParkedSlot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("teardown ran without a deadline")
	}
	if f.tries == nil {
		f.tries = map[string]int{}
	}
	f.seen = append(f.seen, slot)
	f.tries[slot.ID]++
	if f.tries[slot.ID] <= f.fail {
		return errors.New("engine busy")
	}
	return nil
}

func (f *flakySpawner) count(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tries[id]
}

type readyNote struct {
	id    string
	ready bool
}

// pendingHarness is a pool on a fake clock with a failing engine, recording
// releases and readiness notices.
type pendingHarness struct {
	p        *Pool
	sp       *flakySpawner
	now      time.Time
	released []string
	notes    []readyNote
}

func newPendingHarness(t *testing.T, fail int) *pendingHarness {
	t.Helper()
	h := &pendingHarness{p: New(nil), sp: &flakySpawner{fail: fail}, now: time.Unix(1_000_000, 0)}
	h.p.now = func() time.Time { return h.now }
	h.p.SetSpawner(h.sp)
	h.p.SetParkReleaser(func(id string) { h.released = append(h.released, id) })
	h.p.SetParkReadyNotifier(func(id string, ready bool) { h.notes = append(h.notes, readyNote{id, ready}) })
	t.Cleanup(func() { pendingGauges.set(h.p, 0, time.Time{}) })
	return h
}

func (h *pendingHarness) wasReleased(id string) bool {
	for _, r := range h.released {
		if r == id {
			return true
		}
	}
	return false
}

// Every path that takes a slot out of its ready queue to destroy it keeps a
// failed teardown charged and retries it on the refill tick until the
// engine confirms it, then releases the reservation exactly once.
func TestFailedTeardownIsKeptChargedAndRetriedUntilGone(t *testing.T) {
	cases := []struct {
		name    string
		discard func(h *pendingHarness, key Key)
	}{
		{"entry deleted", func(h *pendingHarness, key Key) {
			h.p.SetConfigured([]Configured{{Key: key, Depth: 1}})
			parkSlot(h.p, "park-a", key)
			h.p.SetConfigured(nil)
		}},
		{"depth lowered", func(h *pendingHarness, key Key) {
			h.p.SetConfigured([]Configured{{Key: key, Depth: 1}})
			parkSlot(h.p, "park-keep", key)
			parkSlot(h.p, "park-a", key)
			h.p.destroySlots(context.Background(), h.p.trimExcess())
		}},
		{"image replaced", func(h *pendingHarness, key Key) {
			h.p.SetConfigured([]Configured{{Key: key, Depth: 1}})
			h.p.RecordLoaded(&ParkedSlot{ID: "park-a", Key: key, ImageID: "sha256:old", Handle: &fakeHandle{alive: true}})
			h.p.SetImageResolver(func(context.Context, Key) (string, error) { return "sha256:new", nil })
			h.p.destroySlots(context.Background(), h.p.refreshImages(context.Background()))
		}},
		{"idle target reaped", func(h *pendingHarness, key Key) {
			h.p.SetIdleTTL(time.Minute)
			h.p.NoteTarget(key)
			parkSlot(h.p, "park-a", key)
			h.p.ReapIdle(time.Now().Add(time.Hour))
		}},
		{"target evicted after park failures", func(h *pendingHarness, key Key) {
			h.p.NoteTarget(key)
			parkSlot(h.p, "park-a", key)
			for i := 0; i < maxConsecutiveSpawnFails; i++ {
				h.p.NoteSpawnFailure(key.KeyString())
			}
		}},
		{"dead slot pruned on acquire", func(h *pendingHarness, key Key) {
			h.p.NoteTarget(key)
			h.p.RecordLoaded(&ParkedSlot{ID: "park-a", Key: key, Handle: &fakeHandle{alive: false}})
			_, _ = h.p.Acquire(context.Background(), key, "")
		}},
		{"pool closed", func(h *pendingHarness, key Key) {
			h.p.NoteTarget(key)
			parkSlot(h.p, "park-a", key)
			h.p.Close() // its own retry fails too (fail=2)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newPendingHarness(t, 2)
			key := testKey()
			tc.discard(h, key)

			if h.wasReleased("park-a") {
				t.Fatal("the reservation of a container that is still there was released")
			}
			if n, _ := h.p.PendingDestroys(); n != 1 {
				t.Fatalf("pending teardowns = %d, want 1", n)
			}
			if h.p.HasReady(key) && tc.name != "depth lowered" {
				t.Fatal("a slot given up for teardown is still offered to creates")
			}
			if got := h.p.Metrics().Stats().DestroyFailures; got < 1 {
				t.Fatalf("destroy failures metric = %d", got)
			}
			if len(h.notes) == 0 || h.notes[len(h.notes)-1] != (readyNote{"park-a", false}) {
				t.Fatalf("admitter was not told the slot is no longer reclaimable: %v", h.notes)
			}

			// Retries follow the backoff, not every tick, and keep charging
			// until the engine confirms the container is gone.
			for h.sp.count("park-a") <= h.sp.fail {
				before := h.sp.count("park-a")
				h.p.retryPendingDestroys(context.Background(), false)
				if h.sp.count("park-a") != before {
					t.Fatal("retried before its delay passed")
				}
				h.now = h.now.Add(pendingDestroyMaxDelay)
				h.p.retryPendingDestroys(context.Background(), false)
				if h.sp.count("park-a") <= h.sp.fail && h.wasReleased("park-a") {
					t.Fatal("released while the teardown still fails")
				}
			}
			if n, _ := h.p.PendingDestroys(); n != 0 {
				t.Fatalf("pending teardowns after success = %d, want 0", n)
			}
			released := 0
			for _, r := range h.released {
				if r == "park-a" {
					released++
				}
			}
			if released != 1 {
				t.Fatalf("park-a released %d times, want once", released)
			}
		})
	}
}

// A retry is marked as one and carries no handle (the first attempt closed
// it). It keeps the address: containerd clears its rules only once the
// container is confirmed gone, and docker skips the address on a retry.
func TestPendingTeardownRetryIsMarkedAndKeepsAddress(t *testing.T) {
	h := newPendingHarness(t, 1)
	key := testKey()
	h.p.NoteTarget(key)
	h.p.RecordLoaded(&ParkedSlot{ID: "park-a", ContainerID: "ctr-a", ContainerIP: "10.0.0.9", ImageID: "img", Key: key, BootstrapToken: "tok", Handle: &fakeHandle{alive: true}})
	h.p.Close()
	if len(h.sp.seen) != 2 {
		t.Fatalf("teardown calls = %d, want the close plus its one retry", len(h.sp.seen))
	}
	first, retry := h.sp.seen[0], h.sp.seen[1]
	if first.ContainerIP == "" || first.Handle == nil || first.TeardownRetry {
		t.Fatal("the first teardown must get the full, unmarked slot")
	}
	if !retry.TeardownRetry || retry.Handle != nil || retry.BootstrapToken != "" {
		t.Fatalf("retry = %+v, want marked, without handle or token", retry)
	}
	if retry.ID != "park-a" || retry.ContainerID != "ctr-a" || retry.ContainerIP != "10.0.0.9" || retry.ImageID != "img" || retry.Key != key {
		t.Fatalf("retry lost the container identity: %+v", retry)
	}
	if !h.wasReleased("park-a") {
		t.Fatal("close's retry succeeded but the reservation was not released")
	}
}

// Reclaim releases before it returns (the admitter contract). A failed
// background teardown is still kept and retried, with nothing left to
// release.
func TestReclaimFailedTeardownIsRetriedWithoutSecondRelease(t *testing.T) {
	h := newPendingHarness(t, 1)
	key := testKey()
	h.p.NoteTarget(key)
	parkSlot(h.p, "park-a", key)
	if got := h.p.Reclaim(1); got != 1 {
		t.Fatalf("Reclaim = %d", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n, _ := h.p.PendingDestroys(); n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed reclaim teardown was not kept")
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.now = h.now.Add(pendingDestroyMaxDelay)
	h.p.retryPendingDestroys(context.Background(), false)
	if n, _ := h.p.PendingDestroys(); n != 0 {
		t.Fatalf("pending after retry = %d", n)
	}
	if len(h.released) != 1 {
		t.Fatalf("releases = %v, want exactly the one Reclaim did", h.released)
	}
}

// parkThenDelete parks a slot while its entry is deleted, so the refill tick
// must destroy the slot it just parked.
type parkThenDelete struct {
	p     *Pool
	fails int
	tries int
}

func (s *parkThenDelete) Park(_ context.Context, slotID string, key Key) (*ParkedSlot, error) {
	s.p.SetConfigured(nil)
	return &ParkedSlot{ID: slotID, Key: key, Handle: &fakeHandle{alive: true}}, nil
}

func (s *parkThenDelete) DestroyParked(context.Context, *ParkedSlot) error {
	s.tries++
	if s.tries <= s.fails {
		return errors.New("engine busy")
	}
	return nil
}

func TestRefillParkOfDeletedEntryKeepsReservationUntilTeardown(t *testing.T) {
	p := New(nil)
	now := time.Unix(2_000_000, 0)
	p.now = func() time.Time { return now }
	t.Cleanup(func() { pendingGauges.set(p, 0, time.Time{}) })
	key := testKey()
	p.SetConfigured([]Configured{{Key: key, Depth: 1}})
	spawner := &parkThenDelete{p: p, fails: 1}
	p.SetSpawner(spawner)
	gate := &refillGate{canPark: true}
	cfg := RefillConfig{ParkShape: ParkShape{Runtime: models.RuntimeDocker}}

	p.refillTick(context.Background(), cfg, spawner, gate)
	if len(gate.reserved) != 1 || len(gate.released) != 0 {
		t.Fatalf("reserved=%v released=%v: the failed teardown gave its reservation back", gate.reserved, gate.released)
	}
	now = now.Add(pendingDestroyMaxDelay)
	p.refillTick(context.Background(), cfg, spawner, gate)
	if len(gate.released) != 1 || gate.released[0] != gate.reserved[0] {
		t.Fatalf("released=%v, want the slot's reservation once the teardown succeeded", gate.released)
	}
}

func TestPendingDestroyDelayDoublesToCap(t *testing.T) {
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		if got := pendingDestroyDelay(i + 1); got != w {
			t.Fatalf("delay after %d tries = %v, want %v", i+1, got, w)
		}
	}
	if got := pendingDestroyDelay(1000); got != pendingDestroyMaxDelay {
		t.Fatalf("delay is not capped: %v", got)
	}
}

// The same container failing again on another path keeps one entry and its
// first-failure age, and keeps the release it already had.
func TestRetainFailedDestroyTwiceKeepsAgeAndRelease(t *testing.T) {
	h := newPendingHarness(t, 10)
	slot := &ParkedSlot{ID: "park-a", Key: testKey()}
	h.p.retainFailedDestroy(slot, h.p.releasePark, errors.New("one"))
	h.now = h.now.Add(time.Minute)
	h.p.retainFailedDestroy(slot, nil, errors.New("two"))
	n, age := h.p.PendingDestroys()
	if n != 1 || age != time.Minute {
		t.Fatalf("pending=%d age=%v, want 1 and 1m", n, age)
	}
	h.p.mu.Lock()
	e := h.p.pending["park-a"]
	h.p.mu.Unlock()
	if e.tries != 2 || e.release == nil || e.lastErr != "two" {
		t.Fatalf("entry = %+v", e)
	}
	h.sp.fail = 0
	h.p.retryPendingDestroys(context.Background(), true)
	if !h.wasReleased("park-a") {
		t.Fatal("the release recorded by the first failure was lost")
	}
}

func TestDestroySlotWithoutSpawnerReleases(t *testing.T) {
	p := New(nil)
	var released []string
	p.destroySlot(context.Background(), nil, &ParkedSlot{ID: "park-a"}, func(id string) { released = append(released, id) })
	p.destroySlot(context.Background(), nil, nil, nil)
	p.destroySlot(context.Background(), nil, &ParkedSlot{ID: "park-b"}, nil)
	p.retryPendingDestroys(context.Background(), true) // no spawner: no-op
	if len(released) != 1 || released[0] != "park-a" {
		t.Fatalf("released = %v", released)
	}
	var nilPool *Pool
	if n, age := nilPool.PendingDestroys(); n != 0 || age != 0 {
		t.Fatal("nil pool reports pending teardowns")
	}
}

// A retry that is still failing stays counted; a slot with no ID is keyed by
// its container.
func TestPendingRetryFailureKeepsEntryAndCountsIt(t *testing.T) {
	h := newPendingHarness(t, 5)
	h.p.destroySlots(context.Background(), []*ParkedSlot{{ContainerID: "ctr-only", Key: testKey()}})
	before := h.p.Metrics().Stats().DestroyFailures
	h.p.retryPendingDestroys(context.Background(), true)
	if got := h.p.Metrics().Stats().DestroyFailures; got != before+1 {
		t.Fatalf("failures %d -> %d, want +1", before, got)
	}
	h.p.mu.Lock()
	_, ok := h.p.pending["ctr-only"]
	h.p.mu.Unlock()
	if !ok {
		t.Fatal("a slot with no ID was not kept by its container ID")
	}
}

// The process-wide gauges sum the pools on a host and show the oldest wait.
func TestPendingDestroyGaugesSumPools(t *testing.T) {
	a, b := newPendingHarness(t, 10), newPendingHarness(t, 10)
	b.now = a.now.Add(-time.Hour) // b's failure is older
	a.p.destroySlots(context.Background(), []*ParkedSlot{{ID: "park-a1"}, {ID: "park-a2"}})
	b.p.destroySlots(context.Background(), []*ParkedSlot{{ID: "park-b1"}})

	n, age := pendingGauges.totals(a.now)
	if n < 3 || age < time.Hour {
		t.Fatalf("gauges n=%d age=%v, want >=3 and >=1h", n, age)
	}
	count, err := strconv.Atoi(expvar.Get("aerolvm_docker_pool_pending_destroys").String())
	if err != nil || count < 3 {
		t.Fatalf("expvar pending = %q (%v)", expvar.Get("aerolvm_docker_pool_pending_destroys").String(), err)
	}
	if _, err := strconv.ParseFloat(expvar.Get("aerolvm_docker_pool_pending_destroy_oldest_seconds").String(), 64); err != nil {
		t.Fatalf("oldest gauge is not a number: %v", err)
	}
	if expvar.Get("aerolvm_docker_pool_destroy_failures_total") == nil {
		t.Fatal("failure counter not published")
	}

	// A pool whose list empties leaves the registry (other tests' pools may
	// still be in it, so check these two, not the total).
	b.sp.fail = 0
	b.p.retryPendingDestroys(context.Background(), true)
	pendingGauges.mu.Lock()
	_, stillB := pendingGauges.pools[b.p]
	pendingGauges.mu.Unlock()
	if stillB {
		t.Fatal("a pool with no pending teardowns stayed in the gauge registry")
	}
	if n, _ := pendingGauges.totals(a.now); n < 2 {
		t.Fatalf("pool a's entries left the gauges: n=%d", n)
	}
	empty := &pendingRegistry{pools: map[*Pool]pendingStat{}}
	if n, age := empty.totals(time.Now()); n != 0 || age != 0 {
		t.Fatalf("empty registry n=%d age=%v", n, age)
	}
}

package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock advances only when the test tells it to so the coalescer
// can be driven through its debounce window without time.Sleep.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestCoalescer(t *testing.T, interval time.Duration) (*touchCoalescer, *fakeClock, *atomic.Int64, func() []time.Time) {
	t.Helper()
	clock := newFakeClock()
	var flushCount atomic.Int64
	var mu sync.Mutex
	var flushedAt []time.Time
	flush := func(_ context.Context, _ string, at time.Time) error {
		flushCount.Add(1)
		mu.Lock()
		flushedAt = append(flushedAt, at)
		mu.Unlock()
		return nil
	}
	c := newTouchCoalescer(interval, flush)
	c.now = clock.Now
	return c, clock, &flushCount, func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		out := make([]time.Time, len(flushedAt))
		copy(out, flushedAt)
		return out
	}
}

// TestTouchCoalescerCollapsesBurst — P2 regression. A wave of touches
// against one sandbox inside the debounce window must collapse to a
// single flush. Pre-fix every wake-aware HTTP request did a synchronous
// SQLite UPDATE; this assertion prevents the original behavior from
// regressing.
func TestTouchCoalescerCollapsesBurst(t *testing.T) {
	c, _, flushes, _ := newTestCoalescer(t, 5*time.Second)
	ctx := context.Background()

	for i := 0; i < 1000; i++ {
		if err := c.Touch(ctx, "sb-1"); err != nil {
			t.Fatalf("Touch %d: %v", i, err)
		}
	}
	if got := flushes.Load(); got != 1 {
		t.Fatalf("flush count = %d, want 1 (one flush per burst inside the window)", got)
	}
}

// TestTouchCoalescerFlushesAfterWindow — touches separated by more than
// the debounce interval each get their own flush. This is the property
// that keeps last_active_at fresh enough for the idle sweep.
func TestTouchCoalescerFlushesAfterWindow(t *testing.T) {
	c, clock, flushes, _ := newTestCoalescer(t, 5*time.Second)
	ctx := context.Background()

	_ = c.Touch(ctx, "sb-1") // flush 1
	clock.Advance(2 * time.Second)
	_ = c.Touch(ctx, "sb-1") // suppressed
	clock.Advance(4 * time.Second)
	_ = c.Touch(ctx, "sb-1") // flush 2 (6s since flush 1)
	clock.Advance(5 * time.Second)
	_ = c.Touch(ctx, "sb-1") // flush 3 (5s since flush 2 — boundary)

	if got := flushes.Load(); got != 3 {
		t.Fatalf("flush count = %d, want 3 (one per window)", got)
	}
}

// TestTouchCoalescerIndependentSandboxes — distinct sandbox ids do not
// share a debounce slot. A flush for sb-1 must not suppress a flush for
// sb-2.
func TestTouchCoalescerIndependentSandboxes(t *testing.T) {
	c, _, flushes, _ := newTestCoalescer(t, 5*time.Second)
	ctx := context.Background()

	_ = c.Touch(ctx, "sb-1")
	_ = c.Touch(ctx, "sb-2")
	_ = c.Touch(ctx, "sb-3")
	// Now bursts on each — should not add any new flushes.
	for i := 0; i < 100; i++ {
		_ = c.Touch(ctx, "sb-1")
		_ = c.Touch(ctx, "sb-2")
		_ = c.Touch(ctx, "sb-3")
	}
	if got := flushes.Load(); got != 3 {
		t.Fatalf("flush count = %d, want 3 (one per distinct sandbox)", got)
	}
}

// TestTouchCoalescerConcurrent — N goroutines hammering the same
// sandbox simultaneously must still collapse to one flush per window.
// Under -race this also asserts the lock discipline is correct.
func TestTouchCoalescerConcurrent(t *testing.T) {
	c, _, flushes, _ := newTestCoalescer(t, 5*time.Second)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = c.Touch(ctx, "sb-hot")
			}
		}()
	}
	wg.Wait()
	if got := flushes.Load(); got != 1 {
		t.Fatalf("flush count = %d, want 1 across all goroutines", got)
	}
}

// TestTouchCoalescerForgetForcesNextFlush — Forget drops the cached
// stamp so the next Touch flushes immediately even if it lands inside
// what would have been the debounce window.
func TestTouchCoalescerForgetForcesNextFlush(t *testing.T) {
	c, clock, flushes, _ := newTestCoalescer(t, 5*time.Second)
	ctx := context.Background()

	_ = c.Touch(ctx, "sb-1") // flush 1
	clock.Advance(1 * time.Second)
	_ = c.Touch(ctx, "sb-1") // suppressed
	if got := flushes.Load(); got != 1 {
		t.Fatalf("pre-forget flush count = %d, want 1", got)
	}
	c.Forget("sb-1")
	_ = c.Touch(ctx, "sb-1") // flush 2 — Forget cleared the stamp
	if got := flushes.Load(); got != 2 {
		t.Fatalf("post-forget flush count = %d, want 2", got)
	}
}

// TestTouchCoalescerPruneBoundsMap — once the map crosses the prune
// threshold, entries older than 10x the interval must be evicted. The
// pathological scenario this guards against is a node touching many
// distinct destroyed sandboxes — without pruning the map would grow
// without bound.
func TestTouchCoalescerPruneBoundsMap(t *testing.T) {
	c, clock, _, _ := newTestCoalescer(t, 100*time.Millisecond)
	ctx := context.Background()

	// Touch enough distinct ids to cross the prune threshold.
	for i := 0; i < touchCoalescerPruneAt+10; i++ {
		_ = c.Touch(ctx, fmt.Sprintf("sb-%d", i))
	}
	// Walk the clock past 10x interval so every existing entry is stale.
	clock.Advance(11 * 100 * time.Millisecond)
	// One more touch triggers the prune path (map is over the
	// threshold and we now have a stale cutoff).
	_ = c.Touch(ctx, "sb-trigger-prune")

	c.mu.Lock()
	size := len(c.last)
	c.mu.Unlock()
	// After prune we should have just the fresh entry. Allow a small
	// margin for entries created at exactly cutoff (the prune uses
	// strict Before).
	if size > 5 {
		t.Fatalf("map size after prune = %d, want <= 5", size)
	}
}

// TestTouchCoalescerFlushErrorBubblesUp — flush errors are returned to
// the caller (the in-memory stamp is still set, so the next Touch
// inside the window stays suppressed; the call site is expected to log
// or ignore as appropriate, mirroring the current `_ = TouchSandbox`
// pattern in ingressproxy and sshgateway).
func TestTouchCoalescerFlushErrorBubblesUp(t *testing.T) {
	flushErr := errors.New("disk full")
	c := newTouchCoalescer(5*time.Second, func(_ context.Context, _ string, _ time.Time) error {
		return flushErr
	})
	if err := c.Touch(context.Background(), "sb-1"); !errors.Is(err, flushErr) {
		t.Fatalf("Touch err = %v, want %v", err, flushErr)
	}
}

// TestServiceTouchSandboxCoalescesStoreWrites is the end-to-end
// regression for P2: many Service.TouchSandbox calls against a single
// sandbox inside the debounce window must collapse to one SQLite
// UPDATE. We assert via the observed last_active_at: 1000 rapid
// touches advance the row exactly once, not 1000 times. Pre-fix, every
// wake-aware HTTP request did its own UPDATE against the
// single-writer SQLite store — a single hot sandbox could starve every
// other writer on the node.
func TestServiceTouchSandboxCoalescesStoreWrites(t *testing.T) {
	ctx := context.Background()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	seedServerlessSandbox(t, st, "sb-coalesce", true)

	pre, err := st.Get(ctx, "sb-coalesce")
	if err != nil {
		t.Fatalf("get pre: %v", err)
	}

	// First touch flushes (no prior entry). Capture the resulting row
	// so we can prove subsequent touches don't move the timestamp.
	if err := svc.TouchSandbox(ctx, "sb-coalesce"); err != nil {
		t.Fatalf("first touch: %v", err)
	}
	afterFirst, err := st.Get(ctx, "sb-coalesce")
	if err != nil {
		t.Fatalf("get after first touch: %v", err)
	}
	if !afterFirst.LastActiveAt.After(pre.LastActiveAt) {
		t.Fatalf("first touch did not advance LastActiveAt: pre=%v post=%v",
			pre.LastActiveAt, afterFirst.LastActiveAt)
	}

	// Wall-clock-aware: the real Service uses time.Now() for the
	// coalescer. Spin a burst of 1000 sequential touches; all should
	// land inside the 5s debounce window and be suppressed.
	for i := 0; i < 1000; i++ {
		if err := svc.TouchSandbox(ctx, "sb-coalesce"); err != nil {
			t.Fatalf("burst touch %d: %v", i, err)
		}
	}
	afterBurst, err := st.Get(ctx, "sb-coalesce")
	if err != nil {
		t.Fatalf("get after burst: %v", err)
	}
	if !afterBurst.LastActiveAt.Equal(afterFirst.LastActiveAt) {
		t.Fatalf("burst advanced LastActiveAt — coalescer not engaged: "+
			"afterFirst=%v afterBurst=%v",
			afterFirst.LastActiveAt, afterBurst.LastActiveAt)
	}
}

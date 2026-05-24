package service

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// TestAcquireWakeStartSlotCapsConcurrency: with cfg.WakeStartConcurrency=2,
// only 2 callers may hold a slot at once. The third must block until one
// release fires. Without the cap, concurrent wakes for different sandboxes
// would all hit Docker create/start + Caddy admin in lockstep — the storm
// this guard exists to prevent.
func TestAcquireWakeStartSlotCapsConcurrency(t *testing.T) {
	svc := &Service{cfg: config.Config{WakeStartConcurrency: 2}}

	r1, err := svc.acquireWakeStartSlot(context.Background())
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	r2, err := svc.acquireWakeStartSlot(context.Background())
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}

	// Third acquire must block: prove it by racing against a 50ms ctx.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := svc.acquireWakeStartSlot(ctx); err == nil {
		t.Fatal("third acquire returned nil; expected ctx.DeadlineExceeded")
	} else if err != context.DeadlineExceeded {
		t.Fatalf("third acquire err = %v, want DeadlineExceeded", err)
	}

	// Releasing one slot unblocks a fresh acquire.
	r1()
	done := make(chan error, 1)
	go func() {
		_, e := svc.acquireWakeStartSlot(context.Background())
		done <- e
	}()
	select {
	case e := <-done:
		if e != nil {
			t.Fatalf("acquire after release: %v", e)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("acquire did not unblock after release")
	}
	r2()
}

// TestAcquireWakeStartSlotZeroCfgIsUnbounded: a zero or negative cfg value
// disables the cap entirely. Test harnesses building &Service{} without
// config rely on this — they never need to thread the new field through.
func TestAcquireWakeStartSlotZeroCfgIsUnbounded(t *testing.T) {
	svc := &Service{cfg: config.Config{WakeStartConcurrency: 0}}

	for i := 0; i < 1000; i++ {
		release, err := svc.acquireWakeStartSlot(context.Background())
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		release()
	}
}

// TestAcquireWakeStartSlotConcurrentNeverExceedsCap: under contention, the
// in-flight count never crosses cfg.WakeStartConcurrency. This is the
// invariant the sem protects in production — without it, the pending caps
// can release thousands of concurrent cross-id starts.
func TestAcquireWakeStartSlotConcurrentNeverExceedsCap(t *testing.T) {
	const (
		cap     = 4
		workers = 200
		holdNS  = int64(2 * time.Millisecond)
	)
	svc := &Service{cfg: config.Config{WakeStartConcurrency: cap}}

	var (
		inFlight atomic.Int64
		maxSeen  atomic.Int64
		wg       sync.WaitGroup
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := svc.acquireWakeStartSlot(context.Background())
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			cur := inFlight.Add(1)
			for {
				prev := maxSeen.Load()
				if cur <= prev || maxSeen.CompareAndSwap(prev, cur) {
					break
				}
			}
			time.Sleep(time.Duration(holdNS))
			inFlight.Add(-1)
			release()
		}()
	}
	wg.Wait()
	if got := maxSeen.Load(); got > int64(cap) {
		t.Fatalf("max in-flight = %d, cap = %d (sem allowed over-subscription)", got, cap)
	}
}

// TestWarmCacheHitsBeforeExpiry: a warmCacheSet entry is observable from
// warmCacheHit until warmCacheTTL elapses; the hot path uses this to skip
// the SQLite preflight on repeated warm requests to the same sandbox.
func TestWarmCacheHitsBeforeExpiry(t *testing.T) {
	svc := &Service{}
	svc.warmCacheSet("sb-hot")
	if !svc.warmCacheHit("sb-hot") {
		t.Fatal("warmCacheHit returned false immediately after set")
	}
	if svc.warmCacheHit("sb-cold") {
		t.Fatal("warmCacheHit returned true for an id never set")
	}
}

// TestWarmCacheInvalidateClearsEntry: invalidateWarm must drop the entry
// so a stop/destroy transition is reflected on the very next call. This
// is the strict-invalidation guarantee that makes a stale-true hit a
// sub-second window under normal event-stream latency.
func TestWarmCacheInvalidateClearsEntry(t *testing.T) {
	svc := &Service{}
	svc.warmCacheSet("sb-1")
	if !svc.warmCacheHit("sb-1") {
		t.Fatal("set did not register")
	}
	svc.invalidateWarm("sb-1")
	if svc.warmCacheHit("sb-1") {
		t.Fatal("warmCacheHit still true after invalidateWarm")
	}
}

// TestWarmCacheExpiresAfterTTL: even with no explicit invalidation, the
// 2s TTL self-heals. We don't sleep the full TTL here — instead we plant
// a synthetic past expiry directly to keep the test fast and
// deterministic.
func TestWarmCacheExpiresAfterTTL(t *testing.T) {
	svc := &Service{}
	svc.warmCacheMu.Lock()
	svc.warmCache = map[string]int64{
		"sb-stale": time.Now().Add(-1 * time.Second).UnixNano(),
	}
	svc.warmCacheMu.Unlock()
	if svc.warmCacheHit("sb-stale") {
		t.Fatal("warmCacheHit returned true for an entry whose expiry has passed")
	}
}

// TestWarmCacheConcurrentReadsAndInvalidate: the cache is hit on every
// warm request, so reads must not block each other and a writer
// (invalidate / set) must not deadlock with them. This is a smoke test
// for the RWMutex usage — it would race-detect or deadlock if reads
// were exclusive or if a Set held the read side.
func TestWarmCacheConcurrentReadsAndInvalidate(t *testing.T) {
	svc := &Service{}
	for i := 0; i < 16; i++ {
		svc.warmCacheSet(toKey(i))
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = svc.warmCacheHit(toKey(id))
				}
			}
		}(i)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				svc.warmCacheSet(toKey(id))
				svc.invalidateWarm(toKey(id))
			}
		}(i)
	}
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func toKey(i int) string {
	return "sb-" + string(rune('a'+i%26))
}

package statekv

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestRateLimitedStoreDeleteThrottle(t *testing.T) {
	inner := &fakeStore{}
	rl := NewRateLimitedStore(inner, 10 /*per sec*/, 1 /*burst*/).(*RateLimitedStore)
	frozen := time.Now()
	rl.now = func() time.Time { return frozen }
	ctx := context.Background()

	// first delete — allowed
	if err := rl.Delete(ctx, "sb", "k"); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	// second — throttled
	if err := rl.Delete(ctx, "sb", "k"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second delete err = %v, want ErrRateLimited", err)
	}
	if inner.deletes != 1 {
		t.Fatalf("inner deletes = %d, want 1", inner.deletes)
	}
}

func TestRateLimitedStorePruneLocked(t *testing.T) {
	inner := &fakeStore{}
	rl := NewRateLimitedStore(inner, 100, 10).(*RateLimitedStore)
	ctx := context.Background()

	base := time.Now()
	rl.now = func() time.Time { return base }

	// Directly populate the bucket map to exceed maxBuckets.
	// We inject idle+fully-refilled buckets so they'll be pruned.
	rl.mu.Lock()
	idleTime := base.Add(-bucketIdleTTL - time.Second)
	for i := 0; i <= maxBuckets; i++ {
		id := "sb-" + strconv.Itoa(i)
		rl.buckets[id] = &tokenBucket{
			tokens:   rl.burst, // fully refilled → eligible for pruning
			last:     idleTime,
			lastSeen: idleTime, // idle past TTL → prunable
		}
	}
	beforePrune := len(rl.buckets)
	rl.mu.Unlock()

	// Calling allow() triggers pruneLocked (called when a new sandbox entry is added)
	_ = rl.Set(ctx, "trigger-prune", "k", []byte("v"))

	rl.mu.Lock()
	afterPrune := len(rl.buckets)
	rl.mu.Unlock()

	if afterPrune >= beforePrune {
		t.Fatalf("expected some buckets to be pruned: before=%d after=%d", beforePrune, afterPrune)
	}
}

func TestNewRateLimitedStoreBurstDefault(t *testing.T) {
	// When burst < 1, it defaults to ratePerSec.
	inner := &fakeStore{}
	rl := NewRateLimitedStore(inner, 5, 0).(*RateLimitedStore)
	if rl.burst != 5 {
		t.Fatalf("burst should default to rate, got %v", rl.burst)
	}
}

func TestRateLimitedStoreRefillCapsAtBurst(t *testing.T) {
	inner := &fakeStore{}
	rl := NewRateLimitedStore(inner, 10 /*per sec*/, 3 /*burst*/).(*RateLimitedStore)
	now := time.Now()
	rl.now = func() time.Time { return now }
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := rl.Set(ctx, "sb", "k", []byte("v")); err != nil {
			t.Fatalf("drain write %d: %v", i, err)
		}
	}
	// Long idle would refill far past burst without the cap branch in allow().
	now = now.Add(2 * time.Second)
	for i := 0; i < 3; i++ {
		if err := rl.Set(ctx, "sb", "k", []byte("v")); err != nil {
			t.Fatalf("post-refill write %d: %v", i, err)
		}
	}
	if err := rl.Set(ctx, "sb", "k", []byte("v")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("7th write should throttle, got %v", err)
	}
}

func TestRateLimitedStoreListKeysPassthrough(t *testing.T) {
	inner := &fakeStore{}
	rl := NewRateLimitedStore(inner, 10, 1)
	ctx := context.Background()

	// Exhaust write budget
	_ = rl.(*RateLimitedStore) // just cast to confirm type
	frozen := time.Now()
	rl.(*RateLimitedStore).now = func() time.Time { return frozen }
	_ = rl.Set(ctx, "sb", "k", []byte("v"))
	if err := rl.Set(ctx, "sb", "k", []byte("v")); !errors.Is(err, ErrRateLimited) {
		t.Fatal("expected throttle")
	}
	// ListKeys must still work
	keys, err := rl.ListKeys(ctx, "sb")
	if err != nil || keys != nil {
		t.Fatalf("ListKeys = %v, %v", keys, err)
	}
}

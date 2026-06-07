package statekv

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeStore counts writes so tests can assert which calls reached the inner store.
type fakeStore struct {
	mu      sync.Mutex
	sets    int
	deletes int
}

func (f *fakeStore) Get(context.Context, string, string) ([]byte, bool, error) {
	return nil, false, nil
}

func (f *fakeStore) Set(context.Context, string, string, []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets++
	return nil
}

func (f *fakeStore) Delete(context.Context, string, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	return nil
}

func (f *fakeStore) ListKeys(context.Context, string) ([]string, error) { return nil, nil }

func TestNewRateLimitedStore_DisabledPassesThrough(t *testing.T) {
	inner := &fakeStore{}
	if got := NewRateLimitedStore(inner, 0, 10); got != Store(inner) {
		t.Fatalf("rate 0 should return inner unchanged, got %T", got)
	}
	if got := NewRateLimitedStore(nil, 5, 10); got != nil {
		t.Fatalf("nil inner should return nil")
	}
}

func TestRateLimitedStore_BurstThenThrottle(t *testing.T) {
	inner := &fakeStore{}
	rl := NewRateLimitedStore(inner, 10 /*per sec*/, 3 /*burst*/).(*RateLimitedStore)
	// Freeze the clock so refill never adds tokens mid-test.
	frozen := time.Now()
	rl.now = func() time.Time { return frozen }
	ctx := context.Background()

	// First write starts the bucket full at burst=3 and consumes 1 → 3 allowed.
	for i := 0; i < 3; i++ {
		if err := rl.Set(ctx, "sb", "k", []byte("v")); err != nil {
			t.Fatalf("write %d should be allowed: %v", i, err)
		}
	}
	// 4th within the same instant must be throttled.
	if err := rl.Set(ctx, "sb", "k", []byte("v")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("4th write err = %v, want ErrRateLimited", err)
	}
	if inner.sets != 3 {
		t.Fatalf("inner sets = %d, want 3 (throttled write must not reach store)", inner.sets)
	}
}

func TestRateLimitedStore_RefillsOverTime(t *testing.T) {
	inner := &fakeStore{}
	rl := NewRateLimitedStore(inner, 10 /*per sec*/, 1 /*burst*/).(*RateLimitedStore)
	now := time.Now()
	rl.now = func() time.Time { return now }
	ctx := context.Background()

	if err := rl.Set(ctx, "sb", "k", []byte("v")); err != nil {
		t.Fatalf("first write allowed: %v", err)
	}
	if err := rl.Set(ctx, "sb", "k", []byte("v")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second immediate write should throttle, got %v", err)
	}
	// Advance 100ms → 10/s refills exactly one token.
	now = now.Add(100 * time.Millisecond)
	if err := rl.Set(ctx, "sb", "k", []byte("v")); err != nil {
		t.Fatalf("write after refill should be allowed: %v", err)
	}
}

func TestRateLimitedStore_PerSandboxIsolation(t *testing.T) {
	inner := &fakeStore{}
	rl := NewRateLimitedStore(inner, 10, 1).(*RateLimitedStore)
	frozen := time.Now()
	rl.now = func() time.Time { return frozen }
	ctx := context.Background()

	if err := rl.Set(ctx, "a", "k", []byte("v")); err != nil {
		t.Fatalf("sandbox a first write: %v", err)
	}
	// Sandbox a is now empty, but sandbox b has its own full bucket.
	if err := rl.Set(ctx, "b", "k", []byte("v")); err != nil {
		t.Fatalf("sandbox b must not be throttled by a's usage: %v", err)
	}
	if err := rl.Set(ctx, "a", "k", []byte("v")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("sandbox a second write should throttle, got %v", err)
	}
}

func TestRateLimitedStore_ReadsAndListNotThrottled(t *testing.T) {
	inner := &fakeStore{}
	rl := NewRateLimitedStore(inner, 1, 1).(*RateLimitedStore)
	frozen := time.Now()
	rl.now = func() time.Time { return frozen }
	ctx := context.Background()

	// Exhaust the write budget.
	_ = rl.Set(ctx, "sb", "k", []byte("v"))
	if err := rl.Set(ctx, "sb", "k", []byte("v")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected write throttle")
	}
	// Reads/lists must still go through regardless of the write budget.
	for i := 0; i < 5; i++ {
		if _, _, err := rl.Get(ctx, "sb", "k"); err != nil {
			t.Fatalf("Get should not be throttled: %v", err)
		}
		if _, err := rl.ListKeys(ctx, "sb"); err != nil {
			t.Fatalf("ListKeys should not be throttled: %v", err)
		}
	}
}

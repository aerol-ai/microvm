package statekv

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrRateLimited is returned when a sandbox exceeds its host-KV write budget.
// The toolbox handler maps it to HTTP 429 so the guest backs off instead of the
// daemon absorbing the write.
var ErrRateLimited = errors.New("statekv: write rate limit exceeded")

// RateLimitedStore throttles per-sandbox write operations (Set/Delete) on top of
// an inner Store. Host-KV writes land synchronously on the single-writer SQLite
// store (MaxOpenConns=1), so a chatty durable guest can otherwise contend with
// the CreateSandbox boot path on the same writer (plans/wasm-runtime.md §4.6 +
// §4.9; CLAUDE.md single-writer rule forbids a second *sql.DB, so we cap the
// guest-driven write rate instead). Reads pass through unthrottled — they do not
// hold the write lock long enough to matter and read-heavy guests are common.
type RateLimitedStore struct {
	inner Store
	rate  float64 // tokens (writes) per second per sandbox
	burst float64 // bucket capacity

	mu      sync.Mutex
	buckets map[string]*tokenBucket
	now     func() time.Time // injectable clock for tests
}

type tokenBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

// maxBuckets bounds the per-sandbox bucket map. At realistic density (tens of
// durable sandboxes per node) this is never hit; the cap only guards against
// unbounded growth across long-lived churn. When exceeded we drop buckets that
// have been idle long enough to have fully refilled (i.e. carry no useful state).
const maxBuckets = 8192

// bucketIdleTTL is how long a bucket must be untouched before opportunistic
// pruning may drop it.
const bucketIdleTTL = 10 * time.Minute

// NewRateLimitedStore wraps inner with a per-sandbox write limiter. A
// non-positive rate disables limiting and returns inner unchanged so the
// feature is fully off by default.
func NewRateLimitedStore(inner Store, ratePerSec float64, burst int) Store {
	if inner == nil || ratePerSec <= 0 {
		return inner
	}
	b := float64(burst)
	if b < 1 {
		b = ratePerSec
	}
	return &RateLimitedStore{
		inner:   inner,
		rate:    ratePerSec,
		burst:   b,
		buckets: make(map[string]*tokenBucket),
		now:     time.Now,
	}
}

// allow consumes one write token for sandboxID, returning false when the bucket
// is empty. Token-bucket refill is computed lazily from elapsed wall time.
func (s *RateLimitedStore) allow(sandboxID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	bkt := s.buckets[sandboxID]
	if bkt == nil {
		// First write starts full so a single write never trips the limit.
		bkt = &tokenBucket{tokens: s.burst, last: now}
		s.buckets[sandboxID] = bkt
		s.pruneLocked(now)
	}
	elapsed := now.Sub(bkt.last).Seconds()
	if elapsed > 0 {
		bkt.tokens += elapsed * s.rate
		if bkt.tokens > s.burst {
			bkt.tokens = s.burst
		}
		bkt.last = now
	}
	bkt.lastSeen = now
	if bkt.tokens < 1 {
		return false
	}
	bkt.tokens--
	return true
}

// pruneLocked drops idle, fully-refilled buckets when the map grows past the
// cap. Caller must hold s.mu.
func (s *RateLimitedStore) pruneLocked(now time.Time) {
	if len(s.buckets) <= maxBuckets {
		return
	}
	for id, bkt := range s.buckets {
		if now.Sub(bkt.lastSeen) >= bucketIdleTTL && bkt.tokens >= s.burst {
			delete(s.buckets, id)
		}
	}
}

func (s *RateLimitedStore) Get(ctx context.Context, sandboxID, key string) ([]byte, bool, error) {
	return s.inner.Get(ctx, sandboxID, key)
}

func (s *RateLimitedStore) Set(ctx context.Context, sandboxID, key string, value []byte) error {
	if !s.allow(sandboxID) {
		return ErrRateLimited
	}
	return s.inner.Set(ctx, sandboxID, key, value)
}

func (s *RateLimitedStore) Delete(ctx context.Context, sandboxID, key string) error {
	if !s.allow(sandboxID) {
		return ErrRateLimited
	}
	return s.inner.Delete(ctx, sandboxID, key)
}

func (s *RateLimitedStore) ListKeys(ctx context.Context, sandboxID string) ([]string, error) {
	return s.inner.ListKeys(ctx, sandboxID)
}

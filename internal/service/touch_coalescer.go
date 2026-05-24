package service

import (
	"context"
	"sync"
	"time"
)

// touchDebounceInterval bounds how often last_active_at can be flushed
// for a single sandbox. The wake-aware ingress proxy and the toolbox /
// session / runtime control-plane proxies all call TouchSandbox on every
// request, and each Touch is a synchronous UPDATE against the
// single-writer SQLite store. At 1000 RPS into one sandbox that becomes
// 1000 UPDATEs/sec queued behind every other store write — a hot busy
// sandbox would starve the create/start/stop path.
//
// 5s collapses a fan-in of N requests on the same sandbox into one
// UPDATE every 5 seconds. The idle sweep runs once a minute and
// stop_if_idle_for is required to be in minutes when Serverless=true
// (see C1 / plan), so a 5s lag in last_active_at is invisible to the
// sweep — the sandbox cannot be incorrectly stopped because of a
// debounced touch.
//
// Hardcoded for the same reason wakeStartTimeout is (plan D6): one knob
// per actual tuning need. If operators ever need to tune this we add the
// env var then.
const touchDebounceInterval = 5 * time.Second

// touchCoalescerPruneAt is the map-size threshold past which Touch
// opportunistically evicts entries older than 10x the debounce window.
// 4096 is well above the per-node steady state at 100k sandboxes / 2000
// nodes (~50 per node), so the prune path stays cold in normal
// operation; the bound only kicks in on pathological fan-out (e.g. a
// node receiving probes for many destroyed sandboxes). Memory at the
// threshold is ~4096 * (avg-id-len + sizeof(time.Time)) ≈ 256 KiB.
const touchCoalescerPruneAt = 4096

// touchFlushFunc is the underlying store write the coalescer drives.
// Pulled out as a type so tests can inject a counter without standing
// up a SQLite store.
type touchFlushFunc func(ctx context.Context, id string, at time.Time) error

// touchCoalescer debounces per-sandbox last_active_at flushes so a
// burst of HTTP requests against one sandbox collapses to one SQLite
// UPDATE per debounce window. Cold sandboxes (never touched, or last
// touched outside the window) flush synchronously on the next Touch so
// the idle sweep sees a fresh timestamp the next time it runs.
//
// The coalescer is safe for concurrent use. A single sync.Mutex guards
// both `last` and the prune path; per-touch work is a map lookup and at
// most one map write, so contention is negligible even at very high
// per-sandbox RPS.
type touchCoalescer struct {
	mu       sync.Mutex
	last     map[string]time.Time
	interval time.Duration
	now      func() time.Time
	flush    touchFlushFunc
}

func newTouchCoalescer(interval time.Duration, flush touchFlushFunc) *touchCoalescer {
	return &touchCoalescer{
		last:     make(map[string]time.Time),
		interval: interval,
		now:      func() time.Time { return time.Now().UTC() },
		flush:    flush,
	}
}

// Touch flushes last_active_at for id if no flush has happened in the
// past interval, otherwise it is a no-op. The first Touch after a long
// quiet period always flushes; subsequent Touches within the window are
// dropped on the floor.
//
// We mark last[id] BEFORE calling flush so a concurrent second Touch
// for the same id sees the in-flight stamp and skips. If flush errors
// we still leave the stamp in place — the next Touch after the window
// will retry. Repeated transient flush failures would leave
// last_active_at lagging by at most one interval per failure, which the
// caller is expected to log via the returned error if it cares.
func (c *touchCoalescer) Touch(ctx context.Context, id string) error {
	now := c.now()
	c.mu.Lock()
	if prev, ok := c.last[id]; ok && now.Sub(prev) < c.interval {
		c.mu.Unlock()
		return nil
	}
	c.last[id] = now
	if len(c.last) > touchCoalescerPruneAt {
		c.pruneLocked(now)
	}
	c.mu.Unlock()
	return c.flush(ctx, id, now)
}

// pruneLocked evicts entries older than 10x the debounce window. Called
// only when the map crosses the pruneAt threshold. 10x keeps recently
// active sandboxes around (they will skip-flush on their next Touch)
// while reclaiming entries that have gone quiet.
func (c *touchCoalescer) pruneLocked(now time.Time) {
	cutoff := now.Add(-10 * c.interval)
	for k, v := range c.last {
		if v.Before(cutoff) {
			delete(c.last, k)
		}
	}
}

// Forget drops a sandbox's coalescer entry so the next Touch flushes
// immediately. Called on lifecycle transitions where we want the new
// timestamp recorded without the debounce delay — start (fresh wake),
// stop (so a resurrect counts as a real touch), destroy (drop the
// entry permanently).
func (c *touchCoalescer) Forget(id string) {
	c.mu.Lock()
	delete(c.last, id)
	c.mu.Unlock()
}

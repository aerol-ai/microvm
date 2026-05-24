package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// caddyCoalescer batches Caddy admin writes for the same (id, port)
// into one execution per tick. Under HTTPWakeDirectBypassEnabled the
// per-sandbox HTTP route is rewritten on every Start and every Stop
// (wake-aware ↔ direct), doubling the admin write volume vs. today.
// At a node with 100k+ sandboxes and 1k+ starts/stops per minute that
// doubling regresses per-write p99 latency without batching. The
// coalescer collapses a rapid wake → stop → wake sequence for the
// same (id, port) into a single admin call.
//
// Semantics:
//
//   - Enqueue records the LATEST intent for (id, port). Subsequent
//     Enqueues before the next tick overwrite the prior intent — the
//     prior op is dropped. This is the explicit point of the coalescer:
//     intermediate states never reach Caddy.
//
//   - The tick goroutine drains the pending map and executes each
//     stored op exactly once per tick. Execution is sequential within
//     a tick so Caddy's single-threaded admin write path is not
//     hammered, but parallel callers Enqueueing into different (id,
//     port) keys do not block each other.
//
//   - Flush waits for the coalesce window, drains, and waits for the result.
//     Use for ordering-critical callsites that need a write visible to Caddy
//     before continuing (e.g. pre-stop wake install must be observable to
//     incoming requests before docker.Stop fires) while still letting a burst
//     of concurrent callers collapse into one admin write.
//
// The coalescer is callback-based — callers supply a `do func() error`
// that performs the actual Caddy admin write. This keeps the
// coalescer agnostic to which client method (Upsert/Delete/wake/direct)
// is being collapsed; only the (id, port) key matters for batching.
// See plans/warm-direct-route-bypass.md D6 / D12.
type caddyCoalescer struct {
	tick   time.Duration
	logger *slog.Logger

	mu      sync.Mutex
	pending map[coalesceKey]pendingOp

	stop chan struct{}
	done chan struct{}
}

// coalesceKey identifies one (sandbox-id, port) target. Same key for
// wake and direct shapes — that is the whole point: a rapid flip
// between them collapses to one execution of whichever intent landed
// last in the tick window.
type coalesceKey struct {
	id   string
	port int
}

// pendingOp holds the latest intent for one coalesceKey plus a small
// chan slice used to satisfy Flush callers that may be waiting on
// this specific key. Callers without a Flush get no notification —
// fire-and-forget is the default.
type pendingOp struct {
	do      func() error
	notify  []chan<- error
	enqueue time.Time
}

func newCaddyCoalescer(logger *slog.Logger, tick time.Duration) *caddyCoalescer {
	if tick <= 0 {
		tick = 250 * time.Millisecond
	}
	return &caddyCoalescer{
		tick:    tick,
		logger:  logger,
		pending: make(map[coalesceKey]pendingOp),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// Run blocks until ctx is cancelled OR Stop is called. Drains the
// pending map on each tick, then drains once more on the way out so
// in-flight writes are not silently dropped on shutdown.
func (c *caddyCoalescer) Run(ctx context.Context) {
	defer close(c.done)
	t := time.NewTicker(c.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.drain()
			return
		case <-c.stop:
			c.drain()
			return
		case <-t.C:
			c.drain()
		}
	}
}

// Stop signals Run to exit after a final drain. Safe to call once;
// concurrent calls panic on the close. Idempotent via the once-guard
// is intentionally NOT provided — the daemon owns the lifecycle and
// calls Stop exactly once at shutdown.
func (c *caddyCoalescer) Stop() {
	close(c.stop)
	<-c.done
}

// Enqueue records do as the latest intent for (id, port). Any prior
// pending op for the same key is dropped (and any prior Flush waiter
// for that key is notified with a nil error — the drop is by design,
// not a failure). Returns immediately; do runs on the next tick.
func (c *caddyCoalescer) Enqueue(id string, port int, do func() error) {
	c.enqueue(id, port, do, nil)
}

// Flush enqueues do, waits for one coalesce window, drains, and returns the
// result of do. Use this for ordering-critical callsites. ctx bounds how long
// the caller is willing to wait; on ctx cancellation the op is left in the
// pending map and the tick goroutine will eventually execute it, but the caller
// stops waiting.
func (c *caddyCoalescer) Flush(ctx context.Context, id string, port int, do func() error) error {
	ch := make(chan error, 1)
	c.enqueue(id, port, do, ch)

	timer := time.NewTimer(c.tick)
	defer timer.Stop()
	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		go c.drain()
	}

	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *caddyCoalescer) enqueue(id string, port int, do func() error, notify chan<- error) {
	key := coalesceKey{id: id, port: port}
	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, ok := c.pending[key]; ok {
		// A prior op is being dropped. Notify any prior Flush waiters
		// with a nil error — they got the eventual consistency they
		// asked for via a newer write of the same key.
		for _, n := range prev.notify {
			select {
			case n <- nil:
			default:
			}
		}
	}
	op := pendingOp{
		do:      do,
		enqueue: time.Now(),
	}
	if notify != nil {
		op.notify = []chan<- error{notify}
	}
	c.pending[key] = op
}

// drain takes a snapshot of the pending map, clears it, then executes
// each op sequentially. The lock is held only while swapping the map
// so concurrent Enqueues do not block on Caddy admin latency.
func (c *caddyCoalescer) drain() {
	c.mu.Lock()
	if len(c.pending) == 0 {
		c.mu.Unlock()
		return
	}
	batch := c.pending
	c.pending = make(map[coalesceKey]pendingOp, len(batch))
	c.mu.Unlock()

	for key, op := range batch {
		err := op.do()
		if err != nil && c.logger != nil {
			c.logger.Warn("caddy coalescer write failed",
				"sandbox_id", key.id, "port", key.port, "error", err,
				"queued_for", time.Since(op.enqueue).String(),
			)
		}
		for _, n := range op.notify {
			select {
			case n <- err:
			default:
				// Receiver gave up (ctx cancelled). Drop the result.
			}
		}
	}
}

// pendingSize reports the current pending map size. Diagnostics only;
// not part of the hot path. Useful from tests and from expvar
// inspection scripts to see whether the coalescer is keeping up.
func (c *caddyCoalescer) pendingSize() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

// String returns a human-readable summary for debug logs.
func (c *caddyCoalescer) String() string {
	return fmt.Sprintf("caddyCoalescer{tick=%s, pending=%d}", c.tick, c.pendingSize())
}

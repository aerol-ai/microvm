package service

import (
	"context"
	"sync"
	"time"
)

// The snapshot and template push reconcilers each run as ONE worker per
// node. Every create used to start a whole sweep of its own next to the
// ticker's, each with its own semaphore, so a burst of creates meant that
// many sweeps listing the same rows and that many times the configured push
// fan-out. Now a create only wakes the worker, sweeps never overlap, and one
// set of slots bounds the pushes in flight on the node. (The store's claim
// is what keeps two sweeps off one row if they ever do meet; this keeps them
// from meeting in normal operation.)

// pushSweepGate makes a reconciler's sweeps single-flight and carries its
// wake-ups. The zero value is not usable; build one with newPushSweepGate.
type pushSweepGate struct {
	mu      sync.Mutex
	running bool
	rerun   bool
	wake    chan struct{}
}

func newPushSweepGate() *pushSweepGate {
	return &pushSweepGate{wake: make(chan struct{}, 1)}
}

// enter claims the right to sweep. false means a sweep is already running:
// it has been asked to go round once more, so the caller's rows are not
// missed, and the caller should return instead of sweeping alongside it.
func (g *pushSweepGate) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.running {
		g.rerun = true
		return false
	}
	g.running = true
	return true
}

// again is called by the running sweep when it finishes. It reports whether
// another caller arrived meanwhile (sweep once more) and otherwise releases
// the gate. A failed sweep releases it outright: the next tick retries.
func (g *pushSweepGate) again(failed bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.rerun && !failed {
		g.rerun = false
		return true
	}
	g.running, g.rerun = false, false
	return false
}

// kick wakes the worker without blocking. Kicks that arrive while a wake-up
// is already pending collapse into it; the sweep it starts sees every row.
func (g *pushSweepGate) kick() {
	if g == nil {
		return
	}
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

// runPushWorker is the worker loop: a sweep every interval (none when
// interval <= 0) and on every wake-up, never two at once, until ctx ends.
func runPushWorker(ctx context.Context, interval time.Duration, wake <-chan struct{}, sweep func(context.Context)) {
	var tick <-chan time.Time
	if interval > 0 {
		t := time.NewTicker(interval)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
		case <-wake:
		}
		// select picks at random among ready cases, so a wake-up still
		// pending when ctx ends can win over ctx.Done. A sweep then would
		// only fail on the cancelled ctx and report that as an error.
		if ctx.Err() != nil {
			return
		}
		sweep(ctx)
	}
}

// cutShortByShutdown reports whether a sweep failed only because the
// worker's ctx ended while it ran. The worker does not report such a sweep:
// stopping is not a failure, and reporting it logged a spurious error on
// every shutdown that caught a sweep in flight.
func cutShortByShutdown(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() != nil
}

// acquirePushSlot takes one of the node's push slots, or gives up when ctx
// ends. A cancelled ctx never takes a slot, even a free one, so a sweep that
// is being shut down starts no new push.
func acquirePushSlot(ctx context.Context, slots chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

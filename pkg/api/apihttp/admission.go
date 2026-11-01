package apihttp

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"sync"
	"time"
)

// ErrOverloaded is load shedding: this node already runs as many requests of
// one expensive kind as it is configured to, and a short wait freed no slot.
// It is answered at once with 503 and Retry-After (Classify) instead of being
// queued behind the others. On the bank flagship (2026-11-01) queued cluster
// lists reached a 37 s p99 and ended in 502s from a restarted node; a fast,
// retryable refusal keeps the node, and every request it is already serving,
// alive.
var ErrOverloaded = errors.New("this node is serving as many cluster list requests as it is configured to; retry shortly")

// OverloadedRetryAfterSeconds is the Retry-After sent with ErrOverloaded. A
// slot frees as soon as one request in flight ends, usually well inside a
// second, so a short hint is enough; every SDK also backs off on its own.
const OverloadedRetryAfterSeconds = 1

// GateMetrics are a Gate's counters. Any of them may be nil.
type GateMetrics struct {
	InFlight *expvar.Int // requests holding a slot now
	Admitted *expvar.Int // requests that got a slot
	Shed     *expvar.Int // requests refused with ErrOverloaded
}

// Gate bounds how many requests of one expensive kind run at once on this
// node. A request takes a slot, waits at most the gate's queue wait for one
// to free, and otherwise gets ErrOverloaded. A nil *Gate admits everything.
type Gate struct {
	slots   chan struct{}
	wait    time.Duration
	metrics GateMetrics
}

// NewGate returns a gate of limit slots. limit <= 0 means no gate (nil).
func NewGate(limit int, wait time.Duration, metrics GateMetrics) *Gate {
	if limit <= 0 {
		return nil
	}
	if wait < 0 {
		wait = 0
	}
	return &Gate{slots: make(chan struct{}, limit), wait: wait, metrics: metrics}
}

// Acquire takes a slot. On success release must be called once (more is
// safe). It returns ErrOverloaded when no slot freed within the queue wait,
// or when the caller left while waiting (wrapping the context's error).
func (g *Gate) Acquire(ctx context.Context) (release func(), err error) {
	if g == nil {
		return func() {}, nil
	}
	select {
	case g.slots <- struct{}{}:
		return g.admitted(), nil
	default:
	}
	if g.wait > 0 {
		timer := time.NewTimer(g.wait)
		defer timer.Stop()
		select {
		case g.slots <- struct{}{}:
			return g.admitted(), nil
		case <-ctx.Done():
			// The caller left while waiting. Not a shed (no metric), but
			// still ErrOverloaded so the writer answers like one, silently,
			// instead of logging a "request failed" for a client that is
			// gone.
			return nil, fmt.Errorf("%w: %w", ErrOverloaded, ctx.Err())
		case <-timer.C:
		}
	}
	addMetric(g.metrics.Shed, 1)
	return nil, ErrOverloaded
}

// Limit is the number of slots; 0 for a nil gate.
func (g *Gate) Limit() int {
	if g == nil {
		return 0
	}
	return cap(g.slots)
}

func (g *Gate) admitted() func() {
	addMetric(g.metrics.Admitted, 1)
	addMetric(g.metrics.InFlight, 1)
	var once sync.Once
	return func() {
		once.Do(func() {
			addMetric(g.metrics.InFlight, -1)
			<-g.slots
		})
	}
}

func addMetric(v *expvar.Int, delta int64) {
	if v != nil {
		v.Add(delta)
	}
}

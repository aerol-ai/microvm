package runloop

import (
	"sync"
	"time"
)

// failedFlightRetention keeps a failed flight answerable (as `failure` /
// `error`) for callers already polling its id.
const failedFlightRetention = 2 * time.Minute

// flight is one long-running operation (a devbox create, a disk
// snapshot) running detached from the request that started it, so a
// client timeout neither cancels it nor, on retry, starts it twice.
type flight[M any, R any] struct {
	id      string
	started time.Time
	meta    M
	done    chan struct{}

	// Set before done is closed.
	result   R
	err      error
	finished time.Time
}

func (f *flight[M, R]) isDone() bool {
	select {
	case <-f.done:
		return true
	default:
		return false
	}
}

// flightTracker joins concurrent duplicates of one operation on this node.
// The operations it tracks are durably idempotent once finished (the
// devbox or snapshot exists under its deterministic id); what the tracker
// adds is safety for duplicates *in flight at once*. Those only ever come
// from one process lifetime — a restart kills the in-flight work with it —
// so in-memory state on the node running the work is sufficient.
type flightTracker[M any, R any] struct {
	mu      sync.Mutex
	flights map[string]*flight[M, R]
}

func newFlightTracker[M any, R any]() *flightTracker[M, R] {
	return &flightTracker[M, R]{flights: make(map[string]*flight[M, R])}
}

// claim returns the flight for id, starting a new one when there is none
// or the previous attempt failed (a retry after a failure is a new try).
func (t *flightTracker[M, R]) claim(id string, meta M) (*flight[M, R], bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for key, f := range t.flights {
		if f.isDone() && now.Sub(f.finished) > failedFlightRetention {
			delete(t.flights, key)
		}
	}
	if f, ok := t.flights[id]; ok && (!f.isDone() || f.err == nil) {
		return f, false
	}
	f := &flight[M, R]{id: id, started: now, meta: meta, done: make(chan struct{})}
	t.flights[id] = f
	return f, true
}

func (t *flightTracker[M, R]) get(id string) (*flight[M, R], bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.flights[id]
	return f, ok
}

// finish publishes the result. A successful flight leaves the tracker at
// once — the persisted object answers for it from here on — while a failed
// one stays for failedFlightRetention so pollers see the failure, not 404.
// Only failures are retained, so the map stays at in-flight size plus a
// couple of minutes of failures, and the sweep in claim stays cheap.
func (t *flightTracker[M, R]) finish(f *flight[M, R], result R, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f.result, f.err, f.finished = result, err, time.Now()
	close(f.done)
	if err == nil && t.flights[f.id] == f {
		delete(t.flights, f.id)
	}
}

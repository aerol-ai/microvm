package service

import (
	"sync"
	"time"
)

// An exit event is handled only for the run it came from.
//
// A die or stop event waits for the sandbox's lifecycle boundary
// (lifecycle_boundary.go), and so does a start. A program crashes, its die is
// queued, and the user starts the sandbox again at once: the start can take
// the boundary first and start a new run, and the die of the old run is then
// handled against the new run's row. It marked the new run stopped, and with
// restart_on_failure scheduled a restart that killed the user's new program.
//
// What tells the runs apart is time, on the engine's clock: each start
// reports when its run began (SandboxRuntimeState.StartedAt), and an exit
// event stamped before that is of an earlier run. Other signals do not hold:
//
//   - run_generation moves only when the row goes to started, and a start of
//     a row that still says started (its die not yet handled) is a new run
//     that does not move it. Read when an event is queued, it also takes a
//     die of the new run, queued before the start wrote the row, for an old
//     one, and drops a real crash.
//   - the container id stays the same across a stop and a start on Docker
//     and containerd.
//   - sandboxd's own clock is not Docker's on a Mac, where Docker runs in a
//     VM whose clock drifts; a behind clock would drop real crashes.
//
// Both sides are the engine's: Docker's die and stop events carry timeNano
// and its inspect has State.StartedAt, taken before the new process starts.
// The previous run's die is stamped before that, since its start must wait
// for the exit to be recorded; only a start that reaches dockerd while it is
// still recording that exit (microseconds) can be stamped first, and that
// die is then handled as before. containerd's exit carries the shim's
// exited_at, and the driver takes its start time after deleting the old task
// and before making the new one, on the same host clock. gVisor runs under
// either engine and is covered by both. Firecracker, WASM and isolate send
// no exit events (restart_on_failure.go).
//
// The start times live in memory: events are only ever delivered live, and
// the queues do not outlive the daemon, so no event can be older than a
// start the daemon forgot. An event or a start without a time is handled as
// before.
type sandboxRunStarts struct {
	mu      sync.Mutex
	started map[string]time.Time
}

// note records that id's current run started at at. The latest start says
// which run is current, so it replaces any earlier one. A zero at records
// nothing.
func (r *sandboxRunStarts) note(id string, at time.Time) bool {
	if at.IsZero() {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started == nil {
		r.started = make(map[string]time.Time)
	}
	r.started[id] = at
	return true
}

// predates returns id's current run start and whether an event stamped at
// happened before it. Unknown on either side is not before.
func (r *sandboxRunStarts) predates(id string, at time.Time) (time.Time, bool) {
	if at.IsZero() {
		return time.Time{}, false
	}
	r.mu.Lock()
	start, ok := r.started[id]
	r.mu.Unlock()
	return start, ok && at.Before(start)
}

// forget drops id's start time once its row is gone.
func (r *sandboxRunStarts) forget(id string) {
	r.mu.Lock()
	delete(r.started, id)
	r.mu.Unlock()
}

// noteRunStart records the start of id's new run, from the runtime's report.
// A stop's expectation still pending belongs to the run before: the stop
// finished before this start could hold the boundary, and its die, if not
// yet handled, is now ignored as older than this run. Left in place, it
// would take the new run's crash for that stop. Only with a start time: with
// none the old run's die is still handled, and needs its expectation.
func (s *Service) noteRunStart(id string, startedAt time.Time) {
	if s.runStarts.note(id, startedAt) {
		s.consumeExpectedStop(id)
	}
}

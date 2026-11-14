package service

import (
	"sort"
	"sync"
)

// sweepRotation keeps a periodic sweep fair when one pass cannot reach every
// record (review 2 finding 11). The main-program exit probes and the
// lifecycle sweep's stops and deletes both have a deadline per pass. Before,
// each pass walked the same newest-first list, so about 40 agents that never
// answer (3 s each, 8 at a time, in a 10 s budget) used every pass, and the
// older sandboxes behind them were never asked; a delete that kept failing
// slowly did the same to the deletes behind it.
//
// Two rules fix it:
//
//   - Least recently tried first. A pass works its records in the order of
//     the pass that last tried each one, never-tried first, and the caller's
//     order between equals. A record a pass did not reach is ahead of every
//     record that pass did reach, so each record is tried within
//     ceil(records / tries per pass) passes, whatever fails.
//   - Back off on failure. A record whose try failed waits 1, 2, 4, then at
//     most sweepRetryMaxWait passes before the next one, so records that keep
//     failing take a shrinking share of each pass. A success resets it.
//
// A try the pass's own deadline cut short is noted as tried (it rotates to
// the back) but is not a failure: it says nothing about the record.
//
// The state is in memory, one small entry per record that has work, and is
// forgotten when the record has none; a daemon restart only starts every
// record afresh. Not for concurrent passes: each sweep has its own rotation
// and runs its passes one at a time (tries inside a pass may run in
// parallel).
type sweepRotation struct {
	mu      sync.Mutex
	pass    uint64
	records map[string]*sweepRecord
}

type sweepRecord struct {
	lastTried uint64 // the pass that last tried it; 0 = never
	failures  int    // failed tries in a row
	dueAt     uint64 // the first pass that may try it again
}

// sweepRetryMaxWait caps the backoff: a record that keeps failing is still
// tried every 8 passes (8 minutes for the one-minute sweeps).
const sweepRetryMaxWait = 8

// sweepRetryWait is how many passes a record waits after failing its last
// failures tries in a row: 1 (the next pass), 2, 4, then sweepRetryMaxWait.
func sweepRetryWait(failures int) uint64 {
	w := uint64(1)
	for i := 1; i < failures && w < sweepRetryMaxWait; i++ {
		w *= 2
	}
	return min(w, sweepRetryMaxWait)
}

// plan starts a pass. ids are the records with work this pass, in the
// caller's order; plan returns the ones due, least recently tried first, and
// forgets the records that have no work any more. A repeated id counts once.
func (r *sweepRotation) plan(ids []string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pass++
	if r.records == nil {
		r.records = make(map[string]*sweepRecord)
	}
	live := make(map[string]struct{}, len(ids))
	due := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, dup := live[id]; dup {
			continue
		}
		live[id] = struct{}{}
		if rec := r.records[id]; rec != nil && rec.dueAt > r.pass {
			continue
		}
		due = append(due, id)
	}
	for id := range r.records {
		if _, ok := live[id]; !ok {
			delete(r.records, id)
		}
	}
	sort.SliceStable(due, func(i, j int) bool {
		return r.lastTriedLocked(due[i]) < r.lastTriedLocked(due[j])
	})
	return due
}

func (r *sweepRotation) lastTriedLocked(id string) uint64 {
	if rec := r.records[id]; rec != nil {
		return rec.lastTried
	}
	return 0
}

// tried notes that this pass started id's try.
func (r *sweepRotation) tried(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recordLocked(id).lastTried = r.pass
}

// done records how id's try ended: ok resets its backoff, a failure pushes
// its next try back.
func (r *sweepRotation) done(id string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.recordLocked(id)
	if ok {
		rec.failures, rec.dueAt = 0, 0
		return
	}
	rec.failures++
	rec.dueAt = r.pass + sweepRetryWait(rec.failures)
}

func (r *sweepRotation) recordLocked(id string) *sweepRecord {
	if r.records == nil {
		r.records = make(map[string]*sweepRecord)
	}
	rec := r.records[id]
	if rec == nil {
		rec = &sweepRecord{}
		r.records[id] = rec
	}
	return rec
}

package service

import (
	"context"
	"expvar"
	"sync"

	"github.com/aerol-ai/microvm/pkg/docker"
)

// maxQueuedEventsPerSandbox bounds one sandbox's pending runtime events.
// Events queue behind a die, stop or destroy that waits for the sandbox's
// lifecycle boundary, and that wait ends with the step holding it (a runtime
// start, stop or destroy, at most restartStartTimeout). In that time a
// sandbox emits a handful of events: our own starts need the boundary, so
// only out-of-band starts can add new runs, and a run of OOM kills folds into
// one entry. 64 is far above that.
//
// If a sandbox does reach it (out-of-band starts in a loop, say), its oldest
// pending event makes room for the new one: the stream loop never waits for
// one sandbox, so a single busy sandbox cannot hold up every other
// sandbox's events. The newest events say most about where the sandbox is
// now, and reconcile, which reads the runtime itself, covers what a dropped
// event would have said. Each drop is counted in
// aerolvm_sandbox_events_dropped_total and logged.
const maxQueuedEventsPerSandbox = 64

// sandboxEventsDropped counts events dropped from a full per-sandbox queue
// (an entry of folded OOM kills counts each kill).
var sandboxEventsDropped = expvar.NewInt("aerolvm_sandbox_events_dropped_total")

// sandboxEventQueues hands each runtime event to its sandbox's own queue, so
// the one loop that reads the node's event stream never waits for a sandbox
// (review 2 finding 9 follow-up). A die, stop or destroy event waits for the
// sandbox's lifecycle boundary (lifecycle_boundary.go), which a restart or a
// destroy can hold for up to restartStartTimeout. Handled inline, that wait
// held up every other sandbox's events too.
//
// Each sandbox's events run one at a time, in the order the stream gave
// them, on a worker that exists only while the sandbox has events pending.
// Different sandboxes' events run in parallel; none of them needs another's
// order (a stop that clears rules at an address checks who owns it now,
// ipClaimedByOther, because stop events were always allowed to arrive
// late).
//
// The memory is bounded: one queue holds at most limit entries, and
// back-to-back OOM kills of one container fold into one entry that is
// handled once per kill. A full queue drops its oldest pending entry
// (maxQueuedEventsPerSandbox); the stream loop never waits.
//
// The queues live as long as ctx (the event monitor), not one stream, so a
// stream reconnect drops nothing; when ctx ends the workers stop and what is
// left is the next reconcile's.
type sandboxEventQueues struct {
	ctx    context.Context
	handle func(context.Context, docker.DockerEvent)
	limit  int
	// dropped hears about each event a full queue dropped; nil is fine.
	dropped func(docker.DockerEvent, int)

	mu     sync.Mutex
	queues map[string]*sandboxEventQueue
	wg     sync.WaitGroup
}

type sandboxEventQueue struct {
	items []queuedEvent
}

// queuedEvent is one entry: an event, and how many times it came in a row
// (only OOM events fold, each one a separate kill).
type queuedEvent struct {
	event docker.DockerEvent
	times int
}

func newSandboxEventQueues(ctx context.Context, limit int, handle func(context.Context, docker.DockerEvent)) *sandboxEventQueues {
	return &sandboxEventQueues{ctx: ctx, handle: handle, limit: limit, queues: make(map[string]*sandboxEventQueue)}
}

// add queues ev behind its sandbox's earlier events and returns at once. A
// full queue drops its oldest pending entry to make room (the entry a
// worker is handling is no longer in the queue). It returns false, the
// event not queued, only when ctx or the queues' own context has ended.
func (q *sandboxEventQueues) add(ctx context.Context, ev docker.DockerEvent) bool {
	if ctx.Err() != nil || q.ctx.Err() != nil {
		return false
	}
	var dropped *queuedEvent
	q.mu.Lock()
	sq := q.queues[ev.SandboxID]
	if sq == nil {
		sq = &sandboxEventQueue{}
		q.queues[ev.SandboxID] = sq
		q.wg.Add(1)
		// The worker cannot take the queue's lock before this append
		// releases it, so it always finds ev.
		go q.run(ev.SandboxID, sq)
	}
	switch n := len(sq.items); {
	case n > 0 && foldsInto(sq.items[n-1].event, ev):
		sq.items[n-1].times++
	default:
		if n >= q.limit && n > 0 {
			oldest := sq.items[0]
			dropped = &oldest
			sq.items[0] = queuedEvent{}
			sq.items = sq.items[1:]
		}
		sq.items = append(sq.items, queuedEvent{event: ev, times: 1})
	}
	q.mu.Unlock()
	if dropped != nil {
		sandboxEventsDropped.Add(int64(dropped.times))
		if q.dropped != nil {
			q.dropped(dropped.event, dropped.times)
		}
	}
	return true
}

// foldsInto reports whether next can join the pending entry last: OOM kills
// of the same container, back to back. Each is still handled (the entry
// counts them); folding only keeps a burst of kills to one entry.
func foldsInto(last, next docker.DockerEvent) bool {
	return last.Action == "oom" && next.Action == "oom" && last.ContainerID == next.ContainerID
}

// run is one sandbox's worker: it handles the queue's entries in order and
// exits, removing the queue, once it is empty or the queues' context ends.
func (q *sandboxEventQueues) run(id string, sq *sandboxEventQueue) {
	defer q.wg.Done()
	for {
		q.mu.Lock()
		if len(sq.items) == 0 || q.ctx.Err() != nil {
			delete(q.queues, id)
			q.mu.Unlock()
			return
		}
		item := sq.items[0]
		sq.items[0] = queuedEvent{}
		sq.items = sq.items[1:]
		q.mu.Unlock()
		for i := 0; i < item.times && q.ctx.Err() == nil; i++ {
			q.handle(q.ctx, item.event)
		}
	}
}

// wait returns once every queued event has been handled (or dropped because
// the queues' context ended).
func (q *sandboxEventQueues) wait() { q.wg.Wait() }

// pending is the number of entries queued for id (tests).
func (q *sandboxEventQueues) pending(id string) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	if sq := q.queues[id]; sq != nil {
		return len(sq.items)
	}
	return 0
}

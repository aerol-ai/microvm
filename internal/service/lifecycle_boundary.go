package service

import (
	"context"
	"sync"
)

// The lifecycle boundary (review 2 finding 9). Every change to whether one
// sandbox runs happens under one per-sandbox lock, Service.lifecycleLocks:
//
//   - the native start, stop, pause and resume calls, which every facade
//     (Daytona start and stop, E2B pause and connect, Runloop suspend and
//     resume) and the fleet controls go through;
//   - DestroySandbox;
//   - a restart on failure, and a wake by traffic;
//   - the lifecycle sweep's timed stops and deletes, and the disk watchdog's
//     stop;
//   - the die, stop and destroy events, and the restart a crash schedules;
//   - the read-modify-write of the lifecycle timers (D7).
//
// Each step reads the row after it holds the lock and decides from that read,
// so no step acts on a state another one has changed since. A stop that comes
// while a restart on failure is starting the sandbox waits for it and then
// stops it; a restart that comes after a stop finds nothing pending. Before
// this, start, stop and destroy took no lock, so an automatic restart already
// inside the runtime start wrote "started" over a stop that had succeeded.
//
// The public entry points take the lock. The *Locked helpers expect the
// caller to hold it, so a step already inside the boundary (pause calls the
// stop, resume calls the start, the restart calls the start) never takes it
// twice.
//
// Lock order: lifecycleLocks before destroyLocks. DestroySandbox and the
// destroy event both take them in that order.
//
// The lock is one per sandbox, not a shared stripe: a step can hold it across
// a runtime start or stop (seconds, up to restartStartTimeout), and a shared
// stripe would make unrelated sandboxes, and the one goroutine that handles
// runtime events for the whole node, wait for it. Waiting honours ctx, so a
// caller that gives up stops waiting.
type sandboxLocks struct {
	mu    sync.Mutex
	locks map[string]*sandboxLock
}

// sandboxLock is one sandbox's lock: holding it is having the one token in
// held. refs counts the callers holding or waiting for it; the last one out
// removes the map entry, so the map only holds sandboxes with a step in
// flight.
type sandboxLock struct {
	held chan struct{}
	refs int
}

// lock takes id's lock and returns its unlock. A lock that is free is taken
// even when ctx is already done, as before; waiting for a held one ends with
// ctx's error.
func (l *sandboxLocks) lock(ctx context.Context, id string) (func(), error) {
	l.mu.Lock()
	if l.locks == nil {
		l.locks = make(map[string]*sandboxLock)
	}
	e := l.locks[id]
	if e == nil {
		e = &sandboxLock{held: make(chan struct{}, 1)}
		l.locks[id] = e
	}
	e.refs++
	l.mu.Unlock()

	select {
	case e.held <- struct{}{}:
	default:
		select {
		case e.held <- struct{}{}:
		case <-ctx.Done():
			l.release(id, e)
			return nil, ctx.Err()
		}
	}
	return func() {
		<-e.held
		l.release(id, e)
	}, nil
}

func (l *sandboxLocks) release(id string, e *sandboxLock) {
	l.mu.Lock()
	if e.refs--; e.refs == 0 {
		delete(l.locks, id)
	}
	l.mu.Unlock()
}

// size is the number of sandboxes with a step in flight (tests).
func (l *sandboxLocks) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.locks)
}

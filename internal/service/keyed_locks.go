package service

import (
	"context"
	"sync"
)

// keyedLocks is one lock per key K, made on first use and dropped when its
// last holder or waiter leaves, so the map holds only keys with work in
// flight. Unlike the striped egressPolicyLocks, two keys never wait on each
// other, which matters when a holder can wait on a runtime for seconds (a
// start, a resize). The zero value is ready to use.
//
// It is the one copy of this pattern: the port route and allowlist locks
// (route_gate.go), the expose lock (lockExposedPort), the resize and spec
// locks, and the lifecycle lock (lifecycle_boundary.go) each had their own
// before, with small differences nobody chose.
type keyedLocks[K comparable] struct {
	mu sync.Mutex
	m  map[K]*keyedLock
}

type keyedLock struct {
	// sem holds one token while the lock is held; a channel rather than a
	// mutex so a waiter can give up when its caller does.
	sem  chan struct{}
	refs int
}

func (l *keyedLocks[K]) enter(k K) *keyedLock {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = make(map[K]*keyedLock)
	}
	e := l.m[k]
	if e == nil {
		e = &keyedLock{sem: make(chan struct{}, 1)}
		l.m[k] = e
	}
	e.refs++
	return e
}

func (l *keyedLocks[K]) leave(k K, e *keyedLock) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.refs--; e.refs == 0 {
		delete(l.m, k)
	}
}

func (l *keyedLocks[K]) unlockFunc(k K, e *keyedLock) func() {
	return func() {
		<-e.sem
		l.leave(k, e)
	}
}

// lock takes k's lock, waiting as long as it takes, and returns its unlock.
func (l *keyedLocks[K]) lock(k K) func() {
	e := l.enter(k)
	e.sem <- struct{}{}
	return l.unlockFunc(k, e)
}

// lockCtx takes k's lock and returns its unlock, or ctx's error if ctx ends
// while it waits. A free lock is taken even when ctx has already ended (the
// lifecycle steps rely on that); a caller that must not start once its own
// caller left checks ctx.Err() first.
func (l *keyedLocks[K]) lockCtx(ctx context.Context, k K) (func(), error) {
	e := l.enter(k)
	select {
	case e.sem <- struct{}{}:
	default:
		select {
		case e.sem <- struct{}{}:
		case <-ctx.Done():
			l.leave(k, e)
			return nil, ctx.Err()
		}
	}
	return l.unlockFunc(k, e), nil
}

// refs is the number of calls holding or waiting for k's lock, and keys the
// number of keys with any. Tests only.
func (l *keyedLocks[K]) refs(k K) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.m[k]; e != nil {
		return e.refs
	}
	return 0
}

func (l *keyedLocks[K]) keys() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}

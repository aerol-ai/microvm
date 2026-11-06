package service

import (
	"context"
	"sync"
)

// ctxKeyedLocks is one lock per key, which a waiter can give up on when
// its context ends (route_gate.go's keyedLocks cannot) (a sandbox id), made on first use and
// dropped when its last holder or waiter leaves. Unlike the striped
// egressPolicyLocks, two keys never wait on each other, which matters when a
// holder can wait on a runtime for seconds (a resize). Memory follows the
// keys in use, not every key ever seen.
type ctxKeyedLocks struct {
	mu    sync.Mutex
	locks map[string]*ctxKeyedLock
}

type ctxKeyedLock struct {
	// sem holds one token while the lock is held; a channel rather than a
	// mutex so a waiter can give up when its caller does.
	sem  chan struct{}
	refs int
}

// lock takes key's lock, or returns ctx's error if ctx ends first. The
// returned func releases it and must be called exactly once.
func (l *ctxKeyedLocks) lock(ctx context.Context, key string) (func(), error) {
	// A caller that has already left takes nothing, even from a free lock
	// (select would pick between the two at random).
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.locks == nil {
		l.locks = make(map[string]*ctxKeyedLock)
	}
	k := l.locks[key]
	if k == nil {
		k = &ctxKeyedLock{sem: make(chan struct{}, 1)}
		l.locks[key] = k
	}
	k.refs++
	l.mu.Unlock()
	select {
	case k.sem <- struct{}{}:
		return func() {
			<-k.sem
			l.leave(key, k)
		}, nil
	case <-ctx.Done():
		l.leave(key, k)
		return nil, ctx.Err()
	}
}

func (l *ctxKeyedLocks) leave(key string, k *ctxKeyedLock) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k.refs--
	if k.refs == 0 {
		delete(l.locks, key)
	}
}

// waiters reports how many callers hold or wait for key's lock.
func (l *ctxKeyedLocks) waiters(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if k := l.locks[key]; k != nil {
		return k.refs
	}
	return 0
}

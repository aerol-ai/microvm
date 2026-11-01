package cluster

import (
	"fmt"
	"sync"
)

// freshFlight coalesces concurrent identical reads without ever answering a
// caller with data older than its own request.
//
// singleflight would hand a caller the result of a call that was already in
// flight when it arrived — a call that may have started before the caller's
// own create committed, so a list right after a create could miss the new
// sandbox. freshFlight instead lets a caller join only a call that has not
// started yet: while a call runs, every caller that arrives waits for it to
// end and then shares the NEXT call, which starts after all of them arrived.
// So each answer comes from a read that began after the request did, exactly
// as without coalescing, and per key there is at most one call running and
// one queued behind it, however many callers there are.
//
// The cost to a caller is at most the rest of the running call plus its own;
// the saving under a storm is everything else: on the bank flagship 512
// concurrent lists on one ingress made 512 concurrent control-plane reads,
// and the mTLS handshakes they cost starved the node.
type freshFlight[V any] struct {
	mu    sync.Mutex
	calls map[string]*freshCall[V]
}

type freshCall[V any] struct {
	fn   func() (V, error)
	done chan struct{}
	val  V
	err  error
	// next is the call the callers who arrived while this one ran share.
	// It starts when this one ends.
	next *freshCall[V]
	// waiters counts the callers queued on this call (guarded by the
	// group's mu).
	waiters int
}

// do returns fn's result from a call that started no earlier than this
// request. shared reports whether the call served other callers too. fn
// must not depend on the caller (its context, its identity): any one
// waiting caller's fn may run on behalf of all of them.
func (g *freshFlight[V]) do(key string, fn func() (V, error)) (v V, err error, shared bool) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[string]*freshCall[V])
	}
	running, ok := g.calls[key]
	if !ok {
		c := &freshCall[V]{fn: fn, done: make(chan struct{})}
		g.calls[key] = c
		g.mu.Unlock()
		g.run(key, c)
		return c.val, c.err, false
	}
	// The running call started before this request: queue for the next.
	if running.next == nil {
		running.next = &freshCall[V]{fn: fn, done: make(chan struct{})}
	}
	next := running.next
	next.waiters++
	g.mu.Unlock()
	<-next.done
	return next.val, next.err, true
}

// run executes c, then starts the call queued behind it (on its own
// goroutine, so c's caller gets its answer without waiting for that one).
func (g *freshFlight[V]) run(key string, c *freshCall[V]) {
	defer func() {
		if r := recover(); r != nil {
			// A panic must not strand the callers waiting on c, nor the
			// ones queued behind it.
			var zero V
			c.val, c.err = zero, fmt.Errorf("cluster: coalesced read panicked: %v", r)
		}
		g.mu.Lock()
		next := c.next
		if next != nil {
			g.calls[key] = next
		} else {
			delete(g.calls, key)
		}
		g.mu.Unlock()
		close(c.done)
		if next != nil {
			go g.run(key, next)
		}
	}()
	c.val, c.err = c.fn()
}

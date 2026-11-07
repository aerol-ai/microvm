package dockerpool

import (
	"context"
	"expvar"
	"sort"
	"sync"
	"time"
)

// Parked containers whose teardown failed.
//
// A slot leaves its ready queue before its container is destroyed: an entry
// deleted, a depth lowered, an image replaced, a target reaped or evicted, a
// dead or stale slot pruned, a slot reclaimed. A failed DestroyParked used
// to be ignored and the park reservation released anyway, so the container
// lived on with no record in the pool and no charge in the admitter. The
// runtime reconcile skips parked containers, so only a daemon restart's
// boot purge ever found it.
//
// Now a failed teardown keeps the slot in p.pending, still charged, and the
// refill tick retries it with backoff until the engine confirms the
// container is gone: DestroyParked returns nil, and both engines return nil
// for a container that is already absent. Only then is the reservation
// released. A restart drops the list; the boot purge covers that case, as
// it always has.
//
// A retry passes a copy of the slot marked TeardownRetry, without its handle
// (the first attempt closed it). What the address keys depends on who owns
// the address. Docker frees it with the container, so the docker engine
// clears the address's rules before the removal, on the first attempt only:
// on a retry the container may already be gone and the address another
// container's. containerd's address belongs to the netns slot, so it clears
// the rules and frees the slot only after the container is confirmed gone,
// and the retry needs the address for that.

const (
	// parkDestroyTimeout bounds one engine teardown call, so a hung engine
	// cannot hold the refill tick (or a create's Acquire) forever.
	parkDestroyTimeout = 30 * time.Second
	// pendingDestroyFirstRetry is the first retry delay (the default refill
	// interval); each later failure doubles it up to pendingDestroyMaxDelay.
	pendingDestroyFirstRetry = 5 * time.Second
	pendingDestroyMaxDelay   = 5 * time.Minute
)

// pendingDestroy is one parked container whose teardown has not been
// confirmed yet.
type pendingDestroy struct {
	key  string
	slot *ParkedSlot
	// release frees the slot's park reservation once the container is gone.
	// Nil when the reservation was already released (Reclaim must release
	// before it returns, so the create that asked can use the room).
	release func(slotID string)
	since   time.Time
	next    time.Time
	tries   int
	lastErr string
}

// pendingDestroyDelay is the wait after the n-th failed attempt.
func pendingDestroyDelay(tries int) time.Duration {
	d := pendingDestroyFirstRetry
	for i := 1; i < tries && d < pendingDestroyMaxDelay; i++ {
		d *= 2
	}
	if d > pendingDestroyMaxDelay {
		d = pendingDestroyMaxDelay
	}
	return d
}

// destroyBounded runs one teardown under parkDestroyTimeout.
func destroyBounded(ctx context.Context, spawner Spawner, slot *ParkedSlot) error {
	dctx, cancel := context.WithTimeout(ctx, parkDestroyTimeout)
	defer cancel()
	return spawner.DestroyParked(dctx, slot)
}

// destroySlot tears down one slot that already left its ready queue. On
// success it releases the park reservation through release (nil: nothing to
// release); on failure it keeps the slot for retry, still charged.
func (p *Pool) destroySlot(ctx context.Context, spawner Spawner, slot *ParkedSlot, release func(string)) {
	if slot == nil {
		return
	}
	if spawner == nil {
		// No engine was ever wired, so no container exists to leak.
		if release != nil {
			release(slot.ID)
		}
		return
	}
	if err := destroyBounded(ctx, spawner, slot); err != nil {
		p.retainFailedDestroy(slot, release, err)
		return
	}
	if release != nil {
		release(slot.ID)
	}
}

// retainFailedDestroy records a teardown that failed.
func (p *Pool) retainFailedDestroy(slot *ParkedSlot, release func(string), err error) {
	key := slot.ID
	if key == "" {
		key = slot.ContainerID
	}
	now := p.clock()
	e := &pendingDestroy{
		key:     key,
		slot:    &ParkedSlot{ID: slot.ID, ContainerID: slot.ContainerID, ContainerIP: slot.ContainerIP, ImageID: slot.ImageID, Key: slot.Key, TeardownRetry: true},
		release: release,
		since:   now,
		next:    now.Add(pendingDestroyDelay(1)),
		tries:   1,
		lastErr: err.Error(),
	}
	p.mu.Lock()
	if p.pending == nil {
		p.pending = make(map[string]*pendingDestroy)
	}
	if old, ok := p.pending[key]; ok {
		// The same container failed again on another path: keep its age.
		e.since, e.tries = old.since, old.tries+1
		e.next = now.Add(pendingDestroyDelay(e.tries))
		if e.release == nil {
			e.release = old.release
		}
	}
	p.pending[key] = e
	p.publishPendingLocked()
	p.mu.Unlock()
	if p.metrics != nil {
		p.metrics.recordDestroyFail()
	}
	// The slot is out of its ready queue, so no create can reclaim it: stop
	// offering its room as reclaimable. The reservation itself stays, since
	// the container still runs.
	p.notifyParkReady(slot.ID, false)
	p.logger.Warn("warm pool: parked container teardown failed; kept and retried until it is gone",
		"slot_id", slot.ID, "container_id", slot.ContainerID, "key", slot.Key.KeyString(), "error", err)
}

// retryPendingDestroys retries every kept teardown whose delay has passed
// (all of them when force is set). The refill tick calls it before it parks
// anything, so a container that is finally gone frees its reservation for
// this tick's parks.
func (p *Pool) retryPendingDestroys(ctx context.Context, force bool) {
	spawner := p.currentSpawner()
	if spawner == nil {
		return
	}
	now := p.clock()
	p.mu.Lock()
	due := make([]*pendingDestroy, 0, len(p.pending))
	for _, e := range p.pending {
		if force || !e.next.After(now) {
			due = append(due, e)
		}
	}
	p.mu.Unlock()
	sort.Slice(due, func(i, j int) bool { return due[i].since.Before(due[j].since) })
	for _, e := range due {
		err := destroyBounded(ctx, spawner, e.slot)
		gone := false
		p.mu.Lock()
		if cur, ok := p.pending[e.key]; ok && cur == e {
			if err == nil {
				delete(p.pending, e.key)
				gone = true
			} else {
				e.tries++
				e.next = p.clock().Add(pendingDestroyDelay(e.tries))
				e.lastErr = err.Error()
			}
			p.publishPendingLocked()
		}
		p.mu.Unlock()
		if err != nil {
			if p.metrics != nil {
				p.metrics.recordDestroyFail()
			}
			p.logger.Warn("warm pool: parked container teardown retry failed",
				"slot_id", e.slot.ID, "container_id", e.slot.ContainerID, "tries", e.tries, "error", err)
			continue
		}
		if gone && e.release != nil {
			e.release(e.slot.ID)
		}
	}
}

// PendingDestroys reports how many parked containers this pool still has to
// tear down and how long the oldest has waited.
func (p *Pool) PendingDestroys() (int, time.Duration) {
	if p == nil {
		return 0, 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	n, oldest := p.pendingStatLocked()
	if n == 0 {
		return 0, 0
	}
	return n, p.clock().Sub(oldest)
}

func (p *Pool) pendingStatLocked() (int, time.Time) {
	var oldest time.Time
	for _, e := range p.pending {
		if oldest.IsZero() || e.since.Before(oldest) {
			oldest = e.since
		}
	}
	return len(p.pending), oldest
}

// publishPendingLocked updates this pool's share of the process-wide pending
// gauges. A host can run a docker pool and a containerd pool at once; both
// gauges sum (or take the oldest) across them.
func (p *Pool) publishPendingLocked() {
	n, oldest := p.pendingStatLocked()
	pendingGauges.set(p, n, oldest)
}

// pendingRegistry holds each pool's pending count and oldest entry, only
// while it has any, for the expvar gauges below.
type pendingRegistry struct {
	mu    sync.Mutex
	pools map[*Pool]pendingStat
}

type pendingStat struct {
	n      int
	oldest time.Time
}

var pendingGauges = &pendingRegistry{pools: make(map[*Pool]pendingStat)}

func (r *pendingRegistry) set(p *Pool, n int, oldest time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n == 0 {
		delete(r.pools, p)
		return
	}
	r.pools[p] = pendingStat{n: n, oldest: oldest}
}

// totals returns the pending count summed over pools and the age of the
// oldest entry in any of them.
func (r *pendingRegistry) totals(now time.Time) (int, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	var oldest time.Time
	for _, st := range r.pools {
		n += st.n
		if oldest.IsZero() || st.oldest.Before(oldest) {
			oldest = st.oldest
		}
	}
	if n == 0 {
		return 0, 0
	}
	return n, now.Sub(oldest)
}

func init() {
	// aerolvm_docker_pool_pending_destroys: parked containers kept for a
	// retried teardown. aerolvm_docker_pool_pending_destroy_oldest_seconds:
	// how long the oldest of them has waited. Both stay 0 on a healthy host;
	// a rising age means the engine keeps refusing a removal.
	expvar.Publish("aerolvm_docker_pool_pending_destroys", expvar.Func(func() any {
		n, _ := pendingGauges.totals(time.Now())
		return n
	}))
	expvar.Publish("aerolvm_docker_pool_pending_destroy_oldest_seconds", expvar.Func(func() any {
		_, age := pendingGauges.totals(time.Now())
		return age.Seconds()
	}))
}

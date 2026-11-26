package kubepod

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
)

// One watch per worker (plans/security-gaps-m1-m4.md §6.2, M4 PR 2). The
// driver lists this worker's pods once, then watches them from the list's
// resource version, and keeps what it saw in a podCache. While that watch
// is open (live), reads and waits use the cache, so a sandbox costs the API
// server nothing between its create and its delete: no read per Inspect,
// no polling while a create or stop waits. While it is not (before the
// first list, or while it reconnects), every read goes to the API server,
// exactly as without a watch, so a stale view is never taken for the truth.
//
// The same stream gives the service its exit and start events
// (events.go), as containerd's task events do.

const (
	// goneKeep is how long a deleted pod's UID is remembered, so a create
	// waiting for its pod can tell "deleted before the watch showed it"
	// from "not shown yet".
	goneKeep = 10 * time.Minute
	// eventBuffer is how many events one StreamEvents caller may fall
	// behind before the oldest are dropped. The service reads them into
	// queues of its own at once.
	eventBuffer = 1024
	// The wait before a list or watch is tried again after an error
	// (Driver.retryMin and retryMax, which tests shrink).
	watchRetryMin = 200 * time.Millisecond
	watchRetryMax = 30 * time.Second
	// shortWatch: a watch the server ends this soon with no event is an
	// error (Driver.shortWatch).
	shortWatch = time.Second
	// ExitLost is the exit code a sandbox gets when its pod goes away with
	// no end seen (removed by force, or its node lost): the kubelet's own
	// code for a container it cannot find (ContainerStatusUnknown). Never 0:
	// the service reads 0 as "the program exited", and restart-on-failure
	// would not restart a sandbox that was lost.
	ExitLost = 137
)

// errShortWatch is a watch the server ended at once with no event.
var errShortWatch = errors.New("kubepod: the pod watch ended at once with no events")

// podCache is the watch's view of this worker's pods. Each pod in it is
// the object one event carried and is never changed after it is stored,
// so readers may keep it.
type podCache struct {
	mu   sync.Mutex
	pods map[string]*Pod // by name
	// runs is what the events said of each pod, by UID: whether its
	// sandbox container was seen running and seen ended.
	runs map[string]*podRun
	gone map[string]time.Time // UIDs of deleted pods
	rv   string
	// synced is true once a list filled the view; live while a watch from
	// rv is open.
	synced, live bool
	// changed is closed, and replaced, on every change: waiters take it
	// before they read and wake when anything moved.
	changed chan struct{}
	subs    map[int]chan docker.DockerEvent
	nextSub int
	dropped uint64
	now     func() time.Time
}

type podRun struct {
	started, ended bool
}

func newPodCache() *podCache {
	return &podCache{
		pods:    map[string]*Pod{},
		runs:    map[string]*podRun{},
		gone:    map[string]time.Time{},
		changed: make(chan struct{}),
		subs:    map[int]chan docker.DockerEvent{},
		now:     time.Now,
	}
}

func (c *podCache) notifyLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

// changes returns the channel the next change closes and whether the view
// is live. Take it before reading, so a change between the read and the
// wait still wakes the waiter.
func (c *podCache) changes() (<-chan struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.changed, c.live
}

func (c *podCache) setLive(live bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.live = live && c.synced
	c.notifyLocked()
}

// lookup returns the pod of name. live is false when the view cannot
// answer and the caller must ask the API server.
func (c *podCache) lookup(name string) (p *Pod, found, live bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.live {
		return nil, false, false
	}
	p, found = c.pods[name]
	return p, found, true
}

// all returns every pod in the view, when it is live.
func (c *podCache) all() ([]*Pod, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.live {
		return nil, false
	}
	out := make([]*Pod, 0, len(c.pods))
	for _, p := range c.pods {
		out = append(out, p)
	}
	return out, true
}

// deleted reports whether the watch saw the pod with this UID deleted.
func (c *podCache) deleted(uid string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.gone[uid]
	return ok
}

func (c *podCache) version() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rv
}

// replace fills the view from a list read at rv. After the first list,
// what changed since the last view becomes events, as if it had been
// watched: a pod that ended or went away while no watch was open still
// reports its exit.
func (c *podCache) replace(pods []Pod, rv string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	first := !c.synced
	next := make(map[string]*Pod, len(pods))
	for i := range pods {
		p := pods[i]
		next[p.Metadata.Name] = &p
		c.observeLocked(&p, !first)
	}
	for name, old := range c.pods {
		if now, ok := next[name]; !ok || now.Metadata.UID != old.Metadata.UID {
			c.removedLocked(old)
		}
	}
	c.pods, c.rv, c.synced = next, rv, true
	c.notifyLocked()
}

// apply takes one watch event into the view.
func (c *podCache) apply(ev WatchEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := ev.Object
	switch ev.Type {
	case "ADDED", "MODIFIED":
		if old, ok := c.pods[p.Metadata.Name]; ok && old.Metadata.UID != p.Metadata.UID {
			c.removedLocked(old)
		}
		c.pods[p.Metadata.Name] = &p
		c.observeLocked(&p, true)
	case "DELETED":
		if old, ok := c.pods[p.Metadata.Name]; ok && old.Metadata.UID == p.Metadata.UID {
			delete(c.pods, p.Metadata.Name)
		}
		c.removedLocked(&p)
	case "BOOKMARK":
	default:
		return fmt.Errorf("kubepod: watch event of unknown type %q", ev.Type)
	}
	if v := p.Metadata.ResourceVersion; v != "" {
		c.rv = v
	}
	c.notifyLocked()
	return nil
}

// observeLocked records what p says of its run and, with emit, publishes
// the start and exit it shows for the first time.
func (c *podCache) observeLocked(p *Pod, emit bool) {
	run := c.runs[p.Metadata.UID]
	if run == nil {
		run = &podRun{}
		c.runs[p.Metadata.UID] = run
	}
	cs := sandboxStatus(p)
	if cs == nil {
		return
	}
	if r := cs.State.Running; r != nil && !run.started {
		run.started = true
		if emit {
			c.publishLocked(eventOf(p, "start", 0, r.StartedAt))
		}
	}
	if t := cs.State.Terminated; t != nil && !run.ended {
		run.started, run.ended = true, true
		if emit {
			if t.Reason == "OOMKilled" {
				c.publishLocked(eventOf(p, "oom", 0, t.FinishedAt))
			}
			c.publishLocked(eventOf(p, "die", int(t.ExitCode), t.FinishedAt))
		}
	}
}

// removedLocked records that p is gone. A sandbox seen running whose exit
// was never seen (a pod removed by force, or on a node that went away)
// exits now, with ExitLost, at the time its deletion was asked for.
func (c *podCache) removedLocked(p *Pod) {
	uid := p.Metadata.UID
	if run := c.runs[uid]; run != nil && run.started && !run.ended {
		c.publishLocked(eventOf(p, "die", ExitLost, p.Metadata.DeletionTimestamp))
	}
	delete(c.runs, uid)
	now := c.now()
	for old, at := range c.gone {
		if now.Sub(at) > goneKeep {
			delete(c.gone, old)
		}
	}
	c.gone[uid] = now
}

// sandboxStatus is the sandbox container's status, or nil before the
// kubelet reports one.
func sandboxStatus(p *Pod) *ContainerStatus {
	if p.Status == nil {
		return nil
	}
	for i := range p.Status.ContainerStatuses {
		if p.Status.ContainerStatuses[i].Name == sandboxContainer {
			return &p.Status.ContainerStatuses[i]
		}
	}
	return nil
}

func eventOf(p *Pod, action string, exit int, at *time.Time) docker.DockerEvent {
	ev := docker.DockerEvent{ContainerID: p.Metadata.Name, SandboxID: sandboxIDOf(p), Action: action, ExitCode: exit}
	if at != nil {
		ev.Time = *at
	}
	return ev
}

// RunWatch keeps the driver's view of this worker's pods until ctx ends:
// one list, then one watch from its version, resumed from the last version
// seen whenever it ends, and a new list when the API server no longer has
// that version. Errors are retried with backoff; meanwhile reads go to the
// API server. Call it once, in a goroutine of its own.
func (d *Driver) RunWatch(ctx context.Context) {
	defer d.cache.setLive(false)
	retry := d.retryMin
	relist := true
	for ctx.Err() == nil {
		if relist {
			pods, rv, err := d.client.ListPods(ctx, d.cfg.Namespace, d.selector())
			if err != nil {
				d.logger.Warn("kubepod: listing this worker's pods failed; reads go to the API server until it works", "error", err)
				retry = d.retryAfter(ctx, retry)
				continue
			}
			d.cache.replace(pods, rv)
			relist = false
		}
		delivered := false
		began := time.Now()
		// The view goes live only once the server has answered the watch:
		// while a new watch is still being opened (it may hang until its
		// header timeout), reads go to the API server, never to a view
		// that stopped changing when the last watch failed.
		err := d.client.WatchPods(ctx, d.cfg.Namespace, d.selector(), d.cache.version(),
			func() { d.cache.setLive(true) },
			func(ev WatchEvent) error {
				delivered = true
				return d.cache.apply(ev)
			})
		d.cache.setLive(false)
		switch {
		case ctx.Err() != nil:
			return
		case isGone(err):
			// The version is too old to resume from: list again.
			relist = true
			retry = d.retryAfter(ctx, d.retryMin)
			continue
		case err == nil && (delivered || time.Since(began) >= d.shortWatch):
			// The server's own end of a watch: resume at once.
			retry = d.retryMin
			continue
		case err == nil:
			// Ended at once, with nothing in it. As client-go does, that
			// counts as an error and backs off: a server that ends every
			// watch at once would otherwise get thousands of requests a
			// second.
			err = errShortWatch
		}
		if delivered {
			retry = d.retryMin
		}
		if code, _ := apiCode(err); code == http.StatusForbidden || code == http.StatusUnauthorized {
			d.logger.Error("kubepod: this worker may not watch pods in the sandbox namespace; check its Role", "error", err)
		} else {
			d.logger.Warn("kubepod: pod watch ended; resuming", "error", err)
		}
		retry = d.retryAfter(ctx, retry)
	}
}

// retryAfter waits wait (or until ctx ends) and returns the next, longer
// wait.
func (d *Driver) retryAfter(ctx context.Context, wait time.Duration) time.Duration {
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
	return min(wait*2, d.retryMax)
}

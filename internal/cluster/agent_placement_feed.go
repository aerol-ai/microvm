package cluster

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Agent half of the placement delta feed (plans/ingress-proxy-routing.md
// §3.4, task T2). With SB_INGRESS_PROXY_ROUTING on, an ingress Agent keeps
// the whole placement view current from the server's change log instead of
// re-walking /internal/placements/page every 5s:
//
//	not synced ──▶ changes?since=0 (resnapshot, Next=V0) ──▶ page-walk ALL ──▶ cursor=V0, synced
//	synced ────▶ changes?since=cursor&wait=W ──▶ apply (merge by Version) ──▶ cursor=Next ──▶ signal
//	           └─ resnapshot ──▶ not synced
//
// Pages are not a consistent snapshot: each is read under its own lock. A
// row seen in the walk may already be older than a change the feed then
// replays, and vice versa. Every merge therefore keeps the row with the
// higher Placement.Version, and a delete removes a row only if the row is
// not newer than the delete's index, which makes replay idempotent.
//
// With the flag off, none of this runs: PlacementsForShards keeps its page
// walk and SubscribePlacement returns nil, exactly as before.

type agentPlacementFeed struct {
	mu     sync.RWMutex
	rows   map[string]Placement
	synced bool
	cursor uint64

	subMu       sync.Mutex
	subs        []chan struct{}
	watchers    map[int]PlacementChangeHandler
	nextWatcher int

	stop context.CancelFunc
	done chan struct{}
}

// feedBackoff bounds retries after a failed poll or walk.
var (
	feedBackoffMin = 500 * time.Millisecond
	feedBackoffMax = 30 * time.Second
)

// startPlacementFeed launches the feed when the node routes without
// per-sandbox Caddy writes. It is idempotent.
func (a *Agent) startPlacementFeed() {
	if a == nil || !a.cfg.IngressProxyRouting || a.feed != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.feed = &agentPlacementFeed{rows: make(map[string]Placement), stop: cancel, done: make(chan struct{})}
	go a.runPlacementFeed(ctx, a.feed)
}

func (a *Agent) stopPlacementFeed() {
	if a == nil || a.feed == nil {
		return
	}
	a.feed.stop()
	<-a.feed.done
}

func (a *Agent) runPlacementFeed(ctx context.Context, f *agentPlacementFeed) {
	defer close(f.done)
	backoff := feedBackoffMin
	sleep := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, feedBackoffMax)
		return true
	}
	for ctx.Err() == nil {
		f.mu.RLock()
		synced, cursor := f.synced, f.cursor
		f.mu.RUnlock()
		if !synced {
			if err := a.resyncPlacementFeed(ctx, f); err != nil {
				if isStatus(err, http.StatusNotFound) || isStatus(err, http.StatusMethodNotAllowed) {
					a.logger.Warn("cluster agent: control plane has no placement change feed; staying on the page walk", "err", err)
					return
				}
				a.logger.Warn("cluster agent: placement feed resync failed", "err", err)
				if !sleep() {
					return
				}
				continue
			}
			backoff = feedBackoffMin
			continue
		}
		resp, err := a.pollPlacementChanges(ctx, cursor)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.logger.Warn("cluster agent: placement feed poll failed", "err", err, "since", cursor)
			if !sleep() {
				return
			}
			continue
		}
		backoff = feedBackoffMin
		if resp.Resnapshot {
			f.mu.Lock()
			f.synced = false
			f.mu.Unlock()
			continue
		}
		if a.applyPlacementChanges(f, resp) {
			f.notifyWatchers(nil, resp.Changes)
			f.signal()
		}
	}
}

// resyncPlacementFeed takes a fresh view: record the server's version V0,
// walk every page, then resume the feed from V0. Rows changed during the
// walk are replayed by the feed and merged by Version.
func (a *Agent) resyncPlacementFeed(ctx context.Context, f *agentPlacementFeed) error {
	head, err := a.fetchPlacementChanges(ctx, 0, 0)
	if err != nil {
		return err
	}
	v0 := head.Next
	walked, err := a.fetchPlacementPages(PlacementShardFilter{})
	if err != nil {
		return err
	}
	f.mu.Lock()
	next := make(map[string]Placement, len(walked))
	for _, p := range walked {
		if cur, ok := next[p.SandboxID]; !ok || p.Version >= cur.Version {
			next[p.SandboxID] = p
		}
	}
	f.rows = next
	f.cursor = v0
	f.synced = true
	full := make([]Placement, 0, len(next))
	for _, p := range next {
		full = append(full, p)
	}
	f.mu.Unlock()
	a.observePlacementVersions(walked)
	f.notifyWatchers(full, nil)
	f.signal()
	return nil
}

// feedWait asks the server to park for a little less than this agent's own
// HTTP client timeout, so a parked poll is never cut off client-side.
func (a *Agent) feedWait() time.Duration {
	wait := MaxPlacementChangesWait
	if a.internalClient != nil && a.internalClient.Timeout > 0 {
		wait = min(wait, a.internalClient.Timeout-2*time.Second)
	}
	return max(wait, time.Second)
}

func (a *Agent) pollPlacementChanges(ctx context.Context, since uint64) (PlacementChangesResponse, error) {
	return a.fetchPlacementChanges(ctx, since, a.feedWait())
}

func (a *Agent) fetchPlacementChanges(ctx context.Context, since uint64, wait time.Duration) (PlacementChangesResponse, error) {
	path := fmt.Sprintf("%s?since=%d&wait=%s", PublicInternalPlacementChangesPath, since, wait)
	reqCtx, cancel := context.WithTimeout(ctx, wait+controlPlanePlacementRequestTimeout)
	defer cancel()
	var resp PlacementChangesResponse
	if err := a.doControlPlaneJSON(reqCtx, http.MethodGet, path, path, nil, &resp); err != nil {
		return PlacementChangesResponse{}, err
	}
	return resp, nil
}

// applyPlacementChanges merges one delta and reports whether anything
// changed. Merge rule: keep the higher Version. A delete removes the row
// only if the row is not newer than the delete (a delete older than a
// re-create cannot remove it).
func (a *Agent) applyPlacementChanges(f *agentPlacementFeed, resp PlacementChangesResponse) bool {
	changed := false
	var seen []Placement
	f.mu.Lock()
	for _, ch := range resp.Changes {
		cur, ok := f.rows[ch.SandboxID]
		switch {
		case ch.Deleted:
			if ok && cur.Version <= ch.Index {
				delete(f.rows, ch.SandboxID)
				changed = true
			}
		case ch.Placement != nil:
			if !ok || ch.Placement.Version >= cur.Version {
				f.rows[ch.SandboxID] = *ch.Placement
				seen = append(seen, *ch.Placement)
				changed = true
			}
		}
	}
	if resp.Next > f.cursor {
		f.cursor = resp.Next
	}
	f.mu.Unlock()
	a.observePlacementVersions(seen)
	return changed
}

// feedPlacements answers PlacementsForShards from the synced view: no
// control-plane read at all. ok=false means "not synced, use the page walk".
func (a *Agent) feedPlacements(filter PlacementShardFilter) ([]Placement, bool) {
	if a == nil || a.feed == nil {
		return nil, false
	}
	f := a.feed
	f.mu.RLock()
	defer f.mu.RUnlock()
	if !f.synced {
		return nil, false
	}
	filter = filter.Normalize()
	want := make(map[int]struct{}, len(filter.Shards))
	for _, s := range filter.Shards {
		want[s] = struct{}{}
	}
	all := filter.allShards()
	out := make([]Placement, 0, len(f.rows))
	for id, p := range f.rows {
		if !all {
			if _, ok := want[PlacementShardForSandbox(id, filter.ShardCount)]; !ok {
				continue
			}
		}
		out = append(out, p)
	}
	return clonePlacements(out), true
}

// subscribe registers a cap-1 wake channel, coalescing like the FSM's
// subscribers: "more than one change since the last wake" is still just
// "wake up".
func (f *agentPlacementFeed) subscribe(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{}, 1)
	f.subMu.Lock()
	f.subs = append(f.subs, ch)
	f.subMu.Unlock()
	go func() {
		<-ctx.Done()
		f.subMu.Lock()
		defer f.subMu.Unlock()
		for i, c := range f.subs {
			if c == ch {
				f.subs = append(f.subs[:i], f.subs[i+1:]...)
				return
			}
		}
	}()
	return ch
}

func (f *agentPlacementFeed) signal() {
	f.subMu.Lock()
	subs := append([]chan struct{}(nil), f.subs...)
	f.subMu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// PlacementChangeHandler receives placement changes in order. full is
// non-nil after a (re)sync and is then the COMPLETE view; changes follow
// incrementally. Handlers must not block for long.
type PlacementChangeHandler func(full []Placement, changes []PlacementChange)

// PlacementChangeWatcher streams placement changes to a consumer that keeps
// its own index (the ingress route responder). It is implemented by the
// Agent (from its delta feed) and by a server Cluster (from its own change
// log, in-process).
type PlacementChangeWatcher interface {
	WatchPlacementChanges(ctx context.Context, fn PlacementChangeHandler) bool
}

// WatchPlacementChanges registers fn with the delta feed. It returns false
// when the feed is off (flag off). fn first gets the current full view, if
// already synced.
func (a *Agent) WatchPlacementChanges(ctx context.Context, fn PlacementChangeHandler) bool {
	if a == nil || a.feed == nil || fn == nil {
		return false
	}
	f := a.feed
	f.subMu.Lock()
	id := f.nextWatcher
	f.nextWatcher++
	if f.watchers == nil {
		f.watchers = map[int]PlacementChangeHandler{}
	}
	f.watchers[id] = fn
	f.subMu.Unlock()
	if rows, ok := a.feedPlacements(PlacementShardFilter{}); ok {
		fn(rows, nil)
	}
	go func() {
		<-ctx.Done()
		f.subMu.Lock()
		delete(f.watchers, id)
		f.subMu.Unlock()
	}()
	return true
}

func (f *agentPlacementFeed) notifyWatchers(full []Placement, changes []PlacementChange) {
	f.subMu.Lock()
	ws := make([]PlacementChangeHandler, 0, len(f.watchers))
	for _, w := range f.watchers {
		ws = append(ws, w)
	}
	f.subMu.Unlock()
	for _, w := range ws {
		w(full, changes)
	}
}

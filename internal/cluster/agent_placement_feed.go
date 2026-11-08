package cluster

import (
	"context"
	"expvar"
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
//
// Age limit (plan C4 part 3, invariant I7). The rows are only as fresh as the
// last poll the control plane answered. An ingress cut off from every server
// used to keep routing by them for as long as the cut lasted, and so kept
// sending traffic to an owner the leader may have replaced. Once maxStale
// (OwnershipLease: half the dead-owner grace) passes without an answered poll
// or resync, the feed hands every failover.policy=recreate row out in flux:
// the same row, with the owner's addresses blanked (staleViewPlacement). Both
// ingress routers already read a row with no owner address as in flux and
// answer 503 + Retry-After (routedns.addPlacementHosts,
// service.buildClusterIngressIntents). Every other row keeps its route: the
// leader orphans such a sandbox when its owner dies and never starts a second
// copy, so its owner is the only place it can run, and an outage of the whole
// server tier does not take it offline. The next answered poll hands the real
// rows back.
//
//	fresh ──(no answered poll for maxStale)──▶ in flux: watchers get a full view with recreate rows in flux
//	in flux ──(an answered poll or resync)──▶ fresh: watchers get the real full view

type agentPlacementFeed struct {
	mu     sync.RWMutex
	rows   map[string]Placement
	synced bool
	cursor uint64

	// lastAnswered is when the control plane last answered a poll or a
	// resync. maxStale is the age past which the rows are handed out in flux;
	// zero turns the limit off (a feed built without one, in tests).
	lastAnswered time.Time
	maxStale     time.Duration
	// inFluxSent says watchers were last given the all-in-flux view, so the
	// watchdog sends it once and the next answered poll knows to send the
	// real view back. Guarded by mu.
	inFluxSent bool
	// transitionMu orders the full views watchers receive: a view is built
	// and delivered under it, so a late in-flux view can never land after the
	// real view that replaced it (or the other way round).
	transitionMu sync.Mutex
	// clock is time.Now except in tests.
	clock func() time.Time

	subMu       sync.Mutex
	subs        []chan struct{}
	watchers    map[int]PlacementChangeHandler
	nextWatcher int

	stop context.CancelFunc
	done chan struct{}
}

// clusterPlacementFeedInFlux is 1 while this ingress hands out every
// recreate-policy route in flux because the control plane has not answered
// its feed within the age limit.
var clusterPlacementFeedInFlux = expvar.NewInt("aerolvm_cluster_placement_feed_in_flux")

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
	a.feed = &agentPlacementFeed{
		rows:     make(map[string]Placement),
		maxStale: OwnershipLease(a.cfg),
		stop:     cancel,
		done:     make(chan struct{}),
	}
	go a.watchPlacementFeedAge(ctx, a.feed)
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
	// Retries keep several attempts inside one age window, so a control plane
	// that comes back is noticed within a quarter of the window rather than
	// after a 30s backoff that would leave every route in flux meanwhile.
	maxBackoff := feedBackoffMax
	if f.maxStale > 0 {
		maxBackoff = max(min(maxBackoff, f.maxStale/4), feedBackoffMin)
	}
	sleep := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
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
		// While the rows are past the age limit, ask without parking: the
		// first answer ends the in-flux period, and a parked poll would
		// keep every route at 503 for up to one more wait.
		var resp PlacementChangesResponse
		var err error
		if f.isStale() {
			resp, err = a.fetchPlacementChanges(ctx, cursor, 0)
		} else {
			resp, err = a.pollPlacementChanges(ctx, cursor)
		}
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
		f.transitionMu.Lock()
		changed := a.applyPlacementChanges(f, resp)
		if full, wasInFlux := f.markAnswered(); wasInFlux {
			// Watchers hold the all-in-flux view: the deltas alone would
			// leave every untouched row in flux, so they get the whole real
			// view (which already includes these changes).
			f.notifyWatchers(full, nil)
			f.signal()
			a.logger.Info("cluster agent: placement feed answered again; routing by the real view")
		} else if changed {
			f.notifyWatchers(nil, resp.Changes)
			f.signal()
		}
		f.transitionMu.Unlock()
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
	f.transitionMu.Lock()
	defer f.transitionMu.Unlock()
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
	f.lastAnswered = f.now()
	if f.inFluxSent {
		// The full view below replaces the all-in-flux one watchers hold.
		f.inFluxSent = false
		clusterPlacementFeedInFlux.Set(0)
	}
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
// HTTP client timeout, so a parked poll is never cut off client-side, and for
// at most a third of the age limit, so a healthy but quiet feed is answered
// several times per window and never ages into in flux between two polls.
func (a *Agent) feedWait() time.Duration {
	wait := MaxPlacementChangesWait
	if a.internalClient != nil && a.internalClient.Timeout > 0 {
		wait = min(wait, a.internalClient.Timeout-2*time.Second)
	}
	if a.feed != nil && a.feed.maxStale > 0 {
		wait = min(wait, a.feed.maxStale/3)
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
// Past the age limit every recreate-policy row comes back in flux
// (staleViewPlacement); the page walk is not a way out, since its own cache
// is older still.
func (a *Agent) feedPlacements(filter PlacementShardFilter) ([]Placement, bool) {
	if a == nil || a.feed == nil {
		return nil, false
	}
	f := a.feed
	f.mu.RLock()
	defer f.mu.RUnlock()
	stale := f.staleLocked(f.now())
	if !f.synced && !stale {
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
		if stale {
			p = staleViewPlacement(p)
		}
		out = append(out, p)
	}
	return clonePlacements(out), true
}

// inFluxPlacement is p with the owner's addresses blanked: what the two
// ingress routers read as "owner unknown right now" and answer with 503 +
// Retry-After. The owner id and the rest of the row stay, so the sandbox
// reads as in flux, not as orphaned (410) or unknown (404).
func inFluxPlacement(p Placement) Placement {
	p.OwnerAPIURL = ""
	p.OwnerDataPlaneHost = ""
	return p
}

// staleViewPlacement is how a row goes out once the view is past the age
// limit: in flux if the leader may have moved it (placementMovableOnFailover),
// unchanged otherwise.
func staleViewPlacement(p Placement) Placement {
	if placementMovableOnFailover(p) {
		return inFluxPlacement(p)
	}
	return p
}

func (f *agentPlacementFeed) now() time.Time {
	if f.clock != nil {
		return f.clock()
	}
	return time.Now()
}

// staleLocked reports whether the rows are past the age limit. A feed that
// has never been answered holds no rows and is not stale: the page walk
// serves it. A feed waiting to resync (after a resnapshot) still holds its
// last rows and ages like any other, since the page-walk cache it would fall
// back to is older still. The caller holds mu.
func (f *agentPlacementFeed) staleLocked(now time.Time) bool {
	return f.maxStale > 0 && !f.lastAnswered.IsZero() && now.Sub(f.lastAnswered) > f.maxStale
}

// isStale is staleLocked at the current time, under mu.
func (f *agentPlacementFeed) isStale() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.staleLocked(f.now())
}

// markAnswered records an answered poll. When watchers were holding the
// all-in-flux view it returns the real full view to send them instead. The
// caller holds transitionMu.
func (f *agentPlacementFeed) markAnswered() (full []Placement, wasInFlux bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAnswered = f.now()
	if !f.inFluxSent {
		return nil, false
	}
	f.inFluxSent = false
	clusterPlacementFeedInFlux.Set(0)
	full = make([]Placement, 0, len(f.rows))
	for _, p := range f.rows {
		full = append(full, p)
	}
	return clonePlacements(full), true
}

// checkPlacementFeedAge hands watchers the stale view (recreate-policy rows in
// flux) once the rows pass the age limit, and wakes the ingress reconciler so
// it re-reads them too. It reports whether it made that transition.
func (a *Agent) checkPlacementFeedAge(f *agentPlacementFeed) bool {
	f.transitionMu.Lock()
	defer f.transitionMu.Unlock()
	f.mu.Lock()
	now := f.now()
	if f.inFluxSent || !f.staleLocked(now) {
		f.mu.Unlock()
		return false
	}
	f.inFluxSent = true
	age := now.Sub(f.lastAnswered)
	full := make([]Placement, 0, len(f.rows))
	inFlux := 0
	for _, p := range f.rows {
		if placementMovableOnFailover(p) {
			inFlux++
		}
		full = append(full, staleViewPlacement(p))
	}
	f.mu.Unlock()
	clusterPlacementFeedInFlux.Set(1)
	if a.logger != nil {
		a.logger.Warn("cluster agent: placement feed has had no answer from the control plane past its age limit; failover.policy=recreate sandbox routes are in flux (503) until it answers",
			"since_last_answer", age.Round(time.Millisecond), "age_limit", f.maxStale, "placements", len(full), "in_flux", inFlux)
	}
	f.notifyWatchers(clonePlacements(full), nil)
	f.signal()
	return true
}

// watchPlacementFeedAge runs checkPlacementFeedAge a few times per age
// window. The poll loop cannot do it: it can sit inside one poll for longer
// than the window.
func (a *Agent) watchPlacementFeedAge(ctx context.Context, f *agentPlacementFeed) {
	if f.maxStale <= 0 {
		return
	}
	t := time.NewTicker(max(f.maxStale/10, 50*time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.checkPlacementFeedAge(f)
		}
	}
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
	// Under transitionMu so a fresh or in-flux transition cannot deliver its
	// view to fn before this older initial view does.
	f.transitionMu.Lock()
	if rows, ok := a.feedPlacements(PlacementShardFilter{}); ok {
		fn(rows, nil)
	}
	f.transitionMu.Unlock()
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

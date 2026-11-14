package cluster

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// routable reports whether a placement still names an owner address a
// router could send traffic to. Both ingress routers treat a row with no
// owner address as in flux and answer 503: routedns.addPlacementHosts
// (OwnerDataPlaneHost empty) and service.buildClusterIngressIntents (no
// data-plane host and no API host).
func routable(p Placement) bool {
	return p.OwnerDataPlaneHost != "" || p.OwnerAPIURL != ""
}

func ownerHosts(rows []Placement) map[string]string {
	out := make(map[string]string, len(rows))
	for _, p := range rows {
		out[p.SandboxID] = p.OwnerDataPlaneHost
	}
	return out
}

func placeAt(id, owner, host string) command {
	return command{Op: opPlace, SandboxID: id, OwnerNodeID: owner, OwnerAPIURL: "http://" + host + ":8080", OwnerDataPlaneHost: host, IncarnationID: "inc-" + id}
}

// placeRecreateAt is placeAt for a failover.policy=recreate sandbox: the only
// kind the leader may move, so the only kind the age limit puts in flux.
func placeRecreateAt(id, owner, host string) command {
	cmd := placeAt(id, owner, host)
	cmd.Spec = recreateSpec()
	return cmd
}

// staleShape reports whether rows are sb1 (recreate policy) in flux and sb2
// (no policy) still routed: what a view past the age limit must look like.
func staleShape(rows []Placement) bool {
	if len(rows) != 2 {
		return false
	}
	for _, p := range rows {
		if routable(p) != (p.SandboxID == "sb2") {
			return false
		}
	}
	return true
}

func rowByID(rows []Placement, id string) (Placement, bool) {
	for _, p := range rows {
		if p.SandboxID == id {
			return p, true
		}
	}
	return Placement{}, false
}

// TestAgentPlacementFeedMarksRecreateEntriesInFluxWhenPollsStop is the I7
// regression for the ingress data path. An ingress on the cut-off side of a
// partition kept routing by the last rows its feed received, with no age
// limit, so it sent traffic to an owner the leader may since have replaced.
// After the lease (half the dead-owner grace) without a successful poll,
// every failover.policy=recreate entry must be handed out in flux. Every other
// entry keeps its route for the whole outage: the leader cannot move it, so
// its owner is still the only copy. Once polls succeed again the real view
// comes back.
func TestAgentPlacementFeedMarksRecreateEntriesInFluxWhenPollsStop(t *testing.T) {
	oldMin := feedBackoffMin
	feedBackoffMin = 20 * time.Millisecond
	defer func() { feedBackoffMin = oldMin }()

	srv, cleanup := newTestCluster(t, "srv-feed-stale", true, nil)
	defer cleanup()
	waitForLeader(t, srv, 10*time.Second)
	ctx := context.Background()
	for _, cmd := range []command{placeRecreateAt("sb1", "w1", "10.0.0.1"), placeAt("sb2", "w2", "10.0.0.2")} {
		if err := srv.applyCommand(ctx, cmd); err != nil {
			t.Fatal(err)
		}
	}

	var offline atomic.Bool
	agent := newAgentControlPlaneHarness(t, feedControlPlane(srv, nil, &offline), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
	agent.cfg.IngressProxyRouting = true
	// A 1s grace makes the lease 500ms, so the test runs in about a second.
	agent.cfg.ClusterDeadOwnerGrace = time.Second
	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	agent.startPlacementFeed()
	defer agent.stopPlacementFeed()

	var mu sync.Mutex
	var lastFull []Placement
	agent.WatchPlacementChanges(watchCtx, func(full []Placement, _ []PlacementChange) {
		if full == nil {
			return
		}
		mu.Lock()
		lastFull = clonePlacements(full)
		mu.Unlock()
	})
	watcherView := func() []Placement {
		mu.Lock()
		defer mu.Unlock()
		return clonePlacements(lastFull)
	}
	allRoutable := func(rows []Placement, want bool) bool {
		if len(rows) != 2 {
			return false
		}
		for _, p := range rows {
			if routable(p) != want {
				return false
			}
		}
		return true
	}
	waitForFeed(t, "the synced feed to route both sandboxes", func() bool {
		rows, ok := agent.feedPlacements(PlacementShardFilter{})
		return ok && allRoutable(rows, true) && allRoutable(watcherView(), true)
	})

	// The control plane stops answering: every poll fails from now on.
	offline.Store(true)
	cutOff := time.Now()
	deadline := cutOff.Add(5 * time.Second)
	for {
		rows := agent.PlacementsForShards(PlacementShardFilter{})
		if p, ok := rowByID(rows, "sb2"); !ok || !routable(p) {
			t.Fatalf("the sandbox with no recreate policy lost its route during the outage: %v", ownerHosts(rows))
		}
		if staleShape(rows) && staleShape(watcherView()) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s after the last successful poll the feed still routes by its old rows (PlacementsForShards %v, watcher %v); want the recreate-policy entry in flux after the 500ms lease and the other routed",
				time.Since(cutOff).Round(time.Millisecond), ownerHosts(rows), ownerHosts(watcherView()))
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The lease runs from the last poll the control plane answered, which
	// can come a little before cutOff. Measured from cutOff, a busy runner
	// saw a correct feed go in flux at 497.6ms and failed it.
	agent.feed.mu.RLock()
	lastAnswered := agent.feed.lastAnswered
	agent.feed.mu.RUnlock()
	if got := time.Since(lastAnswered); got < 500*time.Millisecond {
		t.Fatalf("entries went in flux %s after the last answered poll, before the 500ms lease ran out", got)
	}
	t.Logf("recreate-policy entry in flux %s after the control plane stopped answering (lease 500ms)", time.Since(cutOff).Round(10*time.Millisecond))
	// In flux, not gone: the rows stay (with their owner), so a router answers
	// 503 + Retry-After rather than 404.
	for _, p := range agent.PlacementsForShards(PlacementShardFilter{}) {
		if p.OwnerNodeID == "" {
			t.Fatalf("in-flux row %s lost its owner; it must read as in flux, not orphaned", p.SandboxID)
		}
	}

	// Polls succeed again: the real view comes back to both consumers.
	offline.Store(false)
	back := time.Now()
	waitForFeed(t, "the real view after polls succeed again", func() bool {
		return allRoutable(agent.PlacementsForShards(PlacementShardFilter{}), true) && allRoutable(watcherView(), true)
	})
	t.Logf("real view back %s after the control plane answered again", time.Since(back).Round(10*time.Millisecond))
}

// fakeFeedClock is a settable clock for the age rule.
type fakeFeedClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeFeedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeFeedClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// TestPlacementFeedAgeRule walks the age rule on a fake clock: fresh inside
// the limit, in flux (once, to watchers and to PlacementsForShards) past it,
// fresh again on the next answered poll, and the stored rows are never
// rewritten in the process.
func TestPlacementFeedAgeRule(t *testing.T) {
	clock := &fakeFeedClock{now: time.Unix(1_000, 0)}
	f := &agentPlacementFeed{
		rows: map[string]Placement{
			"sb1": {SandboxID: "sb1", OwnerNodeID: "w1", OwnerAPIURL: "http://10.0.0.1:8080", OwnerDataPlaneHost: "10.0.0.1", FailoverRecreate: true},
			"sb2": {SandboxID: "sb2", OwnerNodeID: "w2", OwnerAPIURL: "http://10.0.0.2:8080", OwnerDataPlaneHost: "10.0.0.2"},
		},
		synced:       true,
		lastAnswered: clock.Now(),
		maxStale:     15 * time.Second,
		clock:        clock.Now,
	}
	agent := &Agent{feed: f}
	var views [][]Placement
	f.watchers = map[int]PlacementChangeHandler{0: func(full []Placement, _ []PlacementChange) {
		if full != nil {
			views = append(views, full)
		}
	}}
	wake := make(chan struct{}, 1)
	f.subs = []chan struct{}{wake}

	clock.advance(15 * time.Second) // exactly at the limit: still fresh
	if agent.checkPlacementFeedAge(f) {
		t.Fatal("feed went in flux at exactly the age limit")
	}
	if rows, _ := agent.feedPlacements(PlacementShardFilter{}); !allRoutableRows(rows) {
		t.Fatal("rows in flux at exactly the age limit")
	}

	clock.advance(time.Millisecond)
	if !agent.checkPlacementFeedAge(f) {
		t.Fatal("feed did not go in flux past the age limit")
	}
	if agent.checkPlacementFeedAge(f) {
		t.Fatal("the in-flux view was sent twice")
	}
	if len(views) != 1 || !staleShape(views[0]) {
		t.Fatalf("watcher views = %+v, want one view with the recreate-policy row in flux and the other routed", views)
	}
	if p, _ := rowByID(views[0], "sb1"); p.OwnerNodeID != "w1" {
		t.Fatalf("in-flux row lost its owner id: %+v", p)
	}
	select {
	case <-wake:
	default:
		t.Fatal("going in flux did not wake the ingress reconciler")
	}
	if got := clusterPlacementFeedInFlux.Value(); got != 1 {
		t.Fatalf("in-flux gauge = %d, want 1", got)
	}
	rows, ok := agent.feedPlacements(PlacementShardFilter{})
	if !ok || !staleShape(rows) {
		t.Fatalf("PlacementsForShards = %+v ok=%v, want the recreate-policy row in flux and the other routed", rows, ok)
	}
	if !routable(f.rows["sb1"]) {
		t.Fatal("the stored row was rewritten; only the copies handed out may be in flux")
	}

	full, wasInFlux := f.markAnswered()
	if !wasInFlux || len(full) != 2 || !allRoutableRows(full) {
		t.Fatalf("markAnswered = %+v, %v; want the real view back", full, wasInFlux)
	}
	if got := clusterPlacementFeedInFlux.Value(); got != 0 {
		t.Fatalf("in-flux gauge = %d after an answer, want 0", got)
	}
	if rows, _ := agent.feedPlacements(PlacementShardFilter{}); !allRoutableRows(rows) {
		t.Fatal("rows still in flux after an answered poll")
	}
	if _, again := f.markAnswered(); again {
		t.Fatal("a second answer re-sent the real view")
	}
}

// A feed waiting to resync after a resnapshot still holds its last rows and
// ages like any other; a feed never answered holds nothing and is left to the
// page walk; a zero limit turns the rule off.
func TestPlacementFeedAgeEdges(t *testing.T) {
	clock := &fakeFeedClock{now: time.Unix(2_000, 0)}
	row := Placement{SandboxID: "sb1", OwnerNodeID: "w1", OwnerDataPlaneHost: "10.0.0.1", FailoverRecreate: true}

	resyncing := &agentPlacementFeed{rows: map[string]Placement{"sb1": row}, lastAnswered: clock.Now(), maxStale: time.Second, clock: clock.Now}
	never := &agentPlacementFeed{rows: map[string]Placement{}, maxStale: time.Second, clock: clock.Now}
	off := &agentPlacementFeed{rows: map[string]Placement{"sb1": row}, synced: true, lastAnswered: clock.Now(), clock: clock.Now}
	clock.advance(time.Hour)

	if rows, ok := (&Agent{feed: resyncing}).feedPlacements(PlacementShardFilter{}); !ok || len(rows) != 1 || routable(rows[0]) {
		t.Fatalf("resyncing feed past the limit = %+v ok=%v, want its last rows in flux", rows, ok)
	}
	if _, ok := (&Agent{feed: never}).feedPlacements(PlacementShardFilter{}); ok {
		t.Fatal("a never-answered feed claimed a view; the page walk must serve it")
	}
	if (&Agent{feed: never}).checkPlacementFeedAge(never) {
		t.Fatal("a never-answered feed went in flux")
	}
	if rows, ok := (&Agent{feed: off}).feedPlacements(PlacementShardFilter{}); !ok || !routable(rows[0]) {
		t.Fatal("a feed with no age limit put its rows in flux")
	}
}

// The long-poll wait and the retry backoff fit inside the age window, so a
// healthy quiet feed is answered several times per window and a control plane
// that comes back is noticed within a quarter of it.
func TestPlacementFeedPollingFitsTheAgeLimit(t *testing.T) {
	agent := &Agent{cfg: config.Config{ClusterDeadOwnerGrace: 30 * time.Second}}
	agent.feed = &agentPlacementFeed{maxStale: OwnershipLease(agent.cfg)}
	if agent.feed.maxStale != 15*time.Second {
		t.Fatalf("age limit = %s, want 15s (half the 30s grace)", agent.feed.maxStale)
	}
	if got := agent.feedWait(); got != 5*time.Second {
		t.Fatalf("feedWait = %s, want 5s (a third of the age limit)", got)
	}
	agent.feed.maxStale = 0
	if got := agent.feedWait(); got != MaxPlacementChangesWait {
		t.Fatalf("feedWait without an age limit = %s, want %s", got, MaxPlacementChangesWait)
	}
}

// TestAgentPageWalkMarksRecreateEntriesInFluxWhenTheControlPlaneStops is the I7
// regression for an ingress WITHOUT SB_INGRESS_PROXY_ROUTING, which was the
// default then and is what the live cluster-chaos scenario pins (UC-470,
// 2026-11-08; default_ingress_proxy_routing = false in its tfvars).
// That ingress has no feed: PlacementsForShards walks the pages, and when
// the walk fails it falls back to the rows of the last walk that worked,
// with no age limit. A cut-off ingress therefore kept its SNI route to the
// old owner; the owner had paused the sandbox (C4 part 1), and the paused
// process took the connection but never answered, so the probe hung until
// its 10 s timeout instead of getting a quick 503. After the lease without
// an answered walk, the cached recreate-policy rows must come back in flux;
// every other row keeps its route for the whole outage (the leader cannot
// move it), and the real rows come back on the next walk that works.
func TestAgentPageWalkMarksRecreateEntriesInFluxWhenTheControlPlaneStops(t *testing.T) {
	srv, cleanup := newTestCluster(t, "srv-walk-stale", true, nil)
	defer cleanup()
	waitForLeader(t, srv, 10*time.Second)
	ctx := context.Background()
	for _, cmd := range []command{placeRecreateAt("sb1", "w1", "10.0.0.1"), placeAt("sb2", "w2", "10.0.0.2")} {
		if err := srv.applyCommand(ctx, cmd); err != nil {
			t.Fatal(err)
		}
	}

	var offline atomic.Bool
	agent := newAgentControlPlaneHarness(t, feedControlPlane(srv, nil, &offline), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
	// No IngressProxyRouting: no feed, the page walk serves every read.
	// A 1s grace makes the lease 500ms.
	agent.cfg.ClusterDeadOwnerGrace = time.Second
	allRoutable := func(rows []Placement, want bool) bool {
		if len(rows) != 2 {
			return false
		}
		for _, p := range rows {
			if routable(p) != want {
				return false
			}
		}
		return true
	}
	// The lease runs from the start of the last answered walk.
	lastWalk := time.Now()
	if rows := agent.PlacementsForShards(PlacementShardFilter{}); !allRoutable(rows, true) {
		t.Fatalf("the first walk = %v, want both sandboxes routed", ownerHosts(rows))
	}

	// The control plane stops answering: every walk fails from now on.
	offline.Store(true)
	cutOff := time.Now()
	if rows := agent.PlacementsForShards(PlacementShardFilter{}); !allRoutable(rows, true) {
		t.Fatalf("one failed walk inside the lease = %v, want the cached rows still routed", ownerHosts(rows))
	}
	deadline := cutOff.Add(5 * time.Second)
	for {
		rows := agent.PlacementsForShards(PlacementShardFilter{})
		if p, ok := rowByID(rows, "sb2"); !ok || !routable(p) {
			t.Fatalf("the sandbox with no recreate policy lost its route during the outage: %v", ownerHosts(rows))
		}
		if staleShape(rows) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s after the last answered walk the ingress still routes by its cached rows %v; want the recreate-policy entry in flux after the 500ms lease and the other routed",
				time.Since(cutOff).Round(time.Millisecond), ownerHosts(rows))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := time.Since(lastWalk); got < 500*time.Millisecond {
		t.Fatalf("entries went in flux %s after the last answered walk began, before the 500ms lease ran out", got)
	}
	// In flux, not gone and not orphaned: the owner id stays, so the router
	// answers 503 + Retry-After rather than 404 or 410.
	for _, p := range agent.PlacementsForShards(PlacementShardFilter{}) {
		if p.OwnerNodeID == "" {
			t.Fatalf("in-flux row %s lost its owner; it must read as in flux, not orphaned", p.SandboxID)
		}
	}
	// Only the copies handed out are in flux: the cache keeps the real rows.
	if cached := agent.cachedPlacementsForShards(PlacementShardFilter{}); !allRoutable(cached, true) {
		t.Fatalf("the cached rows were rewritten: %v", ownerHosts(cached))
	}

	// The control plane answers again: the next walk routes by the real rows.
	offline.Store(false)
	if rows := agent.PlacementsForShards(PlacementShardFilter{}); !allRoutable(rows, true) {
		t.Fatalf("the first answered walk = %v, want both sandboxes routed again", ownerHosts(rows))
	}
}

func allRoutableRows(rows []Placement) bool {
	for _, p := range rows {
		if !routable(p) {
			return false
		}
	}
	return len(rows) > 0
}

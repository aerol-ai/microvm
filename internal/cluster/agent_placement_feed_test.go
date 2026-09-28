package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// feedControlPlane serves the two endpoints the feed uses from a real server
// Cluster, standing in for pkg/api/v1 (which this package can't import).
func feedControlPlane(c *Cluster, disableChanges *bool, offline ...*atomic.Bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(offline) > 0 && offline[0].Load() {
			http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case PublicInternalPlacementsPagePath:
			var req PlacementPageRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(c.PlacementPage(req))
		case PublicInternalPlacementChangesPath:
			if disableChanges != nil && *disableChanges {
				http.NotFound(w, r) // an older server build
				return
			}
			since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
			wait, _ := time.ParseDuration(r.URL.Query().Get("wait"))
			resp := c.PlacementChanges(r.Context(), since, wait)
			// A poll parked before the switch went offline must not deliver
			// either: re-check after it returns.
			if len(offline) > 0 && offline[0].Load() {
				http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	})
}

func feedIDs(a *Agent) map[string]bool {
	out := map[string]bool{}
	for _, p := range a.PlacementsForShards(PlacementShardFilter{}) {
		out[p.SandboxID] = true
	}
	return out
}

func waitForFeed(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestAgentPlacementFeedTracksTheServer(t *testing.T) {
	oldMin := feedBackoffMin
	feedBackoffMin = 20 * time.Millisecond
	defer func() { feedBackoffMin = oldMin }()

	srv, cleanup := newTestCluster(t, "srv-feed-agent", true, nil)
	defer cleanup()
	waitForLeader(t, srv, 10*time.Second)
	ctx := context.Background()
	if err := srv.applyCommand(ctx, place("sb1", "w1")); err != nil {
		t.Fatal(err)
	}

	var offline atomic.Bool
	agent := newAgentControlPlaneHarness(t, feedControlPlane(srv, nil, &offline), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
	agent.cfg.IngressProxyRouting = true
	subCtx, cancelSub := context.WithCancel(ctx)
	defer cancelSub()
	agent.startPlacementFeed()
	defer agent.stopPlacementFeed()
	wake := agent.SubscribePlacement(subCtx)
	if wake == nil {
		t.Fatal("SubscribePlacement is nil with the feed on")
	}

	var watchMu sync.Mutex
	var sawFull, sawDelta bool
	if !agent.WatchPlacementChanges(subCtx, func(full []Placement, changes []PlacementChange) {
		watchMu.Lock()
		defer watchMu.Unlock()
		if full != nil {
			sawFull = true
		}
		if len(changes) > 0 {
			sawDelta = true
		}
	}) {
		t.Fatal("agent watcher refused with the feed on")
	}
	waitForFeed(t, "initial resync to include sb1", func() bool {
		_, ok := agent.feedPlacements(PlacementShardFilter{})
		return ok && feedIDs(agent)["sb1"]
	})

	// A new placement arrives through the feed, not a page walk.
	if err := srv.applyCommand(ctx, place("sb2", "w1")); err != nil {
		t.Fatal(err)
	}
	waitForFeed(t, "sb2 via the delta feed", func() bool { return feedIDs(agent)["sb2"] })
	waitForFeed(t, "watcher saw a full view and a delta", func() bool {
		watchMu.Lock()
		defer watchMu.Unlock()
		return sawFull && sawDelta
	})
	select {
	case <-wake:
	case <-time.After(5 * time.Second):
		t.Fatal("SubscribePlacement never woke for a new placement")
	}

	// A delete propagates.
	if err := srv.applyCommand(ctx, command{Op: opDelete, SandboxID: "sb1", ExpectedIncarnationID: "inc-sb1"}); err != nil {
		t.Fatal(err)
	}
	waitForFeed(t, "sb1 deleted via the feed", func() bool { return !feedIDs(agent)["sb1"] })

	// The server's log loses coverage of the agent's cursor: with the agent
	// cut off, two applies into a 1-entry log evict sb3 past the cursor. On
	// reconnect the only way to learn sb3 is a resnapshot.
	offline.Store(true)
	srv.fsm.mu.Lock()
	srv.fsm.changes = newPlacementChangeLog(1)
	srv.fsm.changes.reset(srv.fsm.version)
	srv.fsm.mu.Unlock()
	if err := srv.applyCommand(ctx, place("sb3", "w1")); err != nil {
		t.Fatal(err)
	}
	if err := srv.applyCommand(ctx, place("sb4", "w1")); err != nil {
		t.Fatal(err)
	}
	offline.Store(false)
	waitForFeed(t, "sb3 and sb4 after a forced resnapshot", func() bool {
		ids := feedIDs(agent)
		return ids["sb3"] && ids["sb4"] && ids["sb2"] && !ids["sb1"]
	})

	// Shard filters are served from the same view.
	shard := PlacementShardForSandbox("sb2", DefaultPlacementShardCount)
	got := agent.PlacementsForShards(PlacementShardFilter{Shards: []int{shard}})
	if len(got) == 0 || got[0].SandboxID != "sb2" {
		t.Fatalf("shard-filtered read = %v, want sb2's shard only", got)
	}
}

// An older server without the endpoint: the feed stops and the agent stays
// on the page walk.
func TestAgentPlacementFeedFallsBackWithoutServerSupport(t *testing.T) {
	oldMin := feedBackoffMin
	feedBackoffMin = 20 * time.Millisecond
	defer func() { feedBackoffMin = oldMin }()

	srv, cleanup := newTestCluster(t, "srv-feed-old", true, nil)
	defer cleanup()
	waitForLeader(t, srv, 10*time.Second)
	if err := srv.applyCommand(context.Background(), place("sb1", "w1")); err != nil {
		t.Fatal(err)
	}
	disabled := true
	agent := newAgentControlPlaneHarness(t, feedControlPlane(srv, &disabled), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
	agent.cfg.IngressProxyRouting = true
	agent.startPlacementFeed()
	select {
	case <-agent.feed.done:
	case <-time.After(5 * time.Second):
		t.Fatal("feed kept running against a server without the endpoint")
	}
	if _, ok := agent.feedPlacements(PlacementShardFilter{}); ok {
		t.Fatal("feed claims to be synced after the server refused it")
	}
	if !feedIDs(agent)["sb1"] {
		t.Fatal("page-walk fallback did not return sb1")
	}
	agent.stopPlacementFeed() // idempotent after exit
}

// With the flag off nothing changes: no feed, nil subscription.
func TestAgentPlacementFeedOffByDefault(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.NotFoundHandler())
	agent.startPlacementFeed()
	if agent.feed != nil {
		t.Fatal("feed started without SB_INGRESS_PROXY_ROUTING")
	}
	if agent.SubscribePlacement(context.Background()) != nil {
		t.Fatal("SubscribePlacement must stay nil with the flag off")
	}
	if agent.WatchPlacementChanges(context.Background(), func([]Placement, []PlacementChange) {}) {
		t.Fatal("WatchPlacementChanges must refuse with the flag off")
	}
	agent.stopPlacementFeed()
}

// Merge rules: the higher Version wins, and a delete older than a re-create
// doesn't remove it.
func TestAgentApplyPlacementChangesMergeRules(t *testing.T) {
	agent := &Agent{}
	f := &agentPlacementFeed{rows: map[string]Placement{"sb": {SandboxID: "sb", Version: 10}}}
	if agent.applyPlacementChanges(f, PlacementChangesResponse{Next: 11, Changes: []PlacementChange{
		{Index: 5, SandboxID: "sb", Placement: &Placement{SandboxID: "sb", Version: 5}},
	}}) {
		t.Fatal("an older version replaced a newer row")
	}
	if agent.applyPlacementChanges(f, PlacementChangesResponse{Next: 12, Changes: []PlacementChange{
		{Index: 9, SandboxID: "sb", Deleted: true},
	}}) || f.rows["sb"].Version != 10 {
		t.Fatal("a delete older than the row removed it")
	}
	if !agent.applyPlacementChanges(f, PlacementChangesResponse{Next: 13, Changes: []PlacementChange{
		{Index: 12, SandboxID: "sb", Deleted: true},
	}}) || len(f.rows) != 0 {
		t.Fatal("a newer delete did not remove the row")
	}
	if f.cursor != 13 {
		t.Fatalf("cursor = %d, want 13", f.cursor)
	}
}

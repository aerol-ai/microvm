package cluster

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// An ingress tier at or below MaxReplicatedIngressRouteNodes asks with an
// all-shards filter, so the unfiltered read DOES have a production caller. A
// minimal 100k-placement answer encodes past the agent's JSON response
// ceiling, and the failure returned an empty fallback view on a cold agent —
// which a reconcile pass would read as "no routes anywhere". Page instead.
func TestAgentPlacementsForShardsPagesInsteadOfOneUnboundedRead(t *testing.T) {
	const total = 3*MaxPlacementPageLimit + 11
	unfilteredReads := 0
	pageReads := 0
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case PublicInternalPlacementsPath, PublicInternalPlacementsQueryPath:
			unfilteredReads++
			http.Error(w, "unbounded placement read", http.StatusInternalServerError)
		case PublicInternalPlacementsPagePath:
			pageReads++
			var req PlacementPageRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode page request: %v", err)
				http.Error(w, "bad", http.StatusBadRequest)
				return
			}
			if req.Limit > MaxPlacementPageLimit {
				t.Errorf("page limit %d exceeds %d", req.Limit, MaxPlacementPageLimit)
			}
			start := 0
			if req.PageToken != "" {
				if _, err := fmt.Sscanf(req.PageToken, "sb-%06d", &start); err != nil {
					t.Errorf("page token %q: %v", req.PageToken, err)
				}
				start++
			}
			end := min(start+req.Limit, total)
			resp := PlacementPageResponse{Authoritative: true}
			for i := start; i < end; i++ {
				resp.Placements = append(resp.Placements, Placement{SandboxID: fmt.Sprintf("sb-%06d", i), Version: 1})
			}
			if end < total {
				resp.NextPageToken = fmt.Sprintf("sb-%06d", end-1)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleIngress})

	got := agent.PlacementsForShards(PlacementShardFilter{})
	if len(got) != total {
		t.Fatalf("PlacementsForShards returned %d placements, want %d", len(got), total)
	}
	if unfilteredReads != 0 {
		t.Fatalf("made %d unbounded placement reads; the whole point is that every response stays inside the size ceiling", unfilteredReads)
	}
	if pageReads != 4 {
		t.Fatalf("made %d page reads for %d placements, want 4", pageReads, total)
	}
}

// A node that serves no ingress has no public-route work, so it must make no
// control-plane read at all — not an all-shards one.
func TestAgentPlacementsForShardsSkipsReadWhenNoShards(t *testing.T) {
	reads := 0
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reads++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PlacementPageResponse{Authoritative: true})
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if got := agent.PlacementsForShards(NoPlacementShards()); got != nil {
		t.Fatalf("no-shard filter returned %d placements, want none", len(got))
	}
	if reads != 0 {
		t.Fatalf("no-shard filter still made %d control-plane reads", reads)
	}
}

// The fallback shard cache is keyed by filter and used only when the control
// plane is unreachable. Retaining one full cloned placement slice per
// historical ingress ring is a leak, not a cache.
func TestAgentShardCacheRetiresSupersededGenerations(t *testing.T) {
	a := &Agent{}
	a.cacheMu.Lock()
	for i := range 100 {
		a.storeShardCacheLocked(fmt.Sprintf("16384:%d", i), []Placement{{SandboxID: fmt.Sprintf("sb-%d", i)}})
	}
	entries := len(a.shardCache)
	_, newestKept := a.shardCache["16384:99"]
	_, previousKept := a.shardCache["16384:98"]
	_, oldestDropped := a.shardCache["16384:0"]
	a.cacheMu.Unlock()

	if entries > maxAgentShardCacheEntries {
		t.Fatalf("shard cache retained %d entries for 100 filter histories, want at most %d", entries, maxAgentShardCacheEntries)
	}
	if !newestKept || !previousKept {
		t.Fatal("current and previous generations must both survive; a ring change must not lose the fallback view")
	}
	if oldestDropped {
		t.Fatal("a superseded generation was retained")
	}
}

// widePlacement is a valid route-carrying row at its maximum supported width:
// models.MaxCustomDomainsPerSandbox hostnames, each at the DNS label/name
// limits. Route metadata lives in these hot rows, so the row count that bounds
// a page does not bound the page's size.
func widePlacement(i int) Placement {
	hosts := make([]string, models.MaxCustomDomainsPerSandbox)
	for j := range hosts {
		hosts[j] = fmt.Sprintf("h%d-%d.%s.%s.example.com", i, j, strings.Repeat("a", 63), strings.Repeat("b", 63))
	}
	return Placement{
		SandboxID:       fmt.Sprintf("sb-%06d", i),
		OwnerNodeID:     "worker",
		CustomHostnames: hosts,
	}
}

// A full page of valid wide rows encoded to 19,487,287 bytes against a
// 16,777,216-byte ceiling: the read failed and a cold ingress fell back to an
// empty view. Bound the page by bytes, not only by rows.
func TestPlacementPageIsBoundedByEncodedSize(t *testing.T) {
	fsm := newPlacementFSM()
	const total = MaxPlacementPageLimit + 32
	for i := range total {
		p := widePlacement(i)
		fsm.placements[p.SandboxID] = p
		fsm.placementIDs.ReplaceOrInsert(p.SandboxID)
	}

	page := fsm.placementPage(PlacementPageRequest{Limit: MaxPlacementPageLimit})
	if len(page.Placements) == 0 {
		t.Fatal("page returned no rows at all")
	}
	payload, err := json.Marshal(page)
	if err != nil {
		t.Fatalf("marshal page: %v", err)
	}
	if len(payload) > maxControlPlaneJSONResponseBytes {
		t.Fatalf("page of %d valid wide rows encodes to %d bytes, past the %d-byte response ceiling",
			len(page.Placements), len(payload), maxControlPlaneJSONResponseBytes)
	}
	if len(page.Placements) == MaxPlacementPageLimit {
		t.Fatal("the page was not trimmed; the fixture no longer exceeds the budget on row count alone")
	}
	if page.NextPageToken == "" {
		t.Fatal("a trimmed page carried no cursor; the rows behind it are unreachable")
	}
}

// Trimming by bytes must not lose rows: the cursor has to carry every row the
// page could not fit.
func TestPlacementPageByteTrimKeepsWalkComplete(t *testing.T) {
	fsm := newPlacementFSM()
	const total = 600
	for i := range total {
		p := widePlacement(i)
		fsm.placements[p.SandboxID] = p
		fsm.placementIDs.ReplaceOrInsert(p.SandboxID)
	}

	seen := map[string]struct{}{}
	token := ""
	for pages := 0; pages < 64; pages++ {
		page := fsm.placementPage(PlacementPageRequest{Limit: MaxPlacementPageLimit, PageToken: token})
		for _, p := range page.Placements {
			seen[p.SandboxID] = struct{}{}
		}
		if page.NextPageToken == "" || page.NextPageToken == token {
			break
		}
		token = page.NextPageToken
	}
	if len(seen) != total {
		t.Fatalf("the byte-trimmed walk returned %d of %d rows", len(seen), total)
	}
}

// A control plane running the previous build pages by row count only, so the
// client has to be able to ask for less. Repeating the identical request
// cannot recover a cold ingress.
func TestAgentShrinksPageWhenResponseExceedsCeiling(t *testing.T) {
	const total = 40
	var limits []int
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalPlacementsPagePath {
			http.NotFound(w, r)
			return
		}
		var req PlacementPageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode page request: %v", err)
			return
		}
		limits = append(limits, req.Limit)
		if req.Limit > total {
			// The legacy shape: honors the row count, blows the size ceiling.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(make([]byte, maxControlPlaneJSONResponseBytes+1))
			return
		}
		resp := PlacementPageResponse{Authoritative: true}
		for i := range total {
			resp.Placements = append(resp.Placements, Placement{SandboxID: fmt.Sprintf("sb-%06d", i), Version: 1})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleIngress})

	got := agent.PlacementsForShards(PlacementShardFilter{})
	if len(got) != total {
		t.Fatalf("PlacementsForShards returned %d placements, want %d; the ingress never recovered from the oversized page", len(got), total)
	}
	if len(limits) < 2 {
		t.Fatalf("made %d requests; an oversized response must be retried with a smaller page", len(limits))
	}
	if limits[1] >= limits[0] {
		t.Fatalf("retry asked for %d rows after %d; repeating the same request cannot recover", limits[1], limits[0])
	}
}

// A row too large to deliver at all is neither present nor absent. Route GC
// deletes routes for placements it cannot see, so the hole must read as
// "unavailable" — the cached view — not as an authoritative answer.
func TestAgentTreatsSkippedPlacementRowsAsUnavailable(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalPlacementsPagePath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PlacementPageResponse{
			Placements:        []Placement{{SandboxID: "sb-visible", Version: 1}},
			SkippedSandboxIDs: []string{"sb-too-wide"},
			Authoritative:     true,
		})
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleIngress})

	// Seed the fallback cache with a previous good view.
	agent.cacheMu.Lock()
	agent.placementCache = []Placement{{SandboxID: "sb-visible", Version: 1}, {SandboxID: "sb-too-wide", Version: 1}}
	agent.cacheMu.Unlock()

	got := agent.PlacementsForShards(PlacementShardFilter{})
	ids := make([]string, 0, len(got))
	for _, p := range got {
		ids = append(ids, p.SandboxID)
	}
	if !slices.Contains(ids, "sb-too-wide") {
		t.Fatalf("view = %v; a row the control plane could not deliver was reported as absent, and route GC deletes what it cannot see", ids)
	}
}

// The ingress reconciler records the version PlacementViewForShards returns
// as installed after a good pass, so on a gateway it must be the version of
// the view it returned: a point read (PlacementOf; OwnerOf on every API call
// the gateway routes) of a row the view does not hold yet moves
// PlacementVersion, never the view's (issue #1343 review: it reported
// converged for a route never installed). With the delta feed synced the
// view is current to the feed's cursor, read with its rows.
func TestAgentPlacementViewVersionMovesOnlyWithTheView(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == PublicInternalPlacementsPagePath:
			_ = json.NewEncoder(w).Encode(PlacementPageResponse{Authoritative: true,
				Placements: []Placement{{SandboxID: "sb-a", OwnerNodeID: "w1", Version: 10}}})
		case strings.HasPrefix(r.URL.Path, PublicInternalPlacementPath):
			// sb-b, created at 11, not delivered to the view yet.
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{SandboxID: "sb-b",
				Placement: Placement{SandboxID: "sb-b", OwnerNodeID: "w1", Version: 11}})
		default:
			http.NotFound(w, r)
		}
	}), Member{NodeID: "gw-self", Alive: true, Role: config.NodeRoleIngress})

	if view, v := agent.PlacementViewForShards(PlacementShardFilter{}); len(view) != 1 || v != 10 {
		t.Fatalf("view walk = (%+v, %d), want (sb-a, 10)", view, v)
	}
	if _, ok := agent.PlacementOf("sb-b"); !ok {
		t.Fatal("point read of sb-b failed")
	}
	if got := agent.PlacementVersion(); got != 11 {
		t.Fatalf("PlacementVersion after the point read = %d, want 11", got)
	}
	if _, v := agent.PlacementViewForShards(PlacementShardFilter{}); v != 10 {
		t.Fatalf("view version after a point read = %d, want 10: sb-b is not in the view", v)
	}
	agent.feed = &agentPlacementFeed{cursor: 15, synced: true, rows: map[string]Placement{
		"sb-a": {SandboxID: "sb-a", OwnerNodeID: "w1", Version: 10},
	}}
	if _, v := agent.PlacementViewForShards(PlacementShardFilter{}); v != 15 {
		t.Fatalf("view version with the feed synced at 15 = %d, want 15 (the cursor counts deletes)", v)
	}
	// A node that serves no shards has nothing to install: no lag.
	if view, v := agent.PlacementViewForShards(NoPlacementShards()); view != nil || v != agent.PlacementVersion() {
		t.Fatalf("no-shard view = (%v, %d), want (nil, %d)", view, v, agent.PlacementVersion())
	}
}

// After a Resnapshot the feed is unsynced and keeps its old cursor and rows,
// and while the server tier fails over the page walk can fail too: the view
// then comes from the walk cache, which may be far older than that cursor.
// Its version must be the cache's own, or a good reconcile pass records a
// version its view does not hold (issue #1343 review, round 2).
func TestAgentViewVersionIsTheCachedViewsWhenTheFeedIsUnsynced(t *testing.T) {
	var failWalk atomic.Bool
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalPlacementsPagePath {
			http.NotFound(w, r)
			return
		}
		if failWalk.Load() {
			http.Error(w, "server tier failing over", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PlacementPageResponse{Authoritative: true,
			Placements: []Placement{{SandboxID: "sb-a", OwnerNodeID: "w1", Version: 10}}})
	}), Member{NodeID: "gw-self", Alive: true, Role: config.NodeRoleIngress})

	// An early walk (before the feed synced) leaves sb-a@10 in the cache.
	if got := agent.PlacementsForShards(PlacementShardFilter{}); len(got) != 1 {
		t.Fatalf("first walk = %+v", got)
	}
	// The feed then ran to 15 (sb-b created at 15), and the server just
	// answered Resnapshot: unsynced, cursor and rows kept.
	agent.feed = &agentPlacementFeed{cursor: 15, rows: map[string]Placement{
		"sb-a": {SandboxID: "sb-a", OwnerNodeID: "w1", Version: 10},
		"sb-b": {SandboxID: "sb-b", OwnerNodeID: "w1", Version: 15},
	}}
	failWalk.Store(true)

	view, v := agent.PlacementViewForShards(PlacementShardFilter{})
	if len(view) != 1 || view[0].SandboxID != "sb-a" {
		t.Fatalf("view = %+v, want the cached sb-a", view)
	}
	if v != 10 {
		t.Fatalf("view version = %d, want 10: the cached view holds nothing past it", v)
	}
}

// A gateway without the delta feed reads its view by page walks. The
// drill's case (issue #1343): while Caddy is down a walk sees sb-b@20, then
// sb-b is deleted; the next walk is newer server state, so its view is
// current to at least 20, the delete included. Versioned by its own rows
// alone (10) the reconciler would record 10 and the lag would stay 10 on a
// quiet cluster with nothing left to install (review round 3).
func TestAgentFreshWalkIsCurrentToEarlierWalks(t *testing.T) {
	var deleted atomic.Bool
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalPlacementsPagePath {
			http.NotFound(w, r)
			return
		}
		rows := []Placement{{SandboxID: "sb-a", OwnerNodeID: "w1", Version: 10}}
		if !deleted.Load() {
			rows = append(rows, Placement{SandboxID: "sb-b", OwnerNodeID: "w1", Version: 20})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PlacementPageResponse{Authoritative: true, Placements: rows})
	}), Member{NodeID: "gw-self", Alive: true, Role: config.NodeRoleIngress})

	if _, v := agent.PlacementViewForShards(PlacementShardFilter{}); v != 20 {
		t.Fatalf("first walk version = %d, want 20", v)
	}
	deleted.Store(true)
	view, v := agent.PlacementViewForShards(PlacementShardFilter{})
	if len(view) != 1 || v != 20 {
		t.Fatalf("walk after the delete = (%d rows, version %d), want (1, 20): it is newer than the walk that saw 20", len(view), v)
	}
	if lag := agent.PlacementVersion() - v; lag != 0 {
		t.Fatalf("lag = %d with nothing left to install", lag)
	}
}

// Walks can overlap (the reconciler, the routing commit and other readers
// each walk). One that finishes while another runs may have read newer
// server state than the one still running, so it must not lend that one its
// version; a walk that starts after both finished is current to both
// (review round 4).
func TestAgentOverlappingWalksLendNoVersion(t *testing.T) {
	var calls atomic.Int64
	var deleted atomic.Bool
	slowEntered := make(chan struct{})
	release := make(chan struct{})
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalPlacementsPagePath {
			http.NotFound(w, r)
			return
		}
		rows := []Placement{{SandboxID: "sb-a", OwnerNodeID: "w1", Version: 10}}
		switch {
		case calls.Add(1) == 1:
			// The slow walk reads the older state.
			close(slowEntered)
			<-release
		case !deleted.Load():
			rows = append(rows, Placement{SandboxID: "sb-c", OwnerNodeID: "w1", Version: 30})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PlacementPageResponse{Authoritative: true, Placements: rows})
	}), Member{NodeID: "gw-self", Alive: true, Role: config.NodeRoleIngress})

	someShards := PlacementShardFilter{Shards: []int{1, 2}, ShardCount: DefaultPlacementShardCount}
	slow := make(chan uint64, 1)
	go func() {
		_, v := agent.PlacementViewForShards(someShards)
		slow <- v
	}()
	<-slowEntered
	if _, v := agent.PlacementViewForShards(PlacementShardFilter{}); v != 30 {
		t.Fatalf("fast walk version = %d, want 30", v)
	}
	close(release)
	if v := <-slow; v != 10 {
		t.Fatalf("the slow walk, started before the fast one finished, reports %d; want its own 10", v)
	}
	deleted.Store(true)
	if _, v := agent.PlacementViewForShards(someShards); v != 30 {
		t.Fatalf("a walk started after both finished reports %d; want 30 (sb-c's delete is in its view)", v)
	}
}

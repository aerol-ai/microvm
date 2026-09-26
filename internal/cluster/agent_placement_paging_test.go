package cluster

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
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

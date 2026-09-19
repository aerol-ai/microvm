package cluster

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
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

package cluster

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

// The handler refuses a body carrying more than MaxPlacementPageLimit ids, and
// a refused batch looks exactly like "control plane unavailable" to callers —
// one oversized request therefore skips a whole node's work, not just the
// surplus. Chunk instead, so the answer is still complete.
func TestAgentPlacementsByIDsChunksAtEndpointLimit(t *testing.T) {
	const total = MaxPlacementPageLimit + 7
	var sizes []int
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != PublicInternalPlacementsByIDsPath {
			http.NotFound(w, r)
			return
		}
		var req placementsByIDsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		sizes = append(sizes, len(req.IDs))
		if len(req.IDs) > MaxPlacementPageLimit {
			// Mirror the real handler's refusal.
			http.Error(w, "too many placement ids", http.StatusBadRequest)
			return
		}
		out := make(map[string]Placement, len(req.IDs))
		for _, id := range req.IDs {
			out[id] = Placement{SandboxID: id, Version: 1}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	ids := make([]string, 0, total)
	for i := range total {
		ids = append(ids, fmt.Sprintf("sb-%05d", i))
	}

	got := agent.PlacementsByIDs(ids)
	if len(got) != total {
		t.Fatalf("PlacementsByIDs returned %d placements, want %d", len(got), total)
	}
	if len(sizes) != 2 {
		t.Fatalf("issued %d requests for %d ids, want 2 chunks", len(sizes), total)
	}
	for _, size := range sizes {
		if size > MaxPlacementPageLimit {
			t.Fatalf("chunk carried %d ids, endpoint accepts at most %d", size, MaxPlacementPageLimit)
		}
	}
}

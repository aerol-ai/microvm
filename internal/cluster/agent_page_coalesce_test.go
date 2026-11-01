package cluster

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// Regression (bank flagship ramp, 2026-11-01): every GET /v1/sandboxes on an
// ingress made its own control-plane placement-page read, so 512 concurrent
// lists on ingress-2 made 512 concurrent mTLS requests to the servers; the
// servers answered each in under a millisecond, but the ingress spent its
// two vCPUs on handshakes, timed out on all of them ("Client.Timeout
// exceeded while awaiting headers") and fell over. Concurrent identical
// reads now share one request — and a shared answer is still one that began
// after the caller asked.
func TestAgentPlacementPageCoalescesConcurrentReads(t *testing.T) {
	var reads atomic.Int32
	release := make(chan struct{})
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalPlacementsPagePath {
			http.NotFound(w, r)
			return
		}
		var req PlacementPageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		n := reads.Add(1)
		if n == 1 {
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PlacementPageResponse{
			Placements:    []Placement{{SandboxID: "sb-1", OwnerNodeID: "worker-1", SecretRef: "ref", Version: uint64(n)}},
			NextPageToken: fmt.Sprintf("read-%d", n),
		})
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleIngress})

	req := PlacementPageRequest{Limit: 100, OwnerRef: "acct-1"}
	first := make(chan PlacementPageResponse, 1)
	go func() { first <- agent.PlacementPage(req) }()
	waitFor(t, 5*time.Second, "the first read to reach the control plane", func() bool { return reads.Load() == 1 })

	const callers = 40
	pages := make([]PlacementPageResponse, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pages[i] = agent.PlacementPage(req)
		}()
	}
	key, _ := json.Marshal(req.Normalize())
	waitFor(t, 5*time.Second, "the callers to queue", func() bool { return agent.pageReads.queued(string(key)) == callers })
	close(release)
	wg.Wait()

	if got := (<-first).NextPageToken; got != "read-1" {
		t.Fatalf("first caller got %q, want read-1", got)
	}
	for i, page := range pages {
		if !page.Authoritative || page.NextPageToken != "read-2" || len(page.Placements) != 1 {
			t.Fatalf("caller %d got %+v, want the authoritative read-2 (the read that began after it asked)", i, page)
		}
	}
	if n := reads.Load(); n != 2 {
		t.Fatalf("%d control-plane reads for %d concurrent lists, want 2", n, callers+1)
	}
	// Each caller owns its rows slice: the sandbox-index handler redacts
	// rows in place, which must not reach another caller's answer.
	pages[0].Placements[0].SecretRef = ""
	if pages[1].Placements[0].SecretRef != "ref" {
		t.Fatal("redacting one caller's rows changed another caller's answer")
	}

	// Different requests are not merged.
	other := agent.PlacementPage(PlacementPageRequest{Limit: 100, OwnerRef: "acct-2"})
	if other.NextPageToken != "read-3" || reads.Load() != 3 {
		t.Fatalf("another tenant's read was not its own: %+v after %d reads", other, reads.Load())
	}
}

// A control-plane failure is shared like an answer: every queued caller gets
// the explicit not-ready page (Authoritative=false), never an empty
// authoritative one.
func TestAgentPlacementPageSharesAFailureAsNotReady(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleIngress})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if page := agent.PlacementPage(PlacementPageRequest{}); page.Authoritative || len(page.Placements) != 0 {
				t.Errorf("a failed read answered %+v, want the not-ready page", page)
			}
		}()
	}
	wg.Wait()
}

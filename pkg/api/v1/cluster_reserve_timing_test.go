package v1

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// Plan PR #1000 item L1: on a cluster create the router picks a node and
// writes the reservation to Raft before create;dur starts. When this node is
// the one picked, those two steps must still show up on the create's
// Server-Timing, or about 10 ms of every cluster create is covered by no stage.
func TestClusterCreateReportsPlaceAndReserveStages(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, _ := newClusterCreateHarness(t, rt, stub)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`))
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	if n := len(rr.Header().Values("Server-Timing")); n != 1 {
		t.Fatalf("Server-Timing header lines = %d, want 1", n)
	}
	st := rr.Header().Get("Server-Timing")
	for _, want := range []string{"create;dur=", "cluster_place;dur=", "cluster_reserve;dur=", "cluster_promote;dur="} {
		if !strings.Contains(st, want) {
			t.Fatalf("Server-Timing = %q, missing %q", st, want)
		}
	}
	// The router only forwards when another node was picked.
	if strings.Contains(st, "cluster_forward") {
		t.Fatalf("Server-Timing = %q, want no cluster_forward on a create placed on this node", st)
	}
}

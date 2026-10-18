package clusterlist

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestPeerFetchStampsTheForward pins E6 and H3 at the fan-out client: both
// merge shapes (the v1 sandbox list and the facades' JSON lists) send each
// peer the forwarded marker, the team the caller's verified Access resolved,
// and the request's correlation id, next to the caller's own credential.
func TestPeerFetchStampsTheForward(t *testing.T) {
	var mu sync.Mutex
	var seen []http.Header
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		_ = json.NewEncoder(w).Encode([]models.Sandbox{{ID: "sb-peer"}})
	}))
	t.Cleanup(peer.Close)
	member := cluster.Member{NodeID: "peer-1", Alive: true, InternalURL: peer.URL, Role: config.NodeRoleWorker}
	opts := Options{
		AuthHeader: "Bearer avm_multi",
		SelfNodeID: "edge",
		Transport:  Transport{InternalClient: peer.Client(), PeerClient: func(string) *http.Client { return peer.Client() }},
		Path:       "/v1/sandboxes",
	}
	access := controlplane.Access{
		Identity:  controlplane.Identity{OwnerRef: controlplane.TeamOwnerRef("bravo")},
		Role:      controlplane.RoleRunner,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_multi"},
	}
	ctx := auditlog.ContextWithCorrelationID(controlplane.ContextWithAccess(context.Background(), access), "corr-list")

	if res := Merge(ctx, []cluster.Member{member}, opts); len(res.Sandboxes) != 1 || res.Coverage.Partial {
		t.Fatalf("Merge = %+v", res)
	}
	type row struct {
		ID string `json:"id"`
	}
	if items, cov := MergeJSON(ctx, []cluster.Member{member}, nil, func(v row) string { return v.ID }, opts); len(items) != 1 || cov.Partial {
		t.Fatalf("MergeJSON = %+v %+v", items, cov)
	}
	if len(seen) != 2 {
		t.Fatalf("peer saw %d requests, want 2", len(seen))
	}
	want := map[string]string{
		"Authorization":             "Bearer avm_multi",
		cluster.HeaderForwarded:     "1",
		cluster.HeaderTeam:          "bravo",
		cluster.HeaderCorrelationID: "corr-list",
		cluster.PeerNodeIDHeader:    "edge",
	}
	for i, h := range seen {
		for name, value := range want {
			if got := h.Get(name); got != value {
				t.Errorf("request %d: %s = %q, want %q", i, name, got, value)
			}
		}
	}
}

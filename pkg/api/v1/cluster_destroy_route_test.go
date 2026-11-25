package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// abandonedGatewayStub is a gateway that knows a sandbox is left on a node
// an operator deleted (pkg/api/clusterroute abandoned.go). It may not delete
// that placement itself, so a DELETE must go on to a server.
type abandonedGatewayStub struct {
	*cluster.Noop
	owner    cluster.OwnerInfo
	ownerErr error
	place    cluster.Placement
	toServer int
}

func (c *abandonedGatewayStub) OwnerOf(string) (cluster.OwnerInfo, error) { return c.owner, c.ownerErr }
func (c *abandonedGatewayStub) PlacementOf(string) (cluster.Placement, bool) {
	return c.place, true
}
func (c *abandonedGatewayStub) IsNodeDenied(id string) bool { return id == "wkr-deleted" }
func (c *abandonedGatewayStub) ForwardToServer(w http.ResponseWriter, _ *http.Request) {
	c.toServer++
	w.WriteHeader(http.StatusNoContent)
}

// abandonedGatewayStubs are the two ways a sandbox is left on a deleted
// node: still named on it (before the leader hands it off), or orphaned
// from it (after).
func abandonedGatewayStubs() map[string]func() *abandonedGatewayStub {
	return map[string]func() *abandonedGatewayStub{
		"still on the deleted node": func() *abandonedGatewayStub {
			return &abandonedGatewayStub{Noop: cluster.NewNoop("gw-1", "http://gw-1", ""),
				owner: cluster.OwnerInfo{NodeID: "wkr-deleted", APIURL: "http://wkr-deleted"},
				place: cluster.Placement{SandboxID: "sb-1", IncarnationID: "inc-1", OwnerNodeID: "wkr-deleted"}}
		},
		"orphaned from the deleted node": func() *abandonedGatewayStub {
			return &abandonedGatewayStub{Noop: cluster.NewNoop("gw-1", "http://gw-1", ""), ownerErr: cluster.ErrOrphaned,
				place: cluster.Placement{SandboxID: "sb-1", IncarnationID: "inc-1",
					OwnerState: cluster.PlacementOwnerStateOrphaned, OrphanedOwnerNodeID: "wkr-deleted"}}
		},
	}
}

// The real DELETE /v1/sandboxes/{id} route marks itself as the delete
// (clusterDestroyForwardWrap, Destroy: true), so a gateway sends a delete of
// a sandbox left on a deleted node to a server. Routed like any other call,
// it would answer 503 or 410 on every retry, which is what this pins.
func TestV1DeleteRouteSendsAnAbandonedSandboxToAServer(t *testing.T) {
	for name, stub := range abandonedGatewayStubs() {
		t.Run(name, func(t *testing.T) {
			c := stub()
			req := httptest.NewRequest(http.MethodDelete, PathPrefix+"/sandboxes/sb-1", nil)
			req.Header.Set("Authorization", "Bearer tok")
			rr := httptest.NewRecorder()
			nodeRoutesMux(t, c).ServeHTTP(rr, req)
			if c.toServer != 1 || rr.Code != http.StatusNoContent {
				t.Fatalf("DELETE = %d %q, sent to a server %d times; want it sent once", rr.Code, rr.Body.String(), c.toServer)
			}
			// Any other call for it is not a delete: it waits or is gone.
			rr = serve(nodeRoutesMux(t, c), http.MethodGet, PathPrefix+"/sandboxes/sb-1")
			if c.toServer != 1 || (rr.Code != http.StatusServiceUnavailable && rr.Code != http.StatusGone) {
				t.Fatalf("GET = %d, sent to a server %d times; want 503 or 410 and no send", rr.Code, c.toServer)
			}
		})
	}
}

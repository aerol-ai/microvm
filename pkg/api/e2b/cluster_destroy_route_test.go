package e2b

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// abandonedGatewayStub is a gateway that knows a sandbox is left on a node
// an operator deleted (pkg/api/clusterroute abandoned.go). It may not delete
// that placement itself, so a kill must go on to a server.
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

// abandonedRoutesMux serves the real E2B routes on a gateway, as the fleet
// operator.
func abandonedRoutesMux(c cluster.Client) *http.ServeMux {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(c)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc, Logger: logger, Auth: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.Access{Fleet: true})))
		})
	}})
	return mux
}

// The real E2B kill route (DELETE /e2b/sandboxes/{id}) marks itself as the
// delete (clusterDestroyForwardWrap, Destroy: true), so a gateway sends a
// kill of a sandbox left on a deleted node to a server. Routed like any
// other call, it would answer 503 or 410 on every retry, which is what this
// pins.
func TestE2BKillRouteSendsAnAbandonedSandboxToAServer(t *testing.T) {
	for name, c := range map[string]*abandonedGatewayStub{
		"still on the deleted node": {Noop: cluster.NewNoop("gw-1", "http://gw-1", ""),
			owner: cluster.OwnerInfo{NodeID: "wkr-deleted", APIURL: "http://wkr-deleted"},
			place: cluster.Placement{SandboxID: "sb-1", IncarnationID: "inc-1", OwnerNodeID: "wkr-deleted"}},
		"orphaned from the deleted node": {Noop: cluster.NewNoop("gw-1", "http://gw-1", ""), ownerErr: cluster.ErrOrphaned,
			place: cluster.Placement{SandboxID: "sb-1", IncarnationID: "inc-1",
				OwnerState: cluster.PlacementOwnerStateOrphaned, OrphanedOwnerNodeID: "wkr-deleted"}},
	} {
		t.Run(name, func(t *testing.T) {
			mux := abandonedRoutesMux(c)
			req := httptest.NewRequest(http.MethodDelete, PathPrefix+"/sandboxes/sb-1", nil)
			req.Header.Set("Authorization", "Bearer tok")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if c.toServer != 1 || rr.Code != http.StatusNoContent {
				t.Fatalf("kill = %d %q, sent to a server %d times; want it sent once", rr.Code, rr.Body.String(), c.toServer)
			}
			// Any other call for it is not a delete: it waits or is gone.
			rr = httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, PathPrefix+"/sandboxes/sb-1/pause", nil))
			if c.toServer != 1 || (rr.Code != http.StatusServiceUnavailable && rr.Code != http.StatusGone) {
				t.Fatalf("pause = %d, sent to a server %d times; want 503 or 410 and no send", rr.Code, c.toServer)
			}
		})
	}
}

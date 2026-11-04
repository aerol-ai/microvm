package clusterroute

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// placementStub adds a scriptable PlacementOf (tenant owner) to stubCluster.
type placementStub struct {
	*stubCluster
	placement cluster.Placement
	hasPlace  bool
}

func (c *placementStub) PlacementOf(string) (cluster.Placement, bool) {
	return c.placement, c.hasPlace
}

// #15: the cluster router must not turn its routing states (410 owner-died,
// 503 owner-URL-unknown) into an existence oracle for another tenant's sandbox
// id. An owner-scoped caller hitting a foreign id gets the local handler (which
// 404s via owner scoping), exactly as for an id that does not exist.
func TestWrap_ForeignSandboxIsNotAnExistenceOracle(t *testing.T) {
	inner := &stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrOrphaned}
	stub := &placementStub{stubCluster: inner, hasPlace: true, placement: cluster.Placement{OwnerRef: "acct-b"}}
	svc := svcWith(t, stub)

	lh, ran := local()
	h := Wrap(svc, Options{WriteError: writeErr}, lh)

	// Caller is tenant acct-a; the sandbox belongs to acct-b. Without the fix
	// this returned 410 (Gone), revealing the id exists.
	r := req("sb-b")
	r = r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.Access{
		Identity: controlplane.Identity{ExternalID: "u-a", OwnerRef: "acct-a"},
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if !*ran {
		t.Fatalf("foreign sandbox did not fall through to the local handler; status %d body %q", rr.Code, rr.Body.String())
	}
	if rr.Code == http.StatusGone {
		t.Fatal("foreign sandbox leaked existence via 410 Gone")
	}

	// Control: the OWNER (acct-b) still gets the real routing state (410).
	inner.forwarded = false
	lh2, ran2 := local()
	h2 := Wrap(svc, Options{WriteError: writeErr}, lh2)
	r2 := req("sb-b")
	r2 = r2.WithContext(controlplane.ContextWithAccess(r2.Context(), controlplane.Access{
		Identity: controlplane.Identity{ExternalID: "u-b", OwnerRef: "acct-b"},
	}))
	rr2 := httptest.NewRecorder()
	h2.ServeHTTP(rr2, r2)
	if *ran2 || rr2.Code != http.StatusGone {
		t.Fatalf("owner routing = ran:%v code:%d, want 410 Gone", *ran2, rr2.Code)
	}
}

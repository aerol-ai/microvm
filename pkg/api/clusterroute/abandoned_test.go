package clusterroute

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// Routing for a sandbox left on a node an operator deleted (abandoned.go).
// The live failure: a DELETE was forwarded to the deleted node, which had no
// InternalURL any more, and answered 503 on every retry.

// abandonedStub is a worker or gateway: it knows the deny set and can send a
// call to a server, but may not delete another node's placement.
type abandonedStub struct {
	*stubCluster
	denied   map[string]bool
	place    cluster.Placement
	placed   bool
	toServer int
}

func (c *abandonedStub) IsNodeDenied(id string) bool { return c.denied[id] }
func (c *abandonedStub) PlacementOf(string) (cluster.Placement, bool) {
	return c.place, c.placed
}
func (c *abandonedStub) ForwardToServer(w http.ResponseWriter, _ *http.Request) {
	c.toServer++
	w.WriteHeader(http.StatusNoContent)
}

// abandonedServerStub is a server: it deletes abandoned placements itself.
type abandonedServerStub struct{ *abandonedStub }

func (c *abandonedServerStub) DeleteAbandonedPlacement(context.Context, cluster.Placement) error {
	return nil
}

func TestWrapSandboxOnADeletedNode(t *testing.T) {
	const deleted, died, live = "worker-deleted", "worker-died", "worker-live"
	onDeleted := cluster.OwnerInfo{NodeID: deleted, APIURL: "http://" + deleted}
	orphanOf := func(node string) cluster.Placement {
		return cluster.Placement{SandboxID: "sb", IncarnationID: "inc", OwnerState: cluster.PlacementOwnerStateOrphaned, OrphanedOwnerNodeID: node}
	}
	ownedBy := func(node string) cluster.Placement {
		return cluster.Placement{SandboxID: "sb", IncarnationID: "inc", OwnerNodeID: node}
	}
	// The agent-sandbox API's caller (pkg/api KubeBackend): an in-process
	// call with no credential, for one owner.
	kube := &controlplane.Access{
		Identity:  controlplane.Identity{OwnerRef: "team:dev", Role: controlplane.RoleRunner},
		Role:      controlplane.RoleRunner,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalKubernetes, ID: "kubernetes:alice"},
	}
	ofTenant := func(p cluster.Placement, owner string) cluster.Placement {
		p.OwnerRef = owner
		return p
	}
	const (
		ranLocal = "local"     // the local handler ran (a server deletes it)
		toServer = "to-server" // sent to a server
		forward  = "forward"   // forwarded to the owner
	)
	tests := []struct {
		name      string
		server    bool
		owner     cluster.OwnerInfo
		ownerErr  error
		place     cluster.Placement
		destroy   bool
		noBearer  bool
		forwarded bool
		access    *controlplane.Access
		want      string
		status    int
	}{
		// The live case: a DELETE of a sandbox still named on the deleted node.
		{name: "DELETE, still on the deleted node, at a server", server: true, owner: onDeleted, place: ownedBy(deleted), destroy: true, want: ranLocal},
		{name: "DELETE, still on the deleted node, at a gateway", owner: onDeleted, place: ownedBy(deleted), destroy: true, want: toServer},
		{name: "DELETE, orphaned from the deleted node, at a server", server: true, ownerErr: cluster.ErrOrphaned, place: orphanOf(deleted), destroy: true, want: ranLocal},
		{name: "DELETE, orphaned from the deleted node, at a gateway", ownerErr: cluster.ErrOrphaned, place: orphanOf(deleted), destroy: true, want: toServer},
		// A gateway never sends the call as itself, and never makes a second hop.
		{name: "DELETE with no credential, at a gateway", ownerErr: cluster.ErrOrphaned, place: orphanOf(deleted), destroy: true, noBearer: true, status: http.StatusGone},
		{name: "DELETE already forwarded once, at a gateway", ownerErr: cluster.ErrOrphaned, place: orphanOf(deleted), destroy: true, forwarded: true, status: http.StatusGone},
		// kubectl delete sandbox: no credential, but the forward speaks for
		// the Kubernetes user by name, so a gateway sends it to a server.
		{name: "Kubernetes DELETE, orphaned from the deleted node, at a gateway", ownerErr: cluster.ErrOrphaned, place: ofTenant(orphanOf(deleted), "team:dev"), destroy: true, noBearer: true, access: kube, want: toServer},
		{name: "Kubernetes DELETE, still on the deleted node, at a gateway", owner: onDeleted, place: ofTenant(ownedBy(deleted), "team:dev"), destroy: true, noBearer: true, access: kube, want: toServer},
		{name: "Kubernetes DELETE already forwarded once, at a gateway", ownerErr: cluster.ErrOrphaned, place: ofTenant(orphanOf(deleted), "team:dev"), destroy: true, noBearer: true, forwarded: true, access: kube, status: http.StatusGone},
		// Another tenant's sandbox is never sent on: the local handler
		// answers it, with the 404 it gives an unknown id.
		{name: "Kubernetes DELETE of another tenant's sandbox, at a gateway", ownerErr: cluster.ErrOrphaned, place: ofTenant(orphanOf(deleted), "team:other"), destroy: true, noBearer: true, access: kube, want: ranLocal},
		{name: "Kubernetes GET, orphaned from the deleted node", ownerErr: cluster.ErrOrphaned, place: ofTenant(orphanOf(deleted), "team:dev"), noBearer: true, access: kube, status: http.StatusGone},
		// What keeps its answer.
		{name: "DELETE, orphan of a node that only died", server: true, ownerErr: cluster.ErrOrphaned, place: orphanOf(died), destroy: true, status: http.StatusGone},
		{name: "GET, orphaned from the deleted node", server: true, ownerErr: cluster.ErrOrphaned, place: orphanOf(deleted), status: http.StatusGone},
		{name: "DELETE, owner live", server: true, owner: cluster.OwnerInfo{NodeID: live, APIURL: "http://" + live}, place: ownedBy(live), destroy: true, want: forward},
		// Never forwarded to the deleted node: other calls wait for the hand-off.
		{name: "GET, still on the deleted node", server: true, owner: onDeleted, place: ownedBy(deleted), status: http.StatusServiceUnavailable},
		{
			name: "DELETE, a reservation on the deleted node", owner: onDeleted, destroy: true, status: http.StatusServiceUnavailable,
			place: cluster.Placement{SandboxID: "sb", IncarnationID: "inc", OwnerNodeID: deleted, State: cluster.PlacementStateReserved},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := &abandonedStub{
				stubCluster: &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: tc.owner, ownerErr: tc.ownerErr},
				denied:      map[string]bool{deleted: true},
				place:       tc.place,
				placed:      true,
			}
			var c cluster.Client = base
			if tc.server {
				c = &abandonedServerStub{abandonedStub: base}
			}
			lh, ran := local()
			r := req("sb")
			if tc.destroy {
				r.Method = http.MethodDelete
			}
			if !tc.noBearer {
				r.Header.Set("Authorization", "Bearer tok")
			}
			if tc.forwarded {
				r.Header.Set(cluster.HeaderForwarded, "1")
			}
			if tc.access != nil {
				r = r.WithContext(controlplane.ContextWithAccess(r.Context(), *tc.access))
			}
			rr := httptest.NewRecorder()
			Wrap(svcWith(t, c), Options{WriteError: writeErr, Destroy: tc.destroy}, lh).ServeHTTP(rr, r)

			got := ""
			switch {
			case *ran:
				got = ranLocal
			case base.toServer > 0:
				got = toServer
			case base.forwarded:
				got = forward
			}
			if got != tc.want {
				t.Fatalf("routed to %q, want %q (status %d, body %q)", got, tc.want, rr.Code, rr.Body.String())
			}
			if tc.status != 0 && rr.Code != tc.status {
				t.Fatalf("status = %d, want %d (body %q)", rr.Code, tc.status, rr.Body.String())
			}
			if tc.status == http.StatusServiceUnavailable && rr.Header().Get("Retry-After") == "" {
				t.Fatal("503 without Retry-After")
			}
		})
	}
}

// byNameStub resolves one name to id, as the real lookups do for an orphan:
// the id comes back with ErrOrphaned. Its placement answers only by id.
type byNameStub struct {
	*abandonedStub
	id string
}

func (c *byNameStub) OwnerOfName(string, string) (string, cluster.OwnerInfo, error) {
	return c.id, cluster.OwnerInfo{}, cluster.ErrOrphaned
}

func (c *byNameStub) PlacementOf(id string) (cluster.Placement, bool) {
	if id != c.id {
		return cluster.Placement{}, false
	}
	return c.abandonedStub.PlacementOf(id)
}

type byNameServerStub struct{ *byNameStub }

func (c *byNameServerStub) DeleteAbandonedPlacement(context.Context, cluster.Placement) error {
	return nil
}

// A DELETE by name (Daytona's idOrName) of a sandbox orphaned from a deleted
// node. The name lookup answers the id with ErrOrphaned; the placement must
// be read by that id, or the call answered 410 as if the node had only died.
func TestWrapDeleteByNameOfAnOrphanOnADeletedNode(t *testing.T) {
	const deleted = "worker-deleted"
	for _, tc := range []struct {
		name   string
		server bool
	}{{name: "at a gateway"}, {name: "at a server", server: true}} {
		t.Run(tc.name, func(t *testing.T) {
			base := &abandonedStub{
				stubCluster: &stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrUnknownSandbox},
				denied:      map[string]bool{deleted: true},
				place: cluster.Placement{SandboxID: "sb-1", IncarnationID: "inc", OwnerState: cluster.PlacementOwnerStateOrphaned,
					OrphanedOwnerNodeID: deleted},
				placed: true,
			}
			named := &byNameStub{abandonedStub: base, id: "sb-1"}
			var c cluster.Client = named
			if tc.server {
				c = &byNameServerStub{byNameStub: named}
			}
			lh, ran := local()
			r := httptest.NewRequest(http.MethodDelete, "/x/web", nil)
			r.SetPathValue("idOrName", "web")
			r.Header.Set("Authorization", "Bearer tok")
			rr := httptest.NewRecorder()
			Wrap(svcWith(t, c), Options{PathKey: "idOrName", ResolveName: true, WriteError: writeErr, Destroy: true}, lh).ServeHTTP(rr, r)
			if tc.server && !*ran {
				t.Fatalf("a server answered %d %q; want its handler to delete the sandbox", rr.Code, rr.Body.String())
			}
			if !tc.server && base.toServer != 1 {
				t.Fatalf("a gateway answered %d %q and sent it %d times; want it sent to a server once", rr.Code, rr.Body.String(), base.toServer)
			}
		})
	}
}

// An owner-cache entry written before its node was deleted is never used:
// the call takes the lookup path, which does not forward to a deleted node.
func TestOwnerCacheSkipsADeletedNode(t *testing.T) {
	f := newFleet(t, true, "ingress-1", "worker-a")
	f.placeOn("sb-1", "worker-a", "")
	if rr := f.call("ingress-1", http.MethodGet, "sb-1", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("first call status %d", rr.Code)
	}
	if _, ok := f.nodes["ingress-1"].cache.Get("sb-1"); !ok {
		t.Fatal("precondition: the first call did not fill the cache")
	}
	f.deny("worker-a")
	forwards := f.nodes["ingress-1"].forwards.Load()
	rr := f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("call for a sandbox on a deleted node = %d, want 503", rr.Code)
	}
	if got := f.nodes["ingress-1"].forwards.Load(); got != forwards {
		t.Fatalf("the edge forwarded %d more calls to a deleted node", got-forwards)
	}
	if _, ok := f.nodes["ingress-1"].cache.Get("sb-1"); ok {
		t.Fatal("the entry for the deleted node is still cached")
	}
}

// deny records node in the fleet's deny set, as `aerolvm delete node` does.
func (f *fleet) deny(node string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denied[node] = true
}

func (n *fleetNode) IsNodeDenied(node string) bool {
	n.f.mu.Lock()
	defer n.f.mu.Unlock()
	return n.f.denied[node]
}

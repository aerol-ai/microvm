package daytona

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
)

func TestPickVolumeOwnerDeterministicAndStable(t *testing.T) {
	members := []cluster.Member{
		{NodeID: "node-a", APIURL: "http://a", Alive: true},
		{NodeID: "node-b", APIURL: "http://b", Alive: true},
		{NodeID: "node-c", APIURL: "http://c", Alive: true},
	}
	owner, ok := pickVolumeOwner(members, "t-xyz")
	if !ok {
		t.Fatal("expected an owner")
	}
	// Stable: recomputing yields the same winner, and order-independence holds.
	reordered := []cluster.Member{members[2], members[0], members[1]}
	owner2, _ := pickVolumeOwner(reordered, "t-xyz")
	if owner.NodeID != owner2.NodeID {
		t.Fatalf("owner not stable across ordering: %q vs %q", owner.NodeID, owner2.NodeID)
	}
	// Removing a node other than the owner must not move the owner (minimal
	// disruption — the defining property of rendezvous hashing).
	kept := make([]cluster.Member, 0, len(members))
	for _, m := range members {
		if m.NodeID != owner.NodeID && len(kept) == 0 {
			continue // drop exactly one non-owner
		}
		kept = append(kept, m)
	}
	owner3, _ := pickVolumeOwner(kept, "t-xyz")
	if owner3.NodeID != owner.NodeID {
		t.Fatalf("owner moved after dropping a non-owner: %q -> %q", owner.NodeID, owner3.NodeID)
	}
}

func TestPickVolumeOwnerEmpty(t *testing.T) {
	if _, ok := pickVolumeOwner(nil, "t"); ok {
		t.Fatal("no members → no owner")
	}
	if _, ok := pickVolumeOwner([]cluster.Member{{NodeID: ""}}, "t"); ok {
		t.Fatal("blank node ids are not candidates")
	}
	if _, ok := pickVolumeOwner([]cluster.Member{{NodeID: "n1", Alive: false}}, "t"); ok {
		t.Fatal("dead members are not candidates")
	}
}

// A dead member must never be selected even when its hash would win.
func TestPickVolumeOwnerExcludesDead(t *testing.T) {
	all := []cluster.Member{
		{NodeID: "node-a", APIURL: "http://a", Alive: true},
		{NodeID: "node-b", APIURL: "http://b", Alive: true},
		{NodeID: "node-c", APIURL: "http://c", Alive: true},
	}
	owner, ok := pickVolumeOwner(all, "t-xyz")
	if !ok {
		t.Fatal("expected an owner")
	}
	// Mark the winner dead; the owner must move to a live node.
	for i := range all {
		if all[i].NodeID == owner.NodeID {
			all[i].Alive = false
		}
	}
	next, ok := pickVolumeOwner(all, "t-xyz")
	if !ok || next.NodeID == owner.NodeID || !next.Alive {
		t.Fatalf("owner must move to a live node, got %+v ok=%v", next, ok)
	}
}

// volumeForwardCluster is a minimal cluster.Client that advertises a member set
// and records ForwardHTTP. SelfNodeID drives the local-vs-forward decision.
type volumeForwardCluster struct {
	*cluster.Noop
	self      string
	members   []cluster.Member
	forwarded bool
}

func (c *volumeForwardCluster) SelfNodeID() string        { return c.self }
func (c *volumeForwardCluster) Members() []cluster.Member { return c.members }
func (c *volumeForwardCluster) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, _ *http.Request) {
	c.forwarded = true
	w.WriteHeader(http.StatusAccepted)
}

func newVolumeSvc(t *testing.T, c cluster.Client) *service.Service {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{PATToken: "operator-pat"}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(c)
	return svc
}

func TestClusterVolumeForwardWrapForwardsToOwner(t *testing.T) {
	// Build a member set where some node other than "self" owns the operator
	// tenant; force it by making self a non-winner via a large peer set.
	members := []cluster.Member{
		{NodeID: "self", APIURL: "http://self", Alive: true},
		{NodeID: "peer-1", APIURL: "http://peer1", Alive: true},
		{NodeID: "peer-2", APIURL: "http://peer2", Alive: true},
		{NodeID: "peer-3", APIURL: "http://peer3", Alive: true},
	}
	svc := newVolumeSvc(t, &volumeForwardCluster{
		Noop: cluster.NewNoop("self", "http://self", ""), self: "self", members: members,
	})
	tenant, err := svc.VolumeTenantScope(httptest.NewRequest(http.MethodGet, "/", nil).Context())
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	owner, _ := pickVolumeOwner(members, tenant)

	h := newHandlers(Deps{Service: svc})
	localCalled := false
	wrapped := h.clusterVolumeForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/daytona/volumes", nil))

	if owner.NodeID == "self" {
		if !localCalled {
			t.Fatal("owner is self → local handler must run")
		}
	} else {
		if localCalled {
			t.Fatal("owner is a peer → must forward, not run locally")
		}
		if rr.Code != http.StatusAccepted {
			t.Fatalf("expected forwarded 202, got %d", rr.Code)
		}
	}
}

func TestClusterVolumeForwardWrapLoopGuardServesLocally(t *testing.T) {
	members := []cluster.Member{
		{NodeID: "self", APIURL: "http://self", Alive: true},
		{NodeID: "peer-1", APIURL: "http://peer1", Alive: true},
		{NodeID: "peer-2", APIURL: "http://peer2", Alive: true},
		{NodeID: "peer-3", APIURL: "http://peer3", Alive: true},
	}
	svc := newVolumeSvc(t, &volumeForwardCluster{
		Noop: cluster.NewNoop("self", "http://self", ""), self: "self", members: members,
	})
	h := newHandlers(Deps{Service: svc})
	localCalled := false
	wrapped := h.clusterVolumeForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/daytona/volumes", nil)
	req.Header.Set("X-Cluster-Forwarded", "1")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if !localCalled {
		t.Fatal("already-forwarded request must be served locally to break the loop")
	}
}

func TestClusterVolumeForwardWrapNilServiceRunsLocal(t *testing.T) {
	h := newHandlers(Deps{Service: nil})
	localCalled := false
	wrapped := h.clusterVolumeForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localCalled = true
	}))
	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/daytona/volumes", nil))
	if !localCalled {
		t.Fatal("nil service must run locally")
	}
}

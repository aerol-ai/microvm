package v1

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// nodeStubCluster is a cluster that can delete and read nodes, with the old
// servers-only RemoveMember: a worker is unknown to it, exactly as on a real
// Raft server.
type nodeStubCluster struct {
	*cluster.Noop
	deleteCalls []removeMemberCall
	deleteRes   cluster.NodeDeleteResult
	deleteErr   error
	detail      cluster.NodeDetail
	detailErr   error
	detailLimit int
	denied      cluster.DeniedNodesResponse
	deniedNews  bool
	deniedSince uint64
	deniedIDs   map[string]bool
	members     []cluster.Member
	roles       cluster.RaftRoles
}

func (c *nodeStubCluster) DeleteNode(_ context.Context, nodeID string, force bool) (cluster.NodeDeleteResult, error) {
	c.deleteCalls = append(c.deleteCalls, removeMemberCall{nodeID: nodeID, force: force})
	return c.deleteRes, c.deleteErr
}

func (c *nodeStubCluster) NodeDetail(_ context.Context, _ string, limit int) (cluster.NodeDetail, error) {
	c.detailLimit = limit
	return c.detail, c.detailErr
}

func (c *nodeStubCluster) DeniedNodes(since uint64) (cluster.DeniedNodesResponse, bool) {
	c.deniedSince = since
	return c.denied, c.deniedNews
}

func (c *nodeStubCluster) IsNodeDenied(id string) bool { return c.deniedIDs[id] }

func (c *nodeStubCluster) RemoveMember(context.Context, string, bool) error {
	return cluster.ErrUnknownMember
}

func (c *nodeStubCluster) Members() []cluster.Member {
	if c.members != nil {
		return append([]cluster.Member(nil), c.members...)
	}
	return c.Noop.Members()
}

func (c *nodeStubCluster) RaftRoles() (cluster.RaftRoles, bool) {
	return c.roles, c.roles.Servers != nil
}

func (c *nodeStubCluster) LookupMember(id string) (cluster.Member, bool) {
	return cluster.Member{NodeID: id, Alive: true}, true
}

func newNodeStub() *nodeStubCluster {
	return &nodeStubCluster{Noop: cluster.NewNoop("srv-1", "http://srv-1", "")}
}

// nodeRoutesMux serves the real v1 routes as the fleet operator.
func nodeRoutesMux(t *testing.T, c cluster.Client) *http.ServeMux {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(c)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc, Logger: logger, Auth: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := controlplane.ContextWithAccess(r.Context(), controlplane.Access{Fleet: true})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}})
	return mux
}

func serve(mux http.Handler, method, path string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
	return rr
}

// The new any-role delete removes a worker, while the soft-frozen members
// route still answers 404 for that same worker.
func TestDeleteNodeRouteAndFrozenMembersRoute(t *testing.T) {
	stub := newNodeStub()
	stub.deleteRes = cluster.NodeDeleteResult{NodeID: "wkr-1", Role: config.NodeRoleWorker, Denied: true, Orphaned: 2}
	mux := nodeRoutesMux(t, stub)

	rr := serve(mux, http.MethodDelete, "/v1/cluster/nodes/wkr-1?force=true")
	var res cluster.NodeDeleteResult
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &res) != nil || !res.Denied || res.Orphaned != 2 {
		t.Fatalf("DELETE nodes = %d %s", rr.Code, rr.Body.String())
	}
	if len(stub.deleteCalls) != 1 || stub.deleteCalls[0] != (removeMemberCall{nodeID: "wkr-1", force: true}) {
		t.Fatalf("delete calls = %+v", stub.deleteCalls)
	}
	if rr := serve(mux, http.MethodDelete, "/v1/cluster/members/wkr-1"); rr.Code != http.StatusNotFound {
		t.Fatalf("DELETE members for a worker = %d %s, want the unchanged 404", rr.Code, rr.Body.String())
	}
}

func TestDeleteNodeRouteMapsErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{cluster.ErrNotLeader, http.StatusServiceUnavailable},
		{cluster.ErrNotCaughtUp, http.StatusServiceUnavailable},
		{cluster.ErrUnknownNode, http.StatusNotFound},
		{cluster.ErrUnknownMember, http.StatusNotFound},
		{cluster.ErrNodeStillServing, http.StatusConflict},
		{cluster.ErrMemberStillAlive, http.StatusConflict},
		{cluster.ErrLastVoter, http.StatusConflict},
		{cluster.ErrClusterVersion, http.StatusConflict},
		{errors.New("boom"), http.StatusInternalServerError},
	} {
		stub := newNodeStub()
		stub.deleteErr = tc.err
		if rr := serve(nodeRoutesMux(t, stub), http.MethodDelete, "/v1/cluster/nodes/wkr-1"); rr.Code != tc.want {
			t.Fatalf("%v = %d, want %d (%s)", tc.err, rr.Code, tc.want, rr.Body.String())
		}
	}
}

func TestGetNodeRoute(t *testing.T) {
	stub := newNodeStub()
	stub.detail = cluster.NodeDetail{Member: cluster.Member{NodeID: "wkr-1", Version: "v1"}, SandboxesOwned: 3, SandboxesRunning: 2, RunningKnown: true}
	mux := nodeRoutesMux(t, stub)
	rr := serve(mux, http.MethodGet, "/v1/cluster/nodes/wkr-1?sandboxes=50")
	var got cluster.NodeDetail
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil || got.SandboxesOwned != 3 || got.Version != "v1" {
		t.Fatalf("GET node = %d %s", rr.Code, rr.Body.String())
	}
	if stub.detailLimit != 50 {
		t.Fatalf("sandbox id limit = %d", stub.detailLimit)
	}
	stub.detailErr = cluster.ErrUnknownNode
	if rr := serve(mux, http.MethodGet, "/v1/cluster/nodes/wkr-gone"); rr.Code != http.StatusNotFound {
		t.Fatalf("GET gone node = %d", rr.Code)
	}
	stub.detailErr = cluster.ErrNotCaughtUp
	if rr := serve(mux, http.MethodGet, "/v1/cluster/nodes/wkr-1"); rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("GET while catching up = %d retry-after %q", rr.Code, rr.Header().Get("Retry-After"))
	}
}

// cordon is the same admission-only mark as drain.
func TestCordonRouteSetsTheDrainMark(t *testing.T) {
	stub := &drainStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	if rr := serve(nodeRoutesMux(t, stub), http.MethodPost, "/v1/cluster/nodes/node-b/cordon"); rr.Code != http.StatusNoContent {
		t.Fatalf("cordon = %d %s", rr.Code, rr.Body.String())
	}
	if len(stub.setCalls) != 1 || stub.setCalls[0] != (drainSetCall{"node-b", true}) {
		t.Fatalf("set calls = %+v", stub.setCalls)
	}
}

// Single-node mode has no other nodes: every node route answers 503, and
// Noop stays untouched.
func TestNodeRoutesWithoutCluster(t *testing.T) {
	mux := nodeRoutesMux(t, cluster.NewNoop("solo", "http://solo", ""))
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		if rr := serve(mux, method, "/v1/cluster/nodes/solo"); rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s node on single-node = %d", method, rr.Code)
		}
	}
	h := &handlers{}
	rr := httptest.NewRecorder()
	h.clusterDeleteNode(rr, httptest.NewRequest(http.MethodDelete, "/v1/cluster/nodes/x", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no service = %d", rr.Code)
	}
	// A request whose {id} never reached the handler is a 400, not a call.
	stub := newNodeStub()
	h = drainTestHandler(t, stub)
	rr = httptest.NewRecorder()
	h.clusterGetNode(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/nodes/", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty id = %d", rr.Code)
	}
}

func TestInternalDeniedNodesRoute(t *testing.T) {
	stub := newNodeStub()
	h := drainTestHandler(t, stub)
	get := func(query string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.clusterInternalDeniedNodes(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalDeniedNodesPath+query, nil))
		return rr
	}
	if rr := get("?since=9"); rr.Code != http.StatusNotModified || stub.deniedSince != 9 {
		t.Fatalf("current cursor = %d (since %d)", rr.Code, stub.deniedSince)
	}
	stub.denied, stub.deniedNews = cluster.DeniedNodesResponse{Version: 12, Nodes: []cluster.NodeDenyRecord{{NodeID: "wkr-1"}}}, true
	rr := get("?since=bogus")
	var got cluster.DeniedNodesResponse
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil || got.Version != 12 || stub.deniedSince != 0 {
		t.Fatalf("news = %d %s (since %d)", rr.Code, rr.Body.String(), stub.deniedSince)
	}
	// A node without a deny set (a worker, or single-node) answers 404,
	// which a polling mirror reads as "none here".
	noop := drainTestHandler(t, cluster.NewNoop("solo", "http://solo", ""))
	rr = httptest.NewRecorder()
	noop.clusterInternalDeniedNodes(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalDeniedNodesPath, nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("no deny set = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	(&handlers{}).clusterInternalDeniedNodes(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalDeniedNodesPath, nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("no service = %d", rr.Code)
	}
}

// A deleted node's cert still verifies, but the public API's internal
// routes refuse it with the "deleted" 403, before the membership check.
func TestWithInternalMTLSRefusesDeletedPeer(t *testing.T) {
	stub := newNodeStub()
	stub.deniedIDs = map[string]bool{"wkr-gone": true}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(stub)
	calls := 0
	guarded := withInternalMTLS(Deps{Service: svc, Logger: logger}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	for id, want := range map[string]int{"wkr-gone": http.StatusForbidden, "wkr-ok": http.StatusNoContent} {
		req := httptest.NewRequest(http.MethodGet, "https://internal/v1/cluster/internal/secrets", nil)
		addVerifiedClientCertificate(req, &x509.Certificate{DNSNames: []string{"node:" + id}})
		rr := httptest.NewRecorder()
		guarded.ServeHTTP(rr, req)
		if rr.Code != want {
			t.Fatalf("%s = %d, want %d", id, rr.Code, want)
		}
		if want == http.StatusForbidden && !strings.Contains(rr.Body.String(), "was deleted") {
			t.Fatalf("deleted peer body = %q", rr.Body.String())
		}
	}
	if calls != 1 {
		t.Fatalf("handler calls = %d, want only the live peer", calls)
	}
	if peerDenied(Deps{}, "wkr-gone") {
		t.Fatal("no service denied a peer")
	}
}

// The members list carries version, voter and leader.
func TestClusterMembersCarriesRaftRoles(t *testing.T) {
	stub := newNodeStub()
	stub.members = []cluster.Member{{NodeID: "srv-1", Alive: true, Version: "v0.6.12"}, {NodeID: "wkr-1", Alive: true}}
	stub.roles = cluster.RaftRoles{Servers: map[string]bool{"srv-1": true}, Leader: "srv-1"}
	rr := serve(nodeRoutesMux(t, stub), http.MethodGet, "/v1/cluster/members")
	var body struct {
		Members []cluster.Member `json:"members"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &body) != nil || len(body.Members) != 2 {
		t.Fatalf("members = %d %s", rr.Code, rr.Body.String())
	}
	srv, wkr := body.Members[0], body.Members[1]
	if !srv.Voter || !srv.Leader || srv.Version != "v0.6.12" || wkr.Voter || wkr.Leader {
		t.Fatalf("members = %+v", body.Members)
	}
}

// A deleted node may still be running and gossiping until someone stops the
// machine. It is not a member any more: the members list leaves it out, so
// `aerolvm get nodes` stops showing it the moment the delete returns.
func TestMembersListLeavesOutDeletedNodes(t *testing.T) {
	stub := newNodeStub()
	stub.members = []cluster.Member{{NodeID: "srv-1", Alive: true}, {NodeID: "wkr-gone", Alive: true}, {NodeID: "wkr-2", Alive: true}}
	stub.deniedIDs = map[string]bool{"wkr-gone": true}
	rr := serve(nodeRoutesMux(t, stub), http.MethodGet, "/v1/cluster/members")
	var got struct {
		Members []cluster.Member `json:"members"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil {
		t.Fatalf("GET members = %d %s", rr.Code, rr.Body.String())
	}
	var ids []string
	for _, m := range got.Members {
		ids = append(ids, m.NodeID)
	}
	if strings.Join(ids, ",") != "srv-1,wkr-2" {
		t.Fatalf("members = %v, want the deleted wkr-gone left out", ids)
	}
}

// A read of a deleted node is a 404 that says why.
func TestGetNodeRouteDeletedNode(t *testing.T) {
	stub := newNodeStub()
	stub.detailErr = cluster.ErrNodeDeleted
	rr := serve(nodeRoutesMux(t, stub), http.MethodGet, "/v1/cluster/nodes/wkr-gone")
	if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "deleted") {
		t.Fatalf("GET deleted node = %d %s, want 404 naming the delete", rr.Code, rr.Body.String())
	}
}

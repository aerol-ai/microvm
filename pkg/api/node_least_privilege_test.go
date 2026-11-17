package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// Node certificates get only what their role needs. A worker's or
// gateway's certificate (or one whose role cannot be read) holds
// cluster.internal and nothing else, except the public routes below, each
// granted for one call the cluster makes as a node. Adding to this list is
// a security decision a reviewer must see.
var nodeGrantedRoutes = map[string]string{
	"GET /v1/capacity":                      "a server reads each owner's capacity as itself (capacity leases)",
	"GET /v1/sandboxes/{id}":                "the SSH gateway reads a sandbox's row through its node to check a key; never with include_env",
	"/v1/sandboxes/{id}/sessions":           "SSH-bridged sessions, only with the gateway marker for that sandbox",
	"/v1/sandboxes/{id}/sessions/{path...}": "SSH-bridged sessions, only with the gateway marker for that sandbox",
	"GET /v1/cluster/members":               "workers and gateways read membership as themselves",
	"GET /v1/cluster/leader":                "workers and gateways read the leader as themselves",
	"DELETE /v1/cluster/members/{id}":       "a node removes itself, only itself",
	"GET /v1/cluster/nodes/{id}":            "a node reads itself, only itself",
}

// limitedNodeRoles are the roles whose certificate holds no fleet powers;
// "" is a certificate whose role cannot be read (one signed before roles).
var limitedNodeRoles = []string{controlplane.NodeRoleWorker, controlplane.NodeRoleIngress, ""}

// asNode makes req a call a peer makes as itself over the internal
// listener: its certificate for role, no bearer, the listener's mark.
func asNode(req *http.Request, peer, role string) *http.Request {
	req.TLS = peerTLSRole(peer, role)
	return req.WithContext(cluster.ContextWithInternalPeer(req.Context(), peer))
}

// Every route on every surface (v1, Daytona, E2B, Runloop, MCP, the
// dashboard), called by a worker's, a gateway's or an unknown role's
// certificate with no bearer, is refused with the node's 403 unless it is
// cluster.internal, needs only a principal, or is on nodeGrantedRoutes. A
// server's certificate holds every permission. The routes that carry a
// node grant are exactly the pinned list.
func TestNodeCertificatesGetOnlyWhatTheirRoleNeeds(t *testing.T) {
	server := matrixServer()
	routes := registeredRoutes(t, server)
	granted := map[string]bool{}
	refused := map[string]int{}
	for pattern, h := range routes {
		rh, ok := apihttp.RouteOf(h)
		if !ok {
			continue
		}
		if rh.NodeGrant() != nil {
			granted[pattern] = true
			if _, pinned := nodeGrantedRoutes[pattern]; !pinned {
				t.Errorf("%s grants node certificates; pin it in nodeGrantedRoutes with the call that needs it", pattern)
			}
		}
		for _, sample := range sampleRequests(pattern) {
			perm := rh.PermissionFor(sample)
			if !controlplane.NodeAccess("srv-1", controlplane.NodeRoleServer).Can(perm) && perm != controlplane.PermAuthenticated {
				t.Errorf("%s: a server's certificate lacks %s", pattern, perm)
			}
			if perm == controlplane.PermClusterInternal || perm == controlplane.PermAuthenticated || granted[pattern] {
				continue
			}
			for _, role := range limitedNodeRoles {
				access := controlplane.NodeAccess("peer-x", role)
				req := asNode(sample.Clone(sample.Context()), "peer-x", role)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				checkDenial(t, pattern, req, "node:"+role, access, perm, rec)
				refused[role]++
			}
		}
	}
	for pattern := range nodeGrantedRoutes {
		if !granted[pattern] {
			t.Errorf("nodeGrantedRoutes pins %s, which grants node certificates nothing", pattern)
		}
	}
	for _, role := range limitedNodeRoles {
		if refused[role] < 100 {
			t.Errorf("role %q was refused only %d calls: the matrix is vacuous", role, refused[role])
		}
	}
	t.Logf("refused cells per node role: %v", refused)
}

// nodeRoleCluster is a server node's cluster for the end-to-end table:
// every peer below is a live member, and the admitted roles come from the
// peers' certificates (an Agent-like reader, as on a worker).
type nodeRoleCluster struct{ *cluster.Noop }

func (c *nodeRoleCluster) LookupMember(id string) (cluster.Member, bool) {
	switch id {
	case "srv-2", "wkr-1", "gw-1", "old-1":
		return cluster.Member{NodeID: id, Alive: true}, true
	}
	return c.Noop.LookupMember(id)
}

func (c *nodeRoleCluster) IsJoinWritePeer(id string) bool  { return id == "srv-2" }
func (c *nodeRoleCluster) IsTokenWritePeer(id string) bool { return id == "srv-2" }

// The fleet calls of the table test, with another team's sandbox.
var fleetCalls = []struct{ method, path, body string }{
	{http.MethodPost, "/v1/sandboxes", `{"image":"alpine"}`},
	{http.MethodGet, "/v1/sandboxes", ""},
	{http.MethodGet, "/v1/sandboxes/sb-other?include_env=true", ""},
	{http.MethodDelete, "/v1/sandboxes/sb-other", ""},
	{http.MethodPost, "/v1/sandboxes/sb-other/stop", ""},
	{http.MethodPost, "/v1/sandboxes/sb-other/toolbox/process/execute", `{"command":"id"}`},
	{http.MethodPost, "/v1/sandboxes/sb-other/sessions", `{}`},
	{http.MethodPost, "/v1/sandboxes/sb-other/tokens", `{"ttl":"1h"}`},
	{http.MethodPost, "/v1/cluster/join-tokens", `{"role":"worker","ttl":"0","reusable":true}`},
	{http.MethodPost, "/v1/cluster/join-tokens", `{"role":"ingress"}`},
	{http.MethodPost, "/v1/cluster/join-tokens", `{"role":"server","ttl":"1h"}`},
	{http.MethodGet, "/v1/cluster/join-tokens", ""},
	{http.MethodDelete, "/v1/cluster/join-tokens/abcdef", ""},
	{http.MethodPut, "/v1/identity/roles/deploy?team=payments", `{"min_role":"runner"}`},
	{http.MethodDelete, "/v1/identity/roles/deploy?team=payments", ""},
	{http.MethodPost, "/v1/identity/keys/rotate", ""},
	{http.MethodPost, "/v1/tokens", `{"name":"x","role":"admin","team":"*","expires_in":"1h"}`},
	{http.MethodDelete, "/v1/cluster/nodes/n9", ""},
	{http.MethodPost, "/v1/cluster/nodes/n9/drain", ""},
	{http.MethodDelete, "/v1/cluster/members/n9", ""},
	{http.MethodPost, "/v1/cluster/nodes/n9/storage-retired", `{"reason":"x"}`},
	{http.MethodPut, "/v1/teams/payments/quota", `{"max_sandboxes":0}`},
	{http.MethodPut, "/v1/egress-profiles/open", `{"allow_out":["*"]}`},
	{http.MethodPut, "/v1/warm-pools/alpine", `{"depth":50}`},
	{http.MethodPost, "/v1/templates", `{}`},
	{http.MethodPost, "/v1/admin/reconcile", ""},
	{http.MethodGet, "/debug/vars", ""},
	{http.MethodGet, "/v1/metrics", ""},
	{http.MethodPost, "/daytona/sandbox", `{}`},
	{http.MethodPost, "/e2b/sandboxes", `{}`},
	{http.MethodPost, "/runloop/v1/devboxes", `{}`},
}

const nodeRefusal = "may not make this call as itself"

// serverNodeHandler is a server node's API with a store, whose cluster is
// nodeRoleCluster.
func serverNodeHandler(t *testing.T, cfg config.Config) http.Handler {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(cfg, discardLogger(), st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&nodeRoleCluster{Noop: cluster.NewNoop("srv-1", "http://srv-1", "")})
	return NewServer(discardLogger(), svc, nil, nil, cfg, "operator-pat-token", nil).Handler()
}

// serveRecover serves req and reports whether a handler panicked: in this
// harness a handler that reaches the container engine has none, which says
// the call got past authorization.
func serveRecover(h http.Handler, req *http.Request) (rec *httptest.ResponseRecorder, panicked bool) {
	rec = httptest.NewRecorder()
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	h.ServeHTTP(rec, req)
	return rec, false
}

// The end-to-end table: each role's certificate, no bearer, on a server's
// API through the internal listener's mark. A worker and a gateway are
// refused every fleet call with the node's 403 and nothing runs; a server
// gets past the role check on every one (its handler then answers as it
// always did). A certificate whose role cannot be read is a worker.
func TestNodeCertificateFleetCallsByRole(t *testing.T) {
	cfg := config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer, PATToken: "operator-pat-token", IdentityEnabled: true}
	h := serverNodeHandler(t, cfg)
	for _, peer := range []struct{ id, role string }{
		{"srv-2", controlplane.NodeRoleServer}, {"wkr-1", controlplane.NodeRoleWorker},
		{"gw-1", controlplane.NodeRoleIngress}, {"old-1", ""},
	} {
		for _, call := range fleetCalls {
			name := peer.id + " " + call.method + " " + call.path
			req := asNode(httptest.NewRequest(call.method, call.path, strings.NewReader(call.body)), peer.id, peer.role)
			req.RemoteAddr = "10.0.0.9:7002"
			rec, panicked := serveRecover(h, req)
			body := rec.Body.String()
			if peer.role == controlplane.NodeRoleServer {
				// Past the role check the handler runs as it always did; in
				// this harness some have no engine and stop there (panicked).
				if strings.Contains(body, nodeRefusal) || rec.Code == http.StatusUnauthorized {
					t.Errorf("%s: a server's certificate was refused: %d %s", name, rec.Code, body)
				}
				_ = panicked
				continue
			}
			if panicked {
				t.Errorf("%s: a handler ran for a %q certificate", name, peer.role)
				continue
			}
			if rec.Code != http.StatusForbidden || !strings.Contains(body, nodeRefusal) {
				t.Errorf("%s: %d %s, want the node's 403", name, rec.Code, body)
			}
		}
	}
}

// What a worker's or gateway's certificate still does as itself, by the
// map of calls the cluster makes: membership, the leader, a node's
// capacity, a sandbox's row for the SSH gateway's key check, a bridged SSH
// session, and leaving or reading itself. Each gets past the role check
// (its handler answers as it always did); the same call about another
// node, a row with its env, or a session without the gateway's marker is
// refused.
func TestNodeCertificateGrantedCalls(t *testing.T) {
	h := serverNodeHandler(t, config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer, PATToken: "operator-pat-token"})
	bridge := func(r *http.Request) {
		r.Header.Set(cluster.HeaderForwarded, "1")
		r.Header.Set(cluster.HeaderCaller, cluster.CallerNode)
		r.Header.Set(cluster.HeaderSSHGateway, auditlog.SSHGatewayCall{SandboxID: "sb-1"}.Encode())
	}
	for _, tc := range []struct {
		method, path string
		set          func(*http.Request)
		allowed      bool
	}{
		{http.MethodGet, "/v1/cluster/members", nil, true},
		{http.MethodGet, "/v1/cluster/leader", nil, true},
		{http.MethodGet, "/v1/capacity", nil, true},
		{http.MethodGet, "/v1/sandboxes/sb-1", nil, true},
		{http.MethodGet, "/v1/sandboxes/sb-1?include_env=true", nil, false},
		{http.MethodPost, "/v1/sandboxes/sb-1/sessions", bridge, true},
		{http.MethodGet, "/v1/sandboxes/sb-1/sessions/s1/attach", bridge, true},
		{http.MethodPost, "/v1/sandboxes/sb-2/sessions", bridge, false},
		{http.MethodPost, "/v1/sandboxes/sb-1/sessions", nil, false},
		{http.MethodDelete, "/v1/cluster/members/SELF", nil, true},
		{http.MethodGet, "/v1/cluster/nodes/SELF", nil, true},
		{http.MethodDelete, "/v1/cluster/members/other", nil, false},
		{http.MethodGet, "/v1/cluster/nodes/other", nil, false},
		{http.MethodDelete, "/v1/cluster/nodes/SELF", nil, false},
	} {
		for _, peer := range []struct{ id, role string }{{"wkr-1", controlplane.NodeRoleWorker}, {"gw-1", controlplane.NodeRoleIngress}} {
			path := strings.ReplaceAll(tc.path, "SELF", peer.id)
			req := asNode(httptest.NewRequest(tc.method, path, strings.NewReader("{}")), peer.id, peer.role)
			req.RemoteAddr = "10.0.0.9:7002"
			if tc.set != nil {
				tc.set(req)
			}
			rec, _ := serveRecover(h, req)
			refused := rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), nodeRefusal)
			if refused == tc.allowed {
				t.Errorf("%s %s %s: %d %s, allowed=%v", peer.role, tc.method, path, rec.Code, rec.Body.String(), tc.allowed)
			}
		}
	}
}

// A forward that speaks for a Kubernetes user (the agent-sandbox API) is
// honoured only from a node whose role runs that API (a gateway, or a
// server) and only on the calls that API makes: create, delete, start and
// stop. A worker's stamp, or one on any other route, is a 401 like any
// malformed one.
func TestOnBehalfOnlyFromGatewaysAndServers(t *testing.T) {
	for _, tc := range []struct {
		role    string
		pattern string
		want    bool
	}{
		{controlplane.NodeRoleIngress, "DELETE /v1/sandboxes/{id}", true},
		{controlplane.NodeRoleIngress, "POST /v1/sandboxes", true},
		{controlplane.NodeRoleIngress, "POST /v1/sandboxes/{id}/start", true},
		{controlplane.NodeRoleIngress, "POST /v1/sandboxes/{id}/stop", true},
		{controlplane.NodeRoleServer, "DELETE /v1/sandboxes/{id}", true},
		{controlplane.NodeRoleWorker, "DELETE /v1/sandboxes/{id}", false},
		{"", "DELETE /v1/sandboxes/{id}", false},
		{controlplane.NodeRoleIngress, "GET /v1/sandboxes/{id}", false},
		{controlplane.NodeRoleIngress, "/v1/sandboxes/{id}/toolbox/{path...}", false},
		{controlplane.NodeRoleIngress, "GET /v1/sandboxes", false},
		{controlplane.NodeRoleIngress, "GET /v1/whoami", false},
	} {
		req := asNode(httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1", nil), "peer-x", tc.role)
		req.Pattern = tc.pattern
		req.Header.Set(cluster.HeaderForwarded, "1")
		req.Header.Set(cluster.HeaderCaller, cluster.CallerNode)
		req.Header.Set(cluster.HeaderOnBehalfOf, "kubernetes:ana")
		req.Header.Set(cluster.HeaderOnBehalfOwner, "team:payments")
		access, ok := nodeCertAccess(req, func(r *http.Request, _ string) string { return cluster.ExtractPeerRole(r.TLS.PeerCertificates[0]) })
		if ok != tc.want {
			t.Fatalf("on-behalf from a %q node on %s = %v, want %v", tc.role, tc.pattern, ok, tc.want)
		}
		if ok && (access.Principal.Kind != controlplane.PrincipalKubernetes || access.Role != controlplane.RoleRunner || access.Identity.OwnerRef != "team:payments") {
			t.Fatalf("on-behalf access = %+v", access)
		}
	}
	// A node's own call (no on-behalf stamp) keeps its role.
	req := asNode(httptest.NewRequest(http.MethodGet, "/", nil), "peer-x", controlplane.NodeRoleWorker)
	if access, ok := nodeCertAccess(req, nil); !ok || !access.NodeLimited() || access.NodeRole != "" {
		t.Fatalf("no role reader = %+v %v, want the least", access, ok)
	}
}

// The server's role lookup (cluster.PeerRole through Server.nodeRole):
// with no cluster the certificate's role is all there is.
func TestServerNodeRoleReadsTheCertificate(t *testing.T) {
	s := &Server{}
	for _, role := range []string{controlplane.NodeRoleServer, controlplane.NodeRoleWorker, ""} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.TLS = peerTLSRole("p1", role)
		if got := s.nodeRole(req, "p1"); got != role {
			t.Fatalf("nodeRole(%q) = %q", role, got)
		}
	}
	if got := s.nodeRole(httptest.NewRequest(http.MethodGet, "/", nil).WithContext(context.Background()), "p1"); got != "" {
		t.Fatalf("no certificate = %q", got)
	}
}

// An operator's call a worker or gateway sends on to a server carries the
// operator's own token and the forward marker: the server takes the
// operator, not the node, so the role check does not touch it. This is
// what a new worker or gateway sends, and the shape every earlier server
// already accepts (the forwarded-token path is unchanged). The same call
// a node makes as itself is refused.
func TestForwardedOperatorCallsPassOnServers(t *testing.T) {
	cfg := config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer, PATToken: "operator-pat-token", IdentityEnabled: true}
	h := serverNodeHandler(t, cfg)
	for _, call := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/cluster/join-tokens", `{"role":"worker"}`},
		{http.MethodGet, "/v1/cluster/join-tokens", ""},
		{http.MethodDelete, "/v1/cluster/nodes/n9", ""},
		{http.MethodPost, "/v1/cluster/nodes/n9/drain", ""},
		{http.MethodDelete, "/v1/cluster/members/n9", ""},
		{http.MethodPost, "/v1/cluster/nodes/n9/storage-retired", `{"reason":"x"}`},
		{http.MethodPut, "/v1/identity/roles/deploy?team=payments", `{"min_role":"runner"}`},
		{http.MethodPut, "/v1/teams/payments/quota", `{"max_sandboxes":3}`},
	} {
		for _, peer := range []struct{ id, role string }{{"wkr-1", controlplane.NodeRoleWorker}, {"gw-1", controlplane.NodeRoleIngress}} {
			req := httptest.NewRequest(call.method, call.path, strings.NewReader(call.body))
			req.RemoteAddr = "10.0.0.9:7002"
			req.TLS = peerTLSRole(peer.id, peer.role)
			req.Header.Set("Authorization", "Bearer operator-pat-token")
			req.Header.Set(cluster.HeaderForwarded, "1")
			rec, _ := serveRecover(h, req)
			if strings.Contains(rec.Body.String(), nodeRefusal) || rec.Code == http.StatusUnauthorized {
				t.Errorf("%s forwarded %s %s: %d %s", peer.role, call.method, call.path, rec.Code, rec.Body.String())
			}
		}
	}
}

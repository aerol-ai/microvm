package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A worker or ingress node joined without the operator PAT
// (config/pat_verifier.go): it holds the PAT's hash and a token of its
// own. operatorPAT is the cluster's PAT, nodeLocalToken this node's.
const (
	operatorPAT    = "operator-pat-token"
	nodeLocalToken = "node-local-token"
)

// patFreeServer is such a node in a cluster whose only live peer is
// peer-test.
func patFreeServer(t *testing.T, scope string) *Server {
	t.Helper()
	cfg := config.Config{EnableCluster: true, IdentityEnabled: true, PATScope: scope,
		PATToken: nodeLocalToken, PATTokenSHA256: []string{config.PATSHA256(operatorPAT)}}
	svc := service.New(cfg, discardLogger(), nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&apiLivePeerCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
	srv := NewServer(discardLogger(), svc, nil, nil, cfg, nodeLocalToken, nil,
		WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens()))
	if srv.patToken != "" || srv.localToken != nodeLocalToken {
		t.Fatalf("a node whose token is not the PAT kept it as the PAT: pat %q local %q", srv.patToken, srv.localToken)
	}
	return srv
}

// patFreeRequest is one request to such a node.
type patFreeRequest struct {
	patScopeRequest
	// internal is the peer the internal listener vouched for
	// (cluster.ContextWithInternalPeer); "" for any other listener.
	internal string
	// header is one more header to send, "Name: value" split in two.
	header [2]string
}

func (p patFreeRequest) serve(srv *Server) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
	req.RemoteAddr = p.remote
	if p.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+p.bearer)
	}
	if p.peer {
		req.TLS = peerTLS("peer-test")
	}
	if p.forwarded {
		req.Header.Set(cluster.HeaderForwarded, "1")
	}
	if p.clientIP != "" {
		req.Header.Set(HeaderClientIP, p.clientIP)
	}
	if p.header[0] != "" {
		req.Header.Set(p.header[0], p.header[1])
	}
	if p.internal != "" {
		req = req.WithContext(cluster.ContextWithInternalPeer(req.Context(), p.internal))
	}
	h := srv.Handler()
	if p.socket {
		h = srv.PublicHandler()
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestPATFreeNodeAuth: such a node accepts the operator PAT by its hash
// under the same scope rules as before, takes its own token only from a
// local tool, and knows a peer with no bearer by the cert the internal
// listener vouched for.
func TestPATFreeNodeAuth(t *testing.T) {
	type want struct {
		status int
		kind   controlplane.PrincipalKind
		id     string
	}
	operator := want{http.StatusOK, controlplane.PrincipalOperator, "operator"}
	node := want{http.StatusOK, controlplane.PrincipalNode, "node:peer-test"}
	refused := want{status: http.StatusUnauthorized}
	loopback, remote, peerAddr := "127.0.0.1:5555", "10.0.0.5:4000", "10.0.0.9:7002"
	cases := []struct {
		name string
		req  patFreeRequest
		any  want
		host want
	}{
		// The operator PAT, by its hash.
		{"the PAT from a remote caller", patFreeRequest{patScopeRequest: patScopeRequest{remote: remote, bearer: operatorPAT}}, operator, refused},
		{"the PAT from a loopback caller", patFreeRequest{patScopeRequest: patScopeRequest{remote: loopback, bearer: operatorPAT}}, operator, operator},
		{"the PAT from a peer acting for itself (an older node)", patFreeRequest{patScopeRequest: patScopeRequest{remote: peerAddr, peer: true, bearer: operatorPAT}, internal: "peer-test"}, node, node},
		{"a wrong token", patFreeRequest{patScopeRequest: patScopeRequest{remote: loopback, bearer: "nope"}}, refused, refused},
		// The node's own token: a local tool only.
		{"own token from a local tool", patFreeRequest{patScopeRequest: patScopeRequest{remote: loopback, bearer: nodeLocalToken}}, operator, operator},
		{"own token from IPv6 loopback", patFreeRequest{patScopeRequest: patScopeRequest{remote: "[::1]:5555", bearer: nodeLocalToken}}, operator, operator},
		{"own token through Caddy (X-Forwarded-For)", patFreeRequest{patScopeRequest: patScopeRequest{remote: loopback, bearer: nodeLocalToken},
			header: [2]string{"X-Forwarded-For", "203.0.113.9"}}, refused, refused},
		{"own token through Caddy (X-Forwarded-Host)", patFreeRequest{patScopeRequest: patScopeRequest{remote: loopback, bearer: nodeLocalToken},
			header: [2]string{"X-Forwarded-Host", "api.example.com"}}, refused, refused},
		{"own token with Caddy's client address", patFreeRequest{patScopeRequest: patScopeRequest{remote: loopback, clientIP: "203.0.113.9", bearer: nodeLocalToken}}, refused, refused},
		{"own token from a remote caller", patFreeRequest{patScopeRequest: patScopeRequest{remote: remote, bearer: nodeLocalToken}}, refused, refused},
		{"own token on the public socket", patFreeRequest{patScopeRequest: patScopeRequest{socket: true, remote: loopback, bearer: nodeLocalToken}}, refused, refused},
		{"own token from a peer", patFreeRequest{patScopeRequest: patScopeRequest{remote: peerAddr, peer: true, bearer: nodeLocalToken}, internal: "peer-test"}, refused, refused},
		{"own token in a forward", patFreeRequest{patScopeRequest: patScopeRequest{remote: peerAddr, peer: true, forwarded: true, bearer: nodeLocalToken}, internal: "peer-test"}, refused, refused},
		// A peer with no bearer.
		{"a peer's cert alone, vouched for by the internal listener", patFreeRequest{patScopeRequest: patScopeRequest{remote: peerAddr, peer: true}, internal: "peer-test"}, node, node},
		{"a peer's cert alone, without the listener's mark", patFreeRequest{patScopeRequest: patScopeRequest{remote: peerAddr, peer: true}}, refused, refused},
		{"a mark that names another node than the cert", patFreeRequest{patScopeRequest: patScopeRequest{remote: peerAddr, peer: true}, internal: "peer-other"}, refused, refused},
		{"a mark with no cert", patFreeRequest{patScopeRequest: patScopeRequest{remote: peerAddr}, internal: "peer-test"}, refused, refused},
		{"a forward that lost the user's credential", patFreeRequest{patScopeRequest: patScopeRequest{remote: peerAddr, peer: true, forwarded: true}, internal: "peer-test"}, refused, refused},
		{"a forward the edge speaks for itself", patFreeRequest{patScopeRequest: patScopeRequest{remote: peerAddr, peer: true, forwarded: true}, internal: "peer-test",
			header: [2]string{cluster.HeaderCaller, cluster.CallerNode}}, node, node},
		{"a peer's unknown bearer is not dropped for its cert", patFreeRequest{patScopeRequest: patScopeRequest{remote: peerAddr, peer: true, bearer: "nope"}, internal: "peer-test"}, refused, refused},
		{"no bearer on the API listener", patFreeRequest{patScopeRequest: patScopeRequest{remote: loopback}}, refused, refused},
	}
	for _, scope := range []string{config.PATScopeAny, config.PATScopeHost} {
		srv := patFreeServer(t, scope)
		for _, tc := range cases {
			t.Run(scope+"/"+tc.name, func(t *testing.T) {
				w := tc.any
				if scope == config.PATScopeHost {
					w = tc.host
				}
				rec := tc.req.serve(srv)
				if rec.Code != w.status {
					t.Fatalf("status = %d, want %d; body %s", rec.Code, w.status, rec.Body.String())
				}
				if w.status != http.StatusOK {
					return
				}
				var got models.WhoAmI
				if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if got.Principal.Kind != string(w.kind) || got.Principal.ID != w.id {
					t.Fatalf("principal = %+v, want %s %s", got.Principal, w.kind, w.id)
				}
			})
		}
	}
}

// A refused local token counts under its own reason, and its 401 says no
// more than any other.
func TestPATFreeLocalTokenRefusal(t *testing.T) {
	srv := patFreeServer(t, config.PATScopeAny)
	before := authFailureCount("operator", "local_only")
	rec := patFreeRequest{patScopeRequest: patScopeRequest{remote: "10.0.0.5:4000", bearer: nodeLocalToken}}.serve(srv)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	var body models.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error != "unauthorized" {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if got := authFailureCount("operator", "local_only"); got != before+1 {
		t.Fatalf("aerolvm_auth_failures_total{operator,local_only} = %d, want %d", got, before+1)
	}
}

// A request a local tool made with the node's own token is marked, so a
// forward of it goes as the node; the PAT and a peer's call are not.
func TestPATFreeLocalCallerMark(t *testing.T) {
	srv := patFreeServer(t, config.PATScopeAny)
	var marked bool
	h := srv.requireAuth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		marked = cluster.LocalCallerFromContext(r.Context())
	}))
	for _, tc := range []struct {
		name   string
		bearer string
		want   bool
	}{
		{"own token", nodeLocalToken, true},
		{"the operator PAT", operatorPAT, false},
	} {
		marked = false
		req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
		req.RemoteAddr = "127.0.0.1:5555"
		req.Header.Set("Authorization", "Bearer "+tc.bearer)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || marked != tc.want {
			t.Fatalf("%s: status %d marked %v, want %v", tc.name, rec.Code, marked, tc.want)
		}
	}
	// End to end: the edge's forward of the marked request carries no
	// credential and says the node speaks for it.
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1", nil)
	req.Header.Set("Authorization", "Bearer "+nodeLocalToken)
	out := req.WithContext(cluster.ContextWithLocalCaller(context.Background()))
	cluster.StampForward(out, controlplane.OperatorAccess())
	if out.Header.Get("Authorization") != "" || out.Header.Get(cluster.HeaderCaller) != cluster.CallerNode {
		t.Fatalf("forward headers = %v", out.Header)
	}
}

// TestNewServerKeepsAListedPAT: a node whose own token is the listed PAT
// (one that holds the PAT and has the hash too) keeps it as the PAT.
func TestNewServerKeepsAListedPAT(t *testing.T) {
	srv := NewServer(discardLogger(), nil, nil, nil, config.Config{PATTokenSHA256: []string{config.PATSHA256(operatorPAT)}}, operatorPAT, nil)
	if srv.patToken != operatorPAT || srv.localToken != "" {
		t.Fatalf("pat %q local %q", srv.patToken, srv.localToken)
	}
}

// An SSH gateway forward from a node without the PAT reaches the owner as
// the edge node; the owner honours the gateway marker on that forward only.
func TestSSHGatewayCallFromANode(t *testing.T) {
	call := auditlog.SSHGatewayCall{SandboxID: "sb-1"}
	mk := func(forwarded bool) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1/sessions", nil)
		req.SetPathValue("id", "sb-1")
		req.Pattern = "GET /v1/sandboxes/{id}/sessions"
		req.TLS = peerTLS("peer-test")
		req.Header.Set(cluster.HeaderSSHGateway, call.Encode())
		if forwarded {
			req.Header.Set(cluster.HeaderForwarded, "1")
		}
		return req
	}
	if got, ok := sshGatewayCall(mk(true), controlplane.NodeAccess("peer-test")); !ok || got.SandboxID != "sb-1" {
		t.Fatalf("a node's forward = %+v %v, want the call", got, ok)
	}
	if _, ok := sshGatewayCall(mk(false), controlplane.NodeAccess("peer-test")); ok {
		t.Fatal("a node calling as itself was taken for a gateway call")
	}
	if _, ok := sshGatewayCall(mk(true), controlplane.Access{Principal: controlplane.Principal{Kind: controlplane.PrincipalToken}}); ok {
		t.Fatal("a token's forward was taken for a gateway call")
	}
}

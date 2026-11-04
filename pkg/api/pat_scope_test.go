package api

import (
	"context"
	"encoding/json"
	"expvar"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// patScopeRequest is one request in the listener-split tables.
type patScopeRequest struct {
	socket    bool   // the public Unix socket (PublicHandler)
	remote    string // the TCP peer; "" keeps a socket's empty address
	peer      bool   // a verified mTLS cluster peer
	forwarded bool   // X-Cluster-Forwarded: 1
	origin    string // X-Cluster-PAT-Origin
	clientIP  string // X-AerolVM-Client-IP
	bearer    string
}

// patScopeServer is a cluster node whose only live peer is peer-test.
func patScopeServer(t *testing.T, cfg config.Config) *Server {
	t.Helper()
	cfg.EnableCluster, cfg.IdentityEnabled = true, true
	svc := service.New(cfg, discardLogger(), nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&apiLivePeerCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
	return NewServer(discardLogger(), svc, nil, nil, cfg, "pat-token", nil,
		WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens()))
}

// serve sends GET /v1/whoami as described and returns the response.
func (p patScopeRequest) serve(srv *Server) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
	req.RemoteAddr = p.remote
	if p.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+p.bearer)
	}
	if p.peer {
		req.TLS = peerTLS("peer-test")
		req.Header.Set(cluster.PeerNodeIDHeader, "peer-test")
	}
	if p.forwarded {
		req.Header.Set(cluster.HeaderForwarded, "1")
	}
	if p.origin != "" {
		req.Header.Set(cluster.HeaderPATOrigin, p.origin)
	}
	if p.clientIP != "" {
		req.Header.Set(HeaderClientIP, p.clientIP)
	}
	h := srv.Handler()
	if p.socket {
		h = srv.PublicHandler()
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestPATScopeListenerSplit is the listener split of CEO review D4
// (plans/identity-and-access.md §5.11): under SB_PAT_SCOPE=host the PAT
// (current or previous) works from a loopback peer on the API listener and
// from mTLS cluster peers, and nowhere else; named credentials work
// everywhere. Under the default scope nothing changes (L8).
func TestPATScopeListenerSplit(t *testing.T) {
	type want struct {
		status int
		kind   controlplane.PrincipalKind
	}
	ok := func(kind controlplane.PrincipalKind) want { return want{http.StatusOK, kind} }
	refused := want{status: http.StatusUnauthorized}
	cases := []struct {
		name     string
		req      patScopeRequest
		host     want // SB_PAT_SCOPE=host
		any      want // the default
		trustIPs bool // SB_L4_FALLBACK_PROXY_PROTOCOL
	}{
		{name: "PAT from a loopback peer on 21212", req: patScopeRequest{remote: "127.0.0.1:5555", bearer: "pat-token"},
			host: ok(controlplane.PrincipalOperator), any: ok(controlplane.PrincipalOperator)},
		{name: "previous PAT from a loopback peer", req: patScopeRequest{remote: "[::1]:5555", bearer: "old-pat-token"},
			host: ok(controlplane.PrincipalOperator), any: ok(controlplane.PrincipalOperator)},
		{name: "PAT from a remote peer on 21212", req: patScopeRequest{remote: "10.0.0.5:4000", bearer: "pat-token"},
			host: refused, any: ok(controlplane.PrincipalOperator)},
		{name: "previous PAT from a remote peer", req: patScopeRequest{remote: "10.0.0.5:4000", bearer: "old-pat-token"},
			host: refused, any: ok(controlplane.PrincipalOperator)},
		{name: "PAT on the public socket", req: patScopeRequest{socket: true, bearer: "pat-token"},
			host: refused, any: ok(controlplane.PrincipalOperator)},
		{name: "PAT on the public socket with a loopback address", req: patScopeRequest{socket: true, remote: "127.0.0.1:5555", bearer: "pat-token"},
			host: refused, any: ok(controlplane.PrincipalOperator)},
		{name: "PAT through Caddy on loopback TCP (PROXY protocol on)", trustIPs: true,
			req:  patScopeRequest{remote: "127.0.0.1:5555", clientIP: "203.0.113.9", bearer: "pat-token"},
			host: refused, any: ok(controlplane.PrincipalOperator)},
		{name: "a client-set X-AerolVM-Client-IP means nothing with PROXY protocol off",
			req:  patScopeRequest{remote: "127.0.0.1:5555", clientIP: "203.0.113.9", bearer: "pat-token"},
			host: ok(controlplane.PrincipalOperator), any: ok(controlplane.PrincipalOperator)},
		{name: "PAT from an mTLS peer on its own behalf", req: patScopeRequest{remote: "10.0.0.9:7002", peer: true, bearer: "pat-token"},
			host: ok(controlplane.PrincipalNode), any: ok(controlplane.PrincipalNode)},
		{name: "PAT a peer forwarded from a host origin", req: patScopeRequest{remote: "10.0.0.9:7002", peer: true, forwarded: true, origin: "host", bearer: "pat-token"},
			host: ok(controlplane.PrincipalOperator), any: ok(controlplane.PrincipalOperator)},
		{name: "PAT a peer forwarded from a public origin", req: patScopeRequest{remote: "10.0.0.9:7002", peer: true, forwarded: true, origin: "public", bearer: "pat-token"},
			host: refused, any: ok(controlplane.PrincipalOperator)},
		{name: "PAT a peer forwarded with no origin (an older build)", req: patScopeRequest{remote: "10.0.0.9:7002", peer: true, forwarded: true, bearer: "pat-token"},
			host: refused, any: ok(controlplane.PrincipalOperator)},
		{name: "an avm_ token on the public socket", req: patScopeRequest{socket: true, bearer: "avm_payments"},
			host: ok(controlplane.PrincipalToken), any: ok(controlplane.PrincipalToken)},
		{name: "an avm_ token from a remote peer", req: patScopeRequest{remote: "10.0.0.5:4000", bearer: "avm_fleet"},
			host: ok(controlplane.PrincipalToken), any: ok(controlplane.PrincipalToken)},
		{name: "a wrong token stays a bare 401", req: patScopeRequest{remote: "127.0.0.1:5555", bearer: "nope"},
			host: refused, any: refused},
	}
	for _, scope := range []string{config.PATScopeHost, config.PATScopeAny} {
		for _, tc := range cases {
			t.Run(scope+"/"+tc.name, func(t *testing.T) {
				srv := patScopeServer(t, config.Config{PATScope: scope, PATTokenPrevious: "old-pat-token", L4FallbackProxyProtocol: tc.trustIPs})
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
				if got.Principal.Kind != string(w.kind) {
					t.Fatalf("principal = %+v, want kind %s", got.Principal, w.kind)
				}
			})
		}
	}
}

// TestPATMatchesPrevious is SB_PAT_TOKEN_PREVIOUS (H2): during a rotation
// both tokens are the PAT, an unset previous token matches nothing, and the
// E2B credential reader treats the previous PAT like the current one.
func TestPATMatchesPrevious(t *testing.T) {
	both := patAuthenticator{token: "new-pat", previous: "old-pat"}
	current := patAuthenticator{token: "new-pat"}
	cases := []struct {
		p    patAuthenticator
		in   string
		want bool
	}{
		{both, "new-pat", true},
		{both, "old-pat", true},
		{both, "old-pa", false},
		{both, "", false},
		{current, "old-pat", false},
		{current, "", false},
		{patAuthenticator{previous: "old-pat"}, "", false},
	}
	for _, tc := range cases {
		if got := tc.p.matches(tc.in); got != tc.want {
			t.Errorf("%+v.matches(%q) = %v, want %v", tc.p, tc.in, got, tc.want)
		}
	}
	srv := NewServer(discardLogger(), nil, nil, nil, config.Config{PATTokenPrevious: "old-pat"}, "new-pat", nil)
	req := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil)
	req.Header.Set("X-API-KEY", "old-pat")
	req.Header.Set("Authorization", "Bearer someone-else")
	if got := srv.e2bCredential(req); got != "old-pat" {
		t.Fatalf("e2b credential = %q, want the previous PAT to win like the current one", got)
	}
}

// TestPATScopeRefusalBody: a PAT refused under host scope gets a 401 that
// says what to use instead, on every surface in its own envelope, and counts
// under aerolvm_auth_failures_total{operator,pat_scope|pat_origin}. The bare
// PAT 401 bodies (TestUnauthorizedBodiesUnchanged) are untouched.
func TestPATScopeRefusalBody(t *testing.T) {
	srv := patScopeServer(t, config.Config{PATScope: config.PATScopeHost})
	before := authFailureCount("operator", "pat_scope")
	for _, tc := range []struct{ path, header, value string }{
		{"/v1/sandboxes", "Authorization", "Bearer pat-token"},
		{"/e2b/sandboxes", "X-API-KEY", "pat-token"},
		{"/runloop/v1/devboxes", "Authorization", "Bearer pat-token"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.RemoteAddr = "198.51.100.7:4000"
		req.Header.Set(tc.header, tc.value)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "the operator token works only on this host") {
			t.Fatalf("%s: %d %s", tc.path, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("%s: a PAT refusal is not an RFC 6750 token error", tc.path)
		}
	}
	if got := authFailureCount("operator", "pat_scope") - before; got != 3 {
		t.Fatalf("pat_scope failures counted %d, want 3", got)
	}
	before = authFailureCount("operator", "pat_origin")
	rec := patScopeRequest{remote: "10.0.0.9:7002", peer: true, forwarded: true, origin: "public", bearer: "pat-token"}.serve(srv)
	if rec.Code != http.StatusUnauthorized || authFailureCount("operator", "pat_origin")-before != 1 {
		t.Fatalf("forwarded public PAT: %d, counted %d", rec.Code, authFailureCount("operator", "pat_origin")-before)
	}
}

func authFailureCount(kind, reason string) int64 {
	inner, _ := authFailures.Get(kind).(*expvar.Map)
	if inner == nil {
		return 0
	}
	v, _ := inner.Get(reason).(*expvar.Int)
	if v == nil {
		return 0
	}
	return v.Value()
}

// TestPATOriginRecordedAtTheEdge: the edge records where it accepted a PAT,
// for the X-Cluster-PAT-Origin every forward of the request carries
// (cluster.StampForward); other credentials record nothing.
func TestPATOriginRecordedAtTheEdge(t *testing.T) {
	srv := patScopeServer(t, config.Config{L4FallbackProxyProtocol: true})
	cases := []struct {
		name string
		req  patScopeRequest
		want string
	}{
		{name: "loopback peer", req: patScopeRequest{remote: "127.0.0.1:5555", bearer: "pat-token"}, want: cluster.PATOriginHost},
		{name: "remote peer", req: patScopeRequest{remote: "10.0.0.5:4000", bearer: "pat-token"}, want: cluster.PATOriginPublic},
		{name: "public socket", req: patScopeRequest{socket: true, bearer: "pat-token"}, want: cluster.PATOriginPublic},
		{name: "Caddy relaying a public caller", req: patScopeRequest{remote: "127.0.0.1:5555", clientIP: "203.0.113.9", bearer: "pat-token"}, want: cluster.PATOriginPublic},
		{name: "a peer acting for itself", req: patScopeRequest{remote: "10.0.0.9:7002", peer: true, bearer: "pat-token"}, want: cluster.PATOriginHost},
		{name: "a forward keeps its host origin", req: patScopeRequest{remote: "10.0.0.9:7002", peer: true, forwarded: true, origin: "host", bearer: "pat-token"}, want: cluster.PATOriginHost},
		{name: "a forward keeps its public origin", req: patScopeRequest{remote: "10.0.0.9:7002", peer: true, forwarded: true, origin: "public", bearer: "pat-token"}, want: cluster.PATOriginPublic},
		{name: "a forward with no origin is public", req: patScopeRequest{remote: "10.0.0.9:7002", peer: true, forwarded: true, bearer: "pat-token"}, want: cluster.PATOriginPublic},
		{name: "a token has no PAT origin", req: patScopeRequest{remote: "127.0.0.1:5555", bearer: "avm_payments"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			var called bool
			h := srv.clusterControlHeaderGuard(srv.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, called = cluster.PATOriginFromContext(r.Context()), true
			})))
			req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
			req.RemoteAddr = tc.req.remote
			req.Header.Set("Authorization", "Bearer "+tc.req.bearer)
			if tc.req.peer {
				req.TLS = peerTLS("peer-test")
				req.Header.Set(cluster.PeerNodeIDHeader, "peer-test")
			}
			if tc.req.forwarded {
				req.Header.Set(cluster.HeaderForwarded, "1")
			}
			if tc.req.origin != "" {
				req.Header.Set(cluster.HeaderPATOrigin, tc.req.origin)
			}
			if tc.req.clientIP != "" {
				req.Header.Set(HeaderClientIP, tc.req.clientIP)
			}
			if tc.req.socket {
				req = req.WithContext(context.WithValue(req.Context(), publicListenerKey{}, true))
			}
			h.ServeHTTP(httptest.NewRecorder(), req)
			if !called || got != tc.want {
				t.Fatalf("origin = %q (handler reached %v), want %q", got, called, tc.want)
			}
		})
	}
}

// TestClientAddress is the X-AerolVM-Client-IP trust rule (§5.9, finding
// 3.4): with PROXY protocol on, the header from Caddy's socket or a
// loopback peer names the client; from any other peer, or when it is not an
// IP, it is dropped and counted; with the flag off it is never read.
func TestClientAddress(t *testing.T) {
	cases := []struct {
		name   string
		trust  bool
		req    patScopeRequest
		want   string
		counts bool // the header was dropped
	}{
		{name: "flag off: the TCP peer, header ignored", req: patScopeRequest{remote: "127.0.0.1:5555", clientIP: "203.0.113.9"}, want: "127.0.0.1"},
		{name: "flag on, no header: the TCP peer", trust: true, req: patScopeRequest{remote: "198.51.100.7:4000"}, want: "198.51.100.7"},
		{name: "flag on, Caddy on loopback TCP", trust: true, req: patScopeRequest{remote: "127.0.0.1:5555", clientIP: "203.0.113.9"}, want: "203.0.113.9"},
		{name: "flag on, Caddy on the public socket", trust: true, req: patScopeRequest{socket: true, clientIP: " 2001:db8::7 "}, want: "2001:db8::7"},
		{name: "an IPv4-mapped address is unmapped", trust: true, req: patScopeRequest{remote: "127.0.0.1:5555", clientIP: "::ffff:203.0.113.9"}, want: "203.0.113.9"},
		{name: "a remote caller picking its own address", trust: true, req: patScopeRequest{remote: "198.51.100.7:4000", clientIP: "10.1.1.1"}, want: "198.51.100.7", counts: true},
		{name: "a cluster peer never sets it", trust: true, req: patScopeRequest{remote: "10.0.0.9:7002", peer: true, clientIP: "10.1.1.1"}, want: "10.0.0.9", counts: true},
		{name: "not an IP", trust: true, req: patScopeRequest{remote: "127.0.0.1:5555", clientIP: "attacker.example"}, want: "127.0.0.1", counts: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.req.remote
			if tc.req.peer {
				req.TLS = peerTLS("n1")
			}
			if tc.req.clientIP != "" {
				req.Header.Set(HeaderClientIP, tc.req.clientIP)
			}
			if tc.req.socket {
				req = req.WithContext(context.WithValue(req.Context(), publicListenerKey{}, true))
			}
			before := authClientIPDropped.Value()
			if got := (&Server{l4ProxyProtocol: tc.trust}).clientAddress(req); got != tc.want {
				t.Fatalf("clientAddress = %q, want %q", got, tc.want)
			}
			if dropped := authClientIPDropped.Value() - before; (dropped == 1) != tc.counts || dropped > 1 {
				t.Fatalf("dropped counter moved by %d, want counted=%v", dropped, tc.counts)
			}
		})
	}
}

// TestAuthDeniedRecordsTheClientIP is the T5 hand-off: with PROXY protocol
// on, an auth_denied record names the caller Caddy saw, not 127.0.0.1, and
// two callers behind the same Caddy get their own per-address budgets.
func TestAuthDeniedRecordsTheClientIP(t *testing.T) {
	st := storeWith(t, "authdenied-ip")
	svc := service.New(config.Config{}, discardLogger(), st, nil, nil, nil, nil, nil, nil)
	sink := &recSink{}
	svc.UseAuditSinkForTest(sink)
	srv := NewServer(discardLogger(), svc, nil, nil, config.Config{L4FallbackProxyProtocol: true}, "pat-token", nil)
	for _, ip := range []string{"203.0.113.9", "203.0.113.10", "203.0.113.9"} {
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/stop", nil)
		req.RemoteAddr = "127.0.0.1:5555"
		req.Header.Set(HeaderClientIP, ip)
		req.Header.Set("Authorization", "Bearer wrong")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code %d", rec.Code)
		}
	}
	var sources []string
	for _, ev := range sink.records() {
		if ev.Kind == auditlog.KindAuthDenied {
			sources = append(sources, ev.Request.Source)
		}
	}
	if strings.Join(sources, ",") != "203.0.113.9,203.0.113.10" {
		t.Fatalf("auth_denied sources = %v, want one per client behind Caddy", sources)
	}
}

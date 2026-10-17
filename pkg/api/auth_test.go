package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// peerTLS is the connection state of a request that arrived over the
// cluster's mTLS listener from node id: a verified leaf with a node:<id> SAN.
func peerTLS(id string) *tls.ConnectionState {
	cert := &x509.Certificate{DNSNames: []string{"node:" + id}}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
}

// stubCredential stands in for the avm_ token mirror (T3) and the OIDC
// verifier (T6): it claims bearers with its prefix, accepts the ones it
// knows and refuses the rest with a D17 reason.
type stubCredential struct {
	prefix string
	kind   controlplane.PrincipalKind
	accept map[string]controlplane.Access
	reject map[string]controlplane.RejectReason
}

func (s stubCredential) Authenticate(_ *http.Request, bearer string) (controlplane.Access, bool, error) {
	if !strings.HasPrefix(bearer, s.prefix) {
		return controlplane.Access{}, false, nil
	}
	if a, ok := s.accept[bearer]; ok {
		return a, true, nil
	}
	reason, ok := s.reject[bearer]
	if !ok {
		reason = controlplane.RejectUnknownOrRevoked
	}
	return controlplane.Access{}, true, &controlplane.CredentialError{Kind: s.kind, Reason: reason}
}

func tokenAccess(team string, role controlplane.Role) controlplane.Access {
	a := controlplane.Access{
		Role:      role,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_7Hq2", Name: "ci-deploy"},
		ExpiresAt: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	if team == controlplane.FleetTeam {
		a.Fleet = true
	} else {
		a.Identity.OwnerRef = controlplane.TeamOwnerRef(team)
	}
	return a
}

// stubTokens is a token authenticator with one live token per case below.
func stubTokens() stubCredential {
	return stubCredential{
		prefix: "avm_",
		kind:   controlplane.PrincipalToken,
		accept: map[string]controlplane.Access{
			"avm_payments": tokenAccess("payments", controlplane.RoleRunner),
			"avm_fleet":    tokenAccess(controlplane.FleetTeam, controlplane.RoleViewer),
		},
		reject: map[string]controlplane.RejectReason{"avm_expired": controlplane.RejectExpired, "avm_bad": controlplane.RejectMalformed},
	}
}

// capture is a protected handler that records the Access auth attached.
type capture struct {
	access controlplane.Access
	ok     bool
	called bool
}

func (c *capture) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.access, c.ok = controlplane.AccessFromContext(r.Context())
		c.called = true
		w.WriteHeader(http.StatusNoContent)
	})
}

// TestPrincipalInvariants pins plans/identity-and-access.md §5.1's
// invariant table through the whole edge: the cluster-header guard, then
// authenticate. Each row is today's behavior under the new names.
func TestPrincipalInvariants(t *testing.T) {
	svc := service.New(config.Config{EnableCluster: true}, discardLogger(), nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&apiLivePeerCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
	validator := stubValidator{accept: "managed-token", identity: controlplane.Identity{OwnerRef: "acme", ExternalID: "ext-1"}}
	viewer := stubValidator{accept: "managed-viewer", identity: controlplane.Identity{OwnerRef: "acme", ExternalID: "ext-2", Role: controlplane.RoleViewer}}

	cases := []struct {
		name      string
		validator controlplane.Validator
		token     string
		peer      bool
		forwarded bool
		want      controlplane.Access
	}{
		{
			name:  "PAT on the public listener",
			token: "pat-token",
			want:  controlplane.OperatorAccess(),
		},
		{
			name: "PAT plus mTLS peer plus X-Cluster-Forwarded", token: "pat-token", peer: true, forwarded: true,
			want: func() controlplane.Access { a := controlplane.OperatorAccess(); a.Via = "peer-test"; return a }(),
		},
		{
			name: "PAT plus mTLS peer, not forwarded", token: "pat-token", peer: true,
			want: controlplane.NodeAccess("peer-test"),
		},
		{
			name: "managed provider token", validator: validator, token: "managed-token",
			want: controlplane.Access{
				Identity:  controlplane.Identity{OwnerRef: "acme", ExternalID: "ext-1"},
				Role:      controlplane.RoleRunner,
				Principal: controlplane.Principal{Kind: controlplane.PrincipalControlPlane, ID: "controlplane:ext-1", Name: "ext-1"},
			},
		},
		{
			name: "managed provider token with Identity.Role", validator: viewer, token: "managed-viewer",
			want: controlplane.Access{
				Identity:  controlplane.Identity{OwnerRef: "acme", ExternalID: "ext-2", Role: controlplane.RoleViewer},
				Role:      controlplane.RoleViewer,
				Principal: controlplane.Principal{Kind: controlplane.PrincipalControlPlane, ID: "controlplane:ext-2", Name: "ext-2"},
			},
		},
		{
			name: "managed provider token forwarded by a peer", validator: validator, token: "managed-token", peer: true, forwarded: true,
			want: controlplane.Access{
				Identity:  controlplane.Identity{OwnerRef: "acme", ExternalID: "ext-1"},
				Role:      controlplane.RoleRunner,
				Principal: controlplane.Principal{Kind: controlplane.PrincipalControlPlane, ID: "controlplane:ext-1", Name: "ext-1"},
				Via:       "peer-test",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := NewServer(discardLogger(), svc, nil, nil, config.Config{EnableCluster: true}, "pat-token", tc.validator)
			var c capture
			edge := server.clusterControlHeaderGuard(server.requireAuth(c.handler()))
			req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			if tc.peer {
				req.TLS = peerTLS("peer-test")
				req.Header.Set(cluster.PeerNodeIDHeader, "peer-test")
			}
			if tc.forwarded {
				req.Header.Set("X-Cluster-Forwarded", "1")
			}
			rec := httptest.NewRecorder()
			edge.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent || !c.ok {
				t.Fatalf("status %d, access attached %v; body %s", rec.Code, c.ok, rec.Body.String())
			}
			if !reflect.DeepEqual(c.access, tc.want) {
				t.Fatalf("access =\n %+v\nwant\n %+v", c.access, tc.want)
			}
		})
	}

	t.Run("no Access (background)", func(t *testing.T) {
		// Background loops never pass the edge; the service layer reads a
		// missing Access as unscoped (TestOwnerScope pins that side).
		if _, ok := controlplane.AccessFromContext(context.Background()); ok {
			t.Fatal("a background context must carry no Access")
		}
	})

	t.Run("forward markers from a caller are not trusted", func(t *testing.T) {
		// X-Cluster-Forwarded without a verified peer: the guard refuses it
		// in a cluster, so it can never turn a public PAT into Via.
		server := NewServer(discardLogger(), svc, nil, nil, config.Config{EnableCluster: true}, "pat-token", nil)
		var c capture
		req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
		req.Header.Set("Authorization", "Bearer pat-token")
		req.Header.Set("X-Cluster-Forwarded", "1")
		rec := httptest.NewRecorder()
		server.clusterControlHeaderGuard(server.requireAuth(c.handler())).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || c.called {
			t.Fatalf("unauthenticated forward marker = %d (handler reached %v), want 403", rec.Code, c.called)
		}
	})
}

func TestPATAuthenticator(t *testing.T) {
	pat := patAuthenticator{token: "pat-token"}
	cases := []struct {
		name        string
		bearer      string
		peer        bool
		forwarded   bool
		wantMatched bool
		wantKind    controlplane.PrincipalKind
	}{
		{name: "empty bearer", bearer: ""},
		{name: "other token passes on", bearer: "user-token"},
		{name: "prefix of the PAT is not the PAT", bearer: "pat-tok"},
		{name: "PAT from the public side is the operator", bearer: "pat-token", wantMatched: true, wantKind: controlplane.PrincipalOperator},
		{name: "PAT from a peer on its own behalf is the node", bearer: "pat-token", peer: true, wantMatched: true, wantKind: controlplane.PrincipalNode},
		{name: "PAT a peer forwarded is the operator", bearer: "pat-token", peer: true, forwarded: true, wantMatched: true, wantKind: controlplane.PrincipalOperator},
		{name: "forward marker without a peer is the operator", bearer: "pat-token", forwarded: true, wantMatched: true, wantKind: controlplane.PrincipalOperator},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.peer {
				req.TLS = peerTLS("n3")
			}
			if tc.forwarded {
				req.Header.Set("X-Cluster-Forwarded", "1")
			}
			access, matched, err := pat.Authenticate(req, tc.bearer)
			if err != nil {
				t.Fatalf("the PAT authenticator never refuses: %v", err)
			}
			if matched != tc.wantMatched || access.Principal.Kind != tc.wantKind {
				t.Fatalf("matched=%v kind=%q, want %v %q", matched, access.Principal.Kind, tc.wantMatched, tc.wantKind)
			}
			if matched && (!access.Fleet || access.Role != controlplane.RoleAdmin) {
				t.Fatalf("the PAT keeps today's powers: %+v", access)
			}
		})
	}
	if _, matched, _ := (patAuthenticator{}).Authenticate(httptest.NewRequest(http.MethodGet, "/", nil), ""); matched {
		t.Fatal("an unset PAT must never match an empty bearer")
	}
}

func TestProviderAuthenticator(t *testing.T) {
	cases := []struct {
		name        string
		identity    controlplane.Identity
		bearer      string
		wantMatched bool
		wantErr     error
		wantRole    controlplane.Role
	}{
		{name: "empty bearer is never validated", bearer: ""},
		{name: "rejected token", bearer: "nope", wantMatched: true, wantErr: controlplane.ErrTokenRejected},
		{name: "accepted token is a runner", bearer: "tok", identity: controlplane.Identity{OwnerRef: "acme"}, wantMatched: true, wantRole: controlplane.RoleRunner},
		{name: "provider may narrow to viewer", bearer: "tok", identity: controlplane.Identity{OwnerRef: "acme", Role: controlplane.RoleViewer}, wantMatched: true, wantRole: controlplane.RoleViewer},
		{name: "provider may not grant admin", bearer: "tok", identity: controlplane.Identity{OwnerRef: "acme", Role: controlplane.RoleAdmin}, wantMatched: true, wantErr: controlplane.ErrIdentityRole},
		{name: "account-less identity fails closed", bearer: "tok", identity: controlplane.Identity{ExternalID: "ext"}, wantMatched: true, wantErr: controlplane.ErrIdentityNoOwner},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := providerAuthenticator{validator: stubValidator{accept: "tok", identity: tc.identity}}
			access, matched, err := p.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil), tc.bearer)
			if matched != tc.wantMatched {
				t.Fatalf("matched = %v, want %v", matched, tc.wantMatched)
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if matched && (access.Fleet || access.Role != tc.wantRole || access.Principal.Kind != controlplane.PrincipalControlPlane) {
				t.Fatalf("access = %+v", access)
			}
		})
	}
}

// TestPostMatchSteps is one table over the three steps that run after an
// authenticator accepts: forward attribution, the surface rule and team
// selection.
func TestPostMatchSteps(t *testing.T) {
	payments := tokenAccess("payments", controlplane.RoleRunner)
	fleet := tokenAccess(controlplane.FleetTeam, controlplane.RoleViewer)
	mcpOnly := payments
	mcpOnly.MCPOnly = true
	oidc := payments
	oidc.Principal = controlplane.Principal{Kind: controlplane.PrincipalOIDC, ID: "oidc:okta:00u1"}
	managed := controlplane.Access{Identity: controlplane.Identity{OwnerRef: "acme"}, Role: controlplane.RoleRunner,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalControlPlane, ID: "controlplane:x"}}

	type req struct {
		path      string
		peer      bool
		forwarded bool
		surface   string
		team      string
	}
	cases := []struct {
		name      string
		access    controlplane.Access
		req       req
		wantVia   string
		wantErr   error
		wantNoErr bool
	}{
		// Forward attribution.
		{name: "forwarded by a verified peer records Via", access: payments, req: req{peer: true, forwarded: true}, wantVia: "peer-test", wantNoErr: true},
		{name: "forward marker without a verified peer records nothing", access: payments, req: req{forwarded: true}, wantNoErr: true},
		{name: "peer call that is not a forward records nothing", access: payments, req: req{peer: true}, wantNoErr: true},
		// Surface rule.
		{name: "ordinary credential on any route", access: payments, req: req{path: "/v1/sandboxes"}, wantNoErr: true},
		{name: "MCP-only credential on /mcp", access: mcpOnly, req: req{path: "/mcp"}, wantNoErr: true},
		{name: "MCP-only credential on a peer's MCP forward", access: mcpOnly, req: req{path: "/v1/sandboxes/sb-1/exec", peer: true, surface: "mcp"}, wantNoErr: true},
		{name: "MCP-only credential off /mcp is wrong_audience", access: mcpOnly, req: req{path: "/v1/sandboxes"}, wantErr: &controlplane.CredentialError{}},
		{name: "MCP surface marker without a peer is ignored", access: mcpOnly, req: req{path: "/v1/sandboxes", surface: "mcp"}, wantErr: &controlplane.CredentialError{}},
		// Team selection.
		{name: "token naming its own team", access: payments, req: req{team: "payments"}, wantNoErr: true},
		{name: "token header is trimmed", access: payments, req: req{team: " payments "}, wantNoErr: true},
		{name: "OIDC naming its own team", access: oidc, req: req{team: "payments"}, wantNoErr: true},
		{name: "token naming another team is refused", access: payments, req: req{team: "checkout"}, wantErr: &teamNotBoundError{}},
		{name: "fleet token naming a team is refused, not narrowed", access: fleet, req: req{team: "payments"}, wantErr: &teamNotBoundError{}},
		{name: "malformed team header", access: payments, req: req{team: "Payments!"}, wantErr: errBadTeamHeader},
		{name: "team name too long", access: payments, req: req{team: strings.Repeat("a", 64)}, wantErr: errBadTeamHeader},
		{name: "PAT ignores the header, even a bad one (L8)", access: controlplane.OperatorAccess(), req: req{team: "Bad Team"}, wantNoErr: true},
		{name: "node ignores the header", access: controlplane.NodeAccess("n1"), req: req{team: "checkout"}, wantNoErr: true},
		{name: "managed caller ignores the header (L8)", access: managed, req: req{team: "checkout"}, wantNoErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.req.path
			if path == "" {
				path = "/v1/sandboxes"
			}
			r := httptest.NewRequest(http.MethodGet, path, nil)
			if tc.req.peer {
				r.TLS = peerTLS("peer-test")
			}
			if tc.req.forwarded {
				r.Header.Set("X-Cluster-Forwarded", "1")
			}
			if tc.req.surface != "" {
				r.Header.Set(headerClusterSurface, tc.req.surface)
			}
			if tc.req.team != "" {
				r.Header.Set(HeaderTeam, tc.req.team)
			}
			got, err := runPostMatchSteps(r, tc.access)
			switch want := tc.wantErr.(type) {
			case nil:
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if got.Via != tc.wantVia {
					t.Fatalf("Via = %q, want %q", got.Via, tc.wantVia)
				}
			case *controlplane.CredentialError:
				ce, ok := controlplane.AsCredentialError(err)
				if !ok || ce.Reason != controlplane.RejectWrongAudience || ce.Kind != tc.access.Principal.Kind {
					t.Fatalf("err = %v, want wrong_audience for %s", err, tc.access.Principal.Kind)
				}
			case *teamNotBoundError:
				var nb *teamNotBoundError
				if !errors.As(err, &nb) {
					t.Fatalf("err = %v, want team not bound", err)
				}
			default:
				if !errors.Is(err, want) {
					t.Fatalf("err = %v, want %v", err, want)
				}
			}
		})
	}
}

func TestTeamNotBoundMessageNamesOnlyTheCaller(t *testing.T) {
	team := (&teamNotBoundError{team: "checkout", role: controlplane.RoleViewer, bound: "payments"}).Error()
	if !strings.Contains(team, "role viewer on team payments") || !strings.Contains(team, "binding on team checkout") {
		t.Fatalf("team message = %q", team)
	}
	fleet := (&teamNotBoundError{team: "checkout", role: controlplane.RoleRunner, bound: controlplane.FleetTeam}).Error()
	if !strings.Contains(fleet, "role runner on all teams") || !strings.Contains(fleet, "send no "+HeaderTeam) {
		t.Fatalf("fleet message = %q", fleet)
	}
}

// TestMapAuthFailure is reason mapping. Only an avm_ token or a JWT with a
// known reason tells the caller why (D17); everything else is today's bare
// 401, and team selection maps to 400/403.
func TestMapAuthFailure(t *testing.T) {
	cases := []struct {
		name        string
		linkKind    string
		err         error
		wantStatus  int
		wantKind    string
		wantReason  string
		wantInvalid controlplane.RejectReason
	}{
		{name: "token expired", linkKind: "token", err: &controlplane.CredentialError{Kind: controlplane.PrincipalToken, Reason: controlplane.RejectExpired},
			wantStatus: 401, wantKind: "token", wantReason: "expired", wantInvalid: controlplane.RejectExpired},
		{name: "oidc wrong audience", linkKind: "oidc", err: &controlplane.CredentialError{Kind: controlplane.PrincipalOIDC, Reason: controlplane.RejectWrongAudience},
			wantStatus: 401, wantKind: "oidc", wantReason: "wrong_audience", wantInvalid: controlplane.RejectWrongAudience},
		{name: "unknown reason is never echoed", linkKind: "token", err: &controlplane.CredentialError{Kind: controlplane.PrincipalToken, Reason: "kid=abc123"},
			wantStatus: 401, wantKind: "token", wantReason: "rejected"},
		{name: "managed provider cannot opt into reasons (L8)", linkKind: "controlplane", err: &controlplane.CredentialError{Kind: controlplane.PrincipalControlPlane, Reason: controlplane.RejectExpired},
			wantStatus: 401, wantKind: "controlplane", wantReason: "rejected"},
		{name: "provider rejection", linkKind: "controlplane", err: controlplane.ErrTokenRejected, wantStatus: 401, wantKind: "controlplane", wantReason: "rejected"},
		{name: "account-less identity", linkKind: "controlplane", err: controlplane.ErrIdentityNoOwner, wantStatus: 401, wantKind: "controlplane", wantReason: "no_owner"},
		{name: "fleet role from a provider", linkKind: "controlplane", err: controlplane.ErrIdentityRole, wantStatus: 401, wantKind: "controlplane", wantReason: "bad_role"},
		{name: "team not bound", linkKind: "token", err: &teamNotBoundError{team: "x", role: controlplane.RoleRunner, bound: "y"}, wantStatus: 403, wantKind: "token", wantReason: "team_not_bound"},
		{name: "bad team header", linkKind: "token", err: errBadTeamHeader, wantStatus: 400, wantKind: "token", wantReason: "bad_team"},
		{name: "anything else", linkKind: "unknown", err: errors.New("boom"), wantStatus: 401, wantKind: "unknown", wantReason: "rejected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := mapAuthFailure(tc.linkKind, tc.err)
			if f.status != tc.wantStatus || f.kind != tc.wantKind || f.reason != tc.wantReason || f.invalidToken != tc.wantInvalid {
				t.Fatalf("failure = %+v", f)
			}
			if f.status != http.StatusUnauthorized && f.message == "" {
				t.Fatal("a 400/403 must explain itself")
			}
		})
	}
}

func newIdentityServer(validator controlplane.Validator, opts ...ServerOption) *Server {
	return NewServer(discardLogger(), nil, nil, nil, config.Config{IdentityEnabled: true}, "pat-token", validator, opts...)
}

// TestUnauthorizedReasons is the per-reason 401 table (D17): every reason on
// every surface carries the RFC 6750 challenge and the same reason in the
// body, in that surface's own envelope.
func TestUnauthorizedReasons(t *testing.T) {
	reasons := []controlplane.RejectReason{
		controlplane.RejectExpired, controlplane.RejectNotYetValid, controlplane.RejectUnknownIssuer,
		controlplane.RejectWrongAudience, controlplane.RejectTooLongLived, controlplane.RejectInvalidSignature,
		controlplane.RejectMalformed, controlplane.RejectUnknownOrRevoked,
	}
	reject := map[string]controlplane.RejectReason{}
	for _, r := range reasons {
		reject["avm_"+string(r)] = r
	}
	server := newIdentityServer(nil, WithCredentialAuthenticator(controlplane.PrincipalToken,
		stubCredential{prefix: "avm_", kind: controlplane.PrincipalToken, reject: reject}))
	surfaces := []struct {
		name string
		path string
		body func(reason string) string
	}{
		{"v1", "/v1/whoami", func(r string) string { return `{"error":"unauthorized","reason":"` + r + `"}` + "\n" }},
		{"e2b", "/e2b/sandboxes", func(r string) string {
			return `{"code":401,"message":"Unauthorized, please check your credentials.","reason":"` + r + `"}` + "\n"
		}},
		{"runloop", "/runloop/v1/devboxes", func(r string) string {
			return `{"message":"unauthorized: check RUNLOOP_API_KEY","reason":"` + r + `"}` + "\n"
		}},
	}
	for _, surface := range surfaces {
		for _, reason := range reasons {
			t.Run(surface.name+"/"+string(reason), func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, surface.path, nil)
				req.Header.Set("Authorization", "Bearer avm_"+string(reason))
				rec := httptest.NewRecorder()
				server.Handler().ServeHTTP(rec, req)
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d", rec.Code)
				}
				wantChallenge := `Bearer error="invalid_token", error_description="` + string(reason) + `"`
				if got := rec.Header().Get("WWW-Authenticate"); got != wantChallenge {
					t.Fatalf("WWW-Authenticate = %q, want %q", got, wantChallenge)
				}
				if got := rec.Body.String(); got != surface.body(string(reason)) {
					t.Fatalf("body = %q, want %q", got, surface.body(string(reason)))
				}
			})
		}
	}
}

// TestUnauthorizedBodiesUnchanged pins the 401s every existing caller sees,
// byte for byte, headers included (L8, D17): no credential, a wrong PAT, a
// token the managed provider refuses, an account-less managed identity.
// None of them may gain a reason or a WWW-Authenticate challenge.
func TestUnauthorizedBodiesUnchanged(t *testing.T) {
	golden := map[string]string{
		"/v1/whoami":           `{"error":"unauthorized"}` + "\n",
		"/v1/sandboxes":        `{"error":"unauthorized"}` + "\n",
		"/daytona/sandbox":     `{"error":"unauthorized"}` + "\n",
		"/e2b/sandboxes":       `{"code":401,"message":"Unauthorized, please check your credentials."}` + "\n",
		"/runloop/v1/devboxes": `{"message":"unauthorized: check RUNLOOP_API_KEY"}` + "\n",
	}
	validator := stubValidator{accept: "no-account", identity: controlplane.Identity{ExternalID: "ext"}}
	servers := map[string]*Server{
		"identity off": NewServer(discardLogger(), nil, nil, nil, config.Config{}, "pat-token", validator),
		// Identity on with a token authenticator must not change a single
		// byte for credentials it does not claim.
		"identity on": newIdentityServer(validator, WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens())),
	}
	credentials := map[string]string{
		"no credential":           "",
		"wrong PAT":               "Bearer pat-tokem",
		"provider rejects":        "Bearer some-user-token",
		"account-less identity":   "Bearer no-account",
		"JWT-shaped bearer":       "Bearer eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl",
		"lowercase scheme, wrong": "bearer nope",
	}
	for serverName, server := range servers {
		for path, want := range golden {
			for credName, auth := range credentials {
				t.Run(serverName+path+"/"+credName, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodGet, path, nil)
					if auth != "" {
						req.Header.Set("Authorization", auth)
					}
					rec := httptest.NewRecorder()
					server.Handler().ServeHTTP(rec, req)
					if rec.Code != http.StatusUnauthorized || rec.Body.String() != want {
						t.Fatalf("got %d %q, want 401 %q", rec.Code, rec.Body.String(), want)
					}
					if got := rec.Header().Get("WWW-Authenticate"); got != "" {
						t.Fatalf("WWW-Authenticate = %q; the bare 401 must not gain a challenge", got)
					}
				})
			}
		}
	}
}

func TestTeamSelectionStatusesOnEachSurface(t *testing.T) {
	server := newIdentityServer(nil, WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens()))
	cases := []struct {
		path, team string
		want       int
		body       string
	}{
		{"/v1/whoami", "checkout", http.StatusForbidden, `"error":"X-AerolVM-Team: checkout is not one of this credential's teams`},
		{"/v1/whoami", "Bad!", http.StatusBadRequest, `"error":"invalid X-AerolVM-Team header`},
		{"/e2b/sandboxes", "checkout", http.StatusForbidden, `"code":403,"message":"X-AerolVM-Team: checkout`},
		{"/runloop/v1/devboxes", "Bad!", http.StatusBadRequest, `"message":"invalid X-AerolVM-Team header`},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Header.Set("Authorization", "Bearer avm_payments")
		req.Header.Set(HeaderTeam, tc.team)
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.body) {
			t.Errorf("%s team %q = %d %s, want %d containing %s", tc.path, tc.team, rec.Code, rec.Body.String(), tc.want, tc.body)
		}
		if rec.Header().Get("WWW-Authenticate") != "" {
			t.Errorf("%s: a 400/403 carries no bearer challenge", tc.path)
		}
	}
}

// TestCredentialAuthenticatorChain checks the order (pat, named credentials,
// provider), that the first match wins, and that identity off drops the
// named credentials entirely so a token-shaped bearer still reaches the
// managed provider (L8).
func TestCredentialAuthenticatorChain(t *testing.T) {
	oidc := stubCredential{prefix: "eyJ", kind: controlplane.PrincipalOIDC}
	claimAll := stubCredential{prefix: "", kind: controlplane.PrincipalToken}
	kinds := func(s *Server) []string {
		var out []string
		for _, l := range s.authLinks() {
			out = append(out, l.kind)
		}
		return out
	}
	on := newIdentityServer(nil,
		WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens()),
		WithCredentialAuthenticator(controlplane.PrincipalOIDC, oidc),
		WithCredentialAuthenticator(controlplane.PrincipalOIDC, nil))
	if got := strings.Join(kinds(on), ","); got != "operator,token,oidc,unknown" {
		t.Fatalf("identity-on chain = %s", got)
	}
	managed := stubValidator{accept: "avm_payments", identity: controlplane.Identity{OwnerRef: "acct"}}
	off := NewServer(discardLogger(), nil, nil, nil, config.Config{}, "pat-token", managed,
		WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens()))
	if got := strings.Join(kinds(off), ","); got != "operator,controlplane" {
		t.Fatalf("identity-off chain = %s; named credentials must be dropped", got)
	}
	// With identity off, an avm_-looking bearer is the managed provider's.
	var c capture
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer avm_payments")
	off.requireAuth(c.handler()).ServeHTTP(httptest.NewRecorder(), req)
	if !c.ok || c.access.Principal.Kind != controlplane.PrincipalControlPlane {
		t.Fatalf("identity off: access = %+v, want the managed provider's", c.access)
	}
	// The PAT is tried first, so an authenticator that claims everything
	// still never sees it.
	greedy := newIdentityServer(nil, WithCredentialAuthenticator(controlplane.PrincipalToken, claimAll))
	c = capture{}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer pat-token")
	greedy.requireAuth(c.handler()).ServeHTTP(httptest.NewRecorder(), req)
	if !c.ok || c.access.Principal.Kind != controlplane.PrincipalOperator {
		t.Fatalf("PAT behind a greedy authenticator = %+v", c.access)
	}
	// And a named credential that claims a bearer decides it: the provider
	// is never asked.
	asked := &countingValidator{}
	claimed := newIdentityServer(asked, WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens()))
	rec := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer avm_unknown")
	claimed.requireAuth(c.handler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || asked.calls != 0 {
		t.Fatalf("claimed token: %d, provider asked %d times", rec.Code, asked.calls)
	}
}

// A Server built without NewServer still fails closed: a nil validator is
// the no-op one, and a chain with nothing that claims the bearer is a 401.
func TestAuthChainFailsClosed(t *testing.T) {
	bare := &Server{patToken: "pat-token"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	rec := httptest.NewRecorder()
	var c capture
	bare.requireAuth(c.handler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || c.called {
		t.Fatalf("nil validator: %d (handler reached %v), want 401", rec.Code, c.called)
	}
	patOnly := &Server{authChain: []authLink{{kind: "operator", auth: patAuthenticator{token: "pat-token"}}}}
	if _, failure := patOnly.authenticate(req, "user-token"); failure == nil || failure.status != http.StatusUnauthorized || failure.kind != authKindUnknown {
		t.Fatalf("unclaimed bearer = %+v, want a bare 401", failure)
	}
}

type countingValidator struct{ calls int }

func (v *countingValidator) Validate(context.Context, string) (controlplane.Identity, error) {
	v.calls++
	return controlplane.Identity{}, controlplane.ErrTokenRejected
}

// TestE2BCredentialPrecedence keeps the old requireE2BAuth order: a PAT in
// either header wins; otherwise the bearer before X-API-KEY.
func TestE2BCredentialPrecedence(t *testing.T) {
	server := NewServer(discardLogger(), nil, nil, nil, config.Config{}, "pat-token",
		multiValidator{"user-bearer": "acct-bearer", "user-key": "acct-key"})
	cases := []struct {
		name, bearer, apiKey string
		wantStatus           int
		wantKind             controlplane.PrincipalKind
		wantOwner            string
	}{
		{name: "PAT in X-API-KEY", apiKey: "pat-token", wantStatus: 204, wantKind: controlplane.PrincipalOperator},
		{name: "PAT in X-API-KEY beats a user bearer", bearer: "user-bearer", apiKey: "pat-token", wantStatus: 204, wantKind: controlplane.PrincipalOperator},
		{name: "PAT bearer beats a user key", bearer: "pat-token", apiKey: "user-key", wantStatus: 204, wantKind: controlplane.PrincipalOperator},
		{name: "user bearer before user key", bearer: "user-bearer", apiKey: "user-key", wantStatus: 204, wantKind: controlplane.PrincipalControlPlane, wantOwner: "acct-bearer"},
		{name: "user key alone", apiKey: " user-key ", wantStatus: 204, wantKind: controlplane.PrincipalControlPlane, wantOwner: "acct-key"},
		{name: "nothing", wantStatus: 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c capture
			req := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil)
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			if tc.apiKey != "" {
				req.Header.Set("X-API-KEY", tc.apiKey)
			}
			rec := httptest.NewRecorder()
			server.requireE2BAuth(c.handler()).ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus == 204 && (c.access.Principal.Kind != tc.wantKind || c.access.Identity.OwnerRef != tc.wantOwner) {
				t.Fatalf("access = %+v", c.access)
			}
		})
	}
}

// multiValidator accepts several tokens, each for its own account.
type multiValidator map[string]string

func (m multiValidator) Validate(_ context.Context, token string) (controlplane.Identity, error) {
	if owner, ok := m[token]; ok {
		return controlplane.Identity{OwnerRef: owner, ExternalID: token}, nil
	}
	return controlplane.Identity{}, controlplane.ErrTokenRejected
}

// TestLowercaseBearerAuthenticates is D5's one intended behavior change: the
// scheme is case-insensitive (RFC 7235), so `bearer <PAT>` now works.
func TestLowercaseBearerAuthenticates(t *testing.T) {
	server := NewServer(discardLogger(), nil, nil, nil, config.Config{}, "pat-token", nil)
	for _, auth := range []string{"bearer pat-token", "BEARER pat-token", "Bearer  pat-token "} {
		var c capture
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", auth)
		rec := httptest.NewRecorder()
		server.requireAuth(c.handler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent || c.access.Principal.Kind != controlplane.PrincipalOperator {
			t.Errorf("%q = %d", auth, rec.Code)
		}
	}
}

func TestAuthOrigin(t *testing.T) {
	cases := []struct {
		remote string
		peer   bool
		want   string
	}{
		{"127.0.0.1:5000", false, "host"},
		{"[::1]:5000", false, "host"},
		{"127.0.0.1", false, "host"},
		{"10.0.0.7:5000", false, "public"},
		{"203.0.113.9:443", false, "public"},
		{"not-an-address", false, "public"},
		{"10.0.0.7:5000", true, "peer"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = tc.remote
		if tc.peer {
			r.TLS = peerTLS("n1")
		}
		if got := authOrigin(r); got != tc.want {
			t.Errorf("authOrigin(%q, peer=%v) = %q, want %q", tc.remote, tc.peer, got, tc.want)
		}
	}
}

// TestWhoAmIThroughTheEdge drives GET /v1/whoami through the real handler
// for the credentials T1 knows plus a stub token: the answer describes only
// the caller.
func TestWhoAmIThroughTheEdge(t *testing.T) {
	server := newIdentityServer(nil, WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens()))
	cases := map[string]string{
		"pat-token":    `{"principal":{"kind":"operator","id":"operator","name":"operator"},"role":"admin","team":"*"}`,
		"avm_payments": `{"principal":{"kind":"token","id":"tok_7Hq2","name":"ci-deploy"},"role":"runner","team":"payments","expires_at":"2027-01-02T03:04:05Z"}`,
		"avm_fleet":    `{"principal":{"kind":"token","id":"tok_7Hq2","name":"ci-deploy"},"role":"viewer","team":"*","expires_at":"2027-01-02T03:04:05Z"}`,
	}
	for token, want := range cases {
		req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != want {
			t.Errorf("whoami(%s) = %d %s, want %s", token, rec.Code, rec.Body.String(), want)
		}
		var decoded models.WhoAmI
		if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
			t.Errorf("whoami body does not decode into models.WhoAmI: %v", err)
		}
	}
}

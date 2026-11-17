package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The Kubernetes operator's own API token (identitywire.OperatorTokenPrefix)
// works only on a server, sent to it directly or through another server
// (operator_token.go).

const opTokenName = "aerolvm-operator-1763380000000000000"

// opTokens is a token index holding the operator's token and an ordinary
// admin token, as a node's mirror would.
func opTokens(t *testing.T) (set *switchableTokens, operator, ordinary string) {
	t.Helper()
	set = &switchableTokens{}
	exp := time.Now().Add(time.Hour)
	operator = mintToken(t, set, opTokenName, controlplane.FleetTeam, controlplane.RoleAdmin, exp)
	ordinary = mintToken(t, set, "ci-admin", controlplane.FleetTeam, controlplane.RoleAdmin, exp)
	return set, operator, ordinary
}

// opNode is a node's API server with set as its token index.
func opNode(set identity.TokenLookup, cfg config.Config, svc *service.Service) *Server {
	cfg.IdentityEnabled, cfg.MCPEnabled = true, true
	return NewServer(discardLogger(), svc, nil, nil, cfg, "pat-token", nil,
		WithCredentialAuthenticator(controlplane.PrincipalToken, identity.NewTokenAuthenticator(set, discardLogger())))
}

// TestOperatorTokenOnlyOnServers: called directly, the operator's token
// works on a single node and on a cluster node with the server role, and
// is a 401 on a gateway or a worker on every surface. An ordinary admin
// token works everywhere, as before.
func TestOperatorTokenOnlyOnServers(t *testing.T) {
	set, operator, ordinary := opTokens(t)
	for _, tc := range []struct {
		name    string
		cfg     config.Config
		takesOp bool
	}{
		{"single node", config.Config{}, true},
		// A single node is its own server, whatever role it names.
		{"single node naming a role", config.Config{NodeRole: config.NodeRoleWorker}, true},
		{"server", config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, true},
		{"mixed", config.Config{EnableCluster: true}, true},
		{"server and worker", config.Config{EnableCluster: true, NodeRole: "server,worker"}, true},
		{"gateway", config.Config{EnableCluster: true, NodeRole: config.NodeRoleIngress}, false},
		{"worker", config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, false},
		{"worker and gateway", config.Config{EnableCluster: true, NodeRole: "worker,ingress"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := opNode(set, tc.cfg, nil)
			if rec := do(t, srv, http.MethodGet, "/v1/whoami", ordinary, "", nil); rec.Code != http.StatusOK {
				t.Fatalf("an ordinary admin token: %d %s", rec.Code, rec.Body.String())
			}
			before := authCounter(authFailures, "token", "servers_only")
			rec := do(t, srv, http.MethodGet, "/v1/whoami", operator, "", nil)
			if tc.takesOp {
				var who models.WhoAmI
				if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &who) != nil || who.Principal.Name != opTokenName {
					t.Fatalf("the operator's token here: %d %s", rec.Code, rec.Body.String())
				}
				return
			}
			// The surface's fixed 401: the caller learns nothing, and the
			// operator reads servers_only in the metric and the record.
			if rec.Code != http.StatusUnauthorized || rec.Body.String() != `{"error":"unauthorized"}`+"\n" || rec.Header().Get("WWW-Authenticate") != "" {
				t.Fatalf("the operator's token on v1: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
			}
			if got := authCounter(authFailures, "token", "servers_only") - before; got != 1 {
				t.Fatalf("the refusal counted %d times as {token,servers_only}, want 1", got)
			}
			// Every surface authenticates through Server.authenticate.
			for _, call := range []struct {
				path   string
				bearer string
				header map[string]string
				want   string
			}{
				{"/e2b/sandboxes", "", map[string]string{"X-API-KEY": operator}, "Unauthorized, please check your credentials."},
				{"/e2b/sandboxes", operator, nil, "Unauthorized, please check your credentials."},
				{"/runloop/v1/devboxes", operator, nil, "unauthorized: check RUNLOOP_API_KEY"},
				{"/v1/sandboxes", operator, nil, "unauthorized"},
				{"/v1/tokens", operator, nil, "unauthorized"},
			} {
				rec := do(t, srv, http.MethodGet, call.path, call.bearer, "", call.header)
				if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), call.want) {
					t.Fatalf("the operator's token on %s: %d %s", call.path, rec.Code, rec.Body.String())
				}
			}
			if rec := postMCP(t, srv, operator); rec.Code != http.StatusUnauthorized {
				t.Fatalf("the operator's token on /mcp: %d %s", rec.Code, rec.Body.String())
			}
			if rec := postMCP(t, srv, ordinary); rec.Code == http.StatusUnauthorized {
				t.Fatalf("an ordinary token on /mcp: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestOperatorTokenNotOnThePublicSocket: on a server, the public socket
// (Caddy's upstream) refuses the operator's token; the API port, also
// when the admin token has its own loopback listener (RemoteHandler, the
// API Service the operator calls), takes it.
func TestOperatorTokenNotOnThePublicSocket(t *testing.T) {
	set, operator, ordinary := opTokens(t)
	for _, cfg := range []config.Config{{}, {EnableCluster: true, NodeRole: config.NodeRoleServer}} {
		srv := opNode(set, cfg, nil)
		for _, tc := range []struct {
			name   string
			h      http.Handler
			bearer string
			want   int
		}{
			{"public socket, operator", srv.PublicHandler(), operator, http.StatusUnauthorized},
			{"public socket, ordinary", srv.PublicHandler(), ordinary, http.StatusOK},
			{"API port, operator", srv.Handler(), operator, http.StatusOK},
			{"API port with its own admin listener, operator", srv.RemoteHandler(), operator, http.StatusOK},
		} {
			req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
			req.RemoteAddr = "10.0.0.7:5000"
			req.Header.Set("Authorization", "Bearer "+tc.bearer)
			rec := httptest.NewRecorder()
			tc.h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("cluster %v, %s: %d %s, want %d", cfg.EnableCluster, tc.name, rec.Code, rec.Body.String(), tc.want)
			}
		}
	}
}

// liveCluster is a server's cluster in which every peer is a live member,
// so the control-header guard lets each forward through and the rule under
// test decides.
type liveCluster struct{ *cluster.Noop }

func (c liveCluster) LookupMember(id string) (cluster.Member, bool) {
	return cluster.Member{NodeID: id, Alive: true}, true
}

// TestOperatorTokenForwardedOnlyByServers: on a server, the operator's
// token another node sent counts only from a server, named by its verified
// certificate: a gateway's or a worker's forward (which keeps
// Authorization, and which an older node sends without checking) is
// refused, as is the token a worker or a gateway sends over the cluster's
// mTLS as itself. An ordinary token's forward is unchanged.
func TestOperatorTokenForwardedOnlyByServers(t *testing.T) {
	set, operator, ordinary := opTokens(t)
	cfg := config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer, IdentityEnabled: true}
	svc := service.New(cfg, discardLogger(), nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(liveCluster{cluster.NewNoop("srv-0", "http://srv-0", "")})
	srv := opNode(set, cfg, svc)
	for _, tc := range []struct {
		name      string
		peer      string
		role      string
		forwarded bool
		bearer    string
		want      int
	}{
		{"forwarded by a server", "srv-1", "server", true, operator, http.StatusOK},
		{"forwarded by a gateway", "gw-1", "ingress", true, operator, http.StatusUnauthorized},
		{"forwarded by a worker", "wkr-1", "worker", true, operator, http.StatusUnauthorized},
		{"forwarded by a node whose certificate names no role", "old-1", "", true, operator, http.StatusUnauthorized},
		{"a server sending it over mTLS", "srv-1", "server", false, operator, http.StatusOK},
		{"a worker sending it over mTLS", "wkr-1", "worker", false, operator, http.StatusUnauthorized},
		{"a gateway sending it over mTLS", "gw-1", "ingress", false, operator, http.StatusUnauthorized},
		{"an ordinary token forwarded by a worker", "wkr-1", "worker", true, ordinary, http.StatusOK},
		{"an ordinary token forwarded by a gateway", "gw-1", "ingress", true, ordinary, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
			req.RemoteAddr = "10.0.0.9:7002"
			req.TLS = peerTLSRole(tc.peer, tc.role)
			req.Header.Set("Authorization", "Bearer "+tc.bearer)
			if tc.forwarded {
				req.Header.Set(cluster.HeaderForwarded, "1")
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("= %d %s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
		})
	}

	// The forward marker counts only with a verified peer: the header
	// guard refuses it from anyone else, and the rule does not lean on
	// that guard.
	req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
	req.Header.Set(cluster.HeaderForwarded, "1")
	if _, f := srv.authenticate(req, operator); f == nil || f.status != http.StatusUnauthorized || f.reason != "servers_only" {
		t.Fatalf("a forward marker with no verified peer: %+v", f)
	}
	if access, f := srv.authenticate(req, ordinary); f != nil || access.Principal.Name != "ci-admin" {
		t.Fatalf("an ordinary token with the same marker: %+v", f)
	}
}

// TestOperatorTokenRotationThroughTheAPI is the operator's token path on
// a node with a real token store: the admin token makes the first one,
// that one makes its successor and revokes itself, and an ordinary admin
// token cannot make one (403, nothing written).
func TestOperatorTokenRotationThroughTheAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := config.Config{IdentityEnabled: true}
	svc := service.New(cfg, discardLogger(), storeWith(t, "optok"), nil, nil, nil, nil, nil, nil)
	if err := svc.StartAPITokens(ctx); err != nil {
		t.Fatal(err)
	}
	srv := opNode(svc.APITokenLookup(), cfg, svc)
	create := func(bearer, name string) (*httptest.ResponseRecorder, models.CreatedAPIToken) {
		t.Helper()
		body := `{"name":"` + name + `","role":"admin","team":"*","expires_in":"720h"}`
		rec := do(t, srv, http.MethodPost, "/v1/tokens", bearer, body, map[string]string{"Content-Type": "application/json"})
		var created models.CreatedAPIToken
		_ = json.Unmarshal(rec.Body.Bytes(), &created)
		return rec, created
	}

	rec, first := create("pat-token", "aerolvm-operator-1")
	if rec.Code != http.StatusCreated || first.Token == "" {
		t.Fatalf("the admin token makes the operator's first token: %d %s", rec.Code, rec.Body.String())
	}
	rec, ci := create("pat-token", "ci-admin")
	if rec.Code != http.StatusCreated {
		t.Fatalf("the admin token makes an ordinary admin token: %d %s", rec.Code, rec.Body.String())
	}
	for _, name := range []string{"aerolvm-operator-2", " aerolvm-operator-3 "} {
		rec, _ = create(ci.Token, name)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "kept for the Kubernetes operator") || strings.Contains(rec.Body.String(), "avm_") {
			t.Fatalf("an ordinary admin token making %q: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec, _ = create(ci.Token, "Aerolvm-operator-2"); rec.Code != http.StatusCreated {
		t.Fatalf("another case is an ordinary name: %d %s", rec.Code, rec.Body.String())
	}
	rec, next := create(first.Token, "aerolvm-operator-2")
	if rec.Code != http.StatusCreated || next.Token == "" {
		t.Fatalf("the operator's token makes its successor: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, srv, http.MethodDelete, "/v1/tokens/"+first.ID, next.Token, "", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("the successor revokes the old one: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, srv, http.MethodGet, "/v1/whoami", first.Token, "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the revoked token: %d", rec.Code)
	}
	rec = do(t, srv, http.MethodGet, "/v1/tokens", next.Token, "", nil)
	var list models.APITokenList
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var live []string
	for _, tok := range list.Tokens {
		if strings.HasPrefix(tok.Name, "aerolvm-operator-") {
			live = append(live, tok.Name)
		}
	}
	if len(live) != 1 || live[0] != "aerolvm-operator-2" {
		t.Fatalf("exactly one operator token is live: %v", live)
	}
}

// TestOperatorTokenRuleIsForTokensOnly: the rule reads an API token's
// name and nothing else. Another kind of caller whose display name starts
// the same way (a sign-in, a Kubernetes user) is not the operator's token,
// and passes on a gateway like any other.
func TestOperatorTokenRuleIsForTokensOnly(t *testing.T) {
	gateway := opNode(&switchableTokens{}, config.Config{EnableCluster: true, NodeRole: config.NodeRoleIngress}, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
	for _, kind := range []controlplane.PrincipalKind{
		controlplane.PrincipalOIDC, controlplane.PrincipalKubernetes, controlplane.PrincipalControlPlane,
		controlplane.PrincipalOperator, controlplane.PrincipalNode, controlplane.PrincipalSandboxToken,
	} {
		a := controlplane.Access{Principal: controlplane.Principal{Kind: kind, ID: "x", Name: opTokenName}}
		if err := gateway.operatorTokenPlace(req, a); err != nil {
			t.Fatalf("%s named %s on a gateway: %v", kind, opTokenName, err)
		}
	}
	a := controlplane.Access{Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_x", Name: opTokenName}}
	if err := gateway.operatorTokenPlace(req, a); err == nil {
		t.Fatal("the operator's token on a gateway passed")
	}
}

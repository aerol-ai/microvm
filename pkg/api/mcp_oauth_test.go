package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/internal/identity/identitytest"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/remotemcp"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// OAuth for remote MCP (plans/identity-and-access.md §5.14, task T13)
// through the real API edge.

const (
	mcpTestAudience = "api://aerolvm-mcp"
	mcpTestResource = "https://api.acme.dev/mcp"
	mcpTestTenant   = "8f1a2b3c-0000-4000-8000-00000000abcd"
	// mcpTestChallenge is the /mcp 401's Bearer challenge for the file
	// below: where the metadata is, and the scope to ask for.
	mcpTestChallenge = `Bearer resource_metadata="https://api.acme.dev/.well-known/oauth-protected-resource/mcp", scope="api://aerolvm-mcp/mcp"`
)

// mcpOAuthFile trusts the httptest issuer for ID tokens (cli) and for MCP
// access tokens (mcpTestAudience), plus an Entra tenant whose keys come
// from a file (no test reaches the network). withMCP=false leaves out the
// mcp: section, as a file that never configured OAuth for /mcp.
func mcpOAuthFile(t *testing.T, iss *identitytest.Issuer, withMCP bool) string {
	t.Helper()
	jwks := filepath.Join(t.TempDir(), "entra-jwks.json")
	if err := os.WriteFile(jwks, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := fmt.Sprintf(`version: 1
issuers:
  - name: okta
    url: %s
    audiences: [cli]
    clients: {cli: cli}
    claims: {username: email}
    mcp: %v
    mcp_audiences: [%s]
  - name: entra
    url: https://login.microsoftonline.com/%s/v2.0
    jwks_file: %s
    audiences: [entra-cli]
bindings:
  - {issuer: okta, group: payments-eng, role: runner, team: payments}
  - {issuer: okta, group: billing-eng, role: runner, team: billing}
`, iss.URL, withMCP, mcpTestAudience, mcpTestTenant, jwks)
	if withMCP {
		doc += "mcp:\n  resource: " + mcpTestResource + "\n  scopes: [\"api://aerolvm-mcp/mcp\"]\n"
	}
	return doc
}

type mcpOAuthEnv struct {
	iss    *identitytest.Issuer
	cfg    atomic.Pointer[identity.Config]
	v      *identity.Verifier
	server *Server
}

// newMCPOAuthEnv is an identity-on server with the OIDC verifier and the
// identity file's MCP resource wired the way the daemon wires them.
func newMCPOAuthEnv(t *testing.T, cfg config.Config, svc *service.Service) *mcpOAuthEnv {
	t.Helper()
	env := &mcpOAuthEnv{iss: identitytest.New(t)}
	env.load(t, true)
	env.v = identity.NewVerifier(env.cfg.Load, identity.VerifierOptions{HTTPClient: env.iss.Client()})
	cfg.IdentityEnabled = true
	env.server = NewServer(discardLogger(), svc, nil, nil, cfg, "pat-token", nil, env.options()...)
	return env
}

func (e *mcpOAuthEnv) load(t *testing.T, withMCP bool) {
	t.Helper()
	c, err := identity.Parse([]byte(mcpOAuthFile(t, e.iss, withMCP)))
	if err != nil {
		t.Fatal(err)
	}
	e.cfg.Store(c)
}

func (e *mcpOAuthEnv) options() []ServerOption {
	return []ServerOption{
		WithCredentialAuthenticator(controlplane.PrincipalOIDC, e.v),
		WithMCPResource(func() MCPResource {
			c := e.cfg.Load()
			if c == nil {
				return MCPResource{}
			}
			return MCPResource{Resource: c.MCPResource, AuthorizationServers: c.MCPAuthorizationServers(), Scopes: c.MCPScopes}
		}),
	}
}

// accessToken is what the connector's OAuth flow yields: a JWT whose aud is
// the issuer's MCP audience.
func (e *mcpOAuthEnv) accessToken(t *testing.T, groups ...string) string {
	t.Helper()
	return e.iss.Mint(t, e.iss.Claims(time.Now(), mcpTestAudience, "ana", groups...))
}

func (e *mcpOAuthEnv) idToken(t *testing.T, groups ...string) string {
	t.Helper()
	return e.iss.Mint(t, e.iss.Claims(time.Now(), "cli", "ana", groups...))
}

// edge runs bearer through the v1 auth edge like oidcEnv.do.
func (e *mcpOAuthEnv) edge(t *testing.T, mw func(http.Handler) http.Handler, bearer string, header http.Header) (*httptest.ResponseRecorder, capture) {
	t.Helper()
	return (&oidcEnv{server: e.server}).do(t, mw, bearer, header)
}

const mcpInitialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`

func postMCP(t *testing.T, srv *Server, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, srv, http.MethodPost, "/mcp?sandbox=agent", bearer, mcpInitialize, map[string]string{
		"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
	})
}

// TestMCPProtectedResourceMetadata is the metadata handler test (RFC 9728):
// both the root and the /mcp path form serve the identity file's resource,
// its mcp: true issuers and its scopes, publicly and uncached. Without an
// mcp.resource (or with no good file) it is the mux's 404; with identity or
// remote MCP off the routes do not exist.
func TestMCPProtectedResourceMetadata(t *testing.T) {
	env := newMCPOAuthEnv(t, config.Config{MCPEnabled: true}, nil)
	want := `{"resource":"https://api.acme.dev/mcp","authorization_servers":["` + env.iss.URL + `"],` +
		`"scopes_supported":["api://aerolvm-mcp/mcp"],"bearer_methods_supported":["header"]}` + "\n"
	paths := []string{remotemcp.MetadataPath, remotemcp.MetadataPath + remotemcp.Path}
	for _, path := range paths {
		rec := do(t, env.server, http.MethodGet, path, "", "", nil)
		if rec.Code != http.StatusOK || rec.Body.String() != want || rec.Header().Get("Cache-Control") != "no-store" ||
			rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("GET %s = %d %v %s", path, rec.Code, rec.Header(), rec.Body.String())
		}
	}

	notFound := func(t *testing.T, srv *Server, why string) {
		t.Helper()
		for _, path := range paths {
			if rec := do(t, srv, http.MethodGet, path, "", "", nil); rec.Code != http.StatusNotFound || rec.Body.String() != "404 page not found\n" {
				t.Fatalf("%s: GET %s = %d %q, want the mux's 404", why, path, rec.Code, rec.Body.String())
			}
		}
	}
	// A resource with no mcp: true issuer still answers, with an empty list
	// (RFC 9728: authorization_servers is a JSON array when present).
	bare := NewServer(discardLogger(), nil, nil, nil, config.Config{IdentityEnabled: true, MCPEnabled: true}, "pat-token", nil,
		WithMCPResource(func() MCPResource { return MCPResource{Resource: mcpTestResource} }))
	if rec := do(t, bare, http.MethodGet, paths[1], "", "", nil); rec.Code != http.StatusOK ||
		rec.Body.String() != `{"resource":"https://api.acme.dev/mcp","authorization_servers":[],"bearer_methods_supported":["header"]}`+"\n" {
		t.Fatalf("resource without issuers = %d %s", rec.Code, rec.Body.String())
	}
	env.load(t, false)
	notFound(t, env.server, "a file without mcp.resource")
	env.cfg.Store(nil)
	notFound(t, env.server, "no good identity file")
	env.load(t, true)

	off := NewServer(discardLogger(), nil, nil, nil, config.Config{MCPEnabled: true}, "pat-token", nil,
		WithMCPResource(func() MCPResource { t.Fatal("identity off must not read the MCP resource"); return MCPResource{} }))
	notFound(t, off, "identity off")
	noMCP := newMCPOAuthEnv(t, config.Config{}, nil)
	notFound(t, noMCP.server, "remote MCP off")

	// The registry: present only with both on, and public (§5.3 allowlist).
	routes := registeredRoutes(t, env.server)
	for _, path := range paths {
		h, ok := routes["GET "+path]
		if !ok || !isPublicRoute("GET "+path) {
			t.Fatalf("GET %s registered %v, public %v", path, ok, isPublicRoute("GET "+path))
		}
		if _, tagged := apihttp.RouteOf(h); tagged {
			t.Fatalf("GET %s is public and must not authenticate", path)
		}
	}
	for name, srv := range map[string]*Server{"identity off": off, "remote MCP off": noMCP.server} {
		for pattern := range registeredRoutes(t, srv) {
			if strings.Contains(pattern, remotemcp.MetadataPath) {
				t.Fatalf("%s registered %s", name, pattern)
			}
		}
	}
}

// TestMCPUnauthorizedChallenge is the challenge handler test: every 401
// from /mcp names the metadata (and the scope), with the D17 error after it
// for a refused named credential; the body is unchanged. Only /mcp carries
// it, and identity off, or no mcp.resource, keeps the 401 byte for byte.
func TestMCPUnauthorizedChallenge(t *testing.T) {
	env := newMCPOAuthEnv(t, config.Config{MCPEnabled: true}, nil)
	now := time.Now()
	expired := env.iss.Claims(now, mcpTestAudience, "ana", "payments-eng")
	expired["iat"], expired["exp"] = now.Add(-time.Hour).Unix(), now.Add(-10*time.Minute).Unix()
	bare := `{"error":"unauthorized"}` + "\n"
	cases := []struct {
		name, path, bearer   string
		wantHeader, wantBody string
	}{
		{"no credential on /mcp", "/mcp?sandbox=agent", "", mcpTestChallenge, bare},
		{"wrong PAT on /mcp", "/mcp?sandbox=agent", "pat-tokem", mcpTestChallenge, bare},
		{"opaque access token on /mcp", "/mcp?sandbox=agent", "ya29.opaque-access-token", mcpTestChallenge, bare},
		{"expired access token on /mcp", "/mcp?sandbox=agent", env.iss.Mint(t, expired),
			mcpTestChallenge + `, error="invalid_token", error_description="expired"`, `{"error":"unauthorized","reason":"expired"}` + "\n"},
		{"wrong-audience JWT on /mcp", "/mcp?sandbox=agent", env.iss.Mint(t, env.iss.Claims(now, mcpTestResource, "ana")),
			mcpTestChallenge + `, error="invalid_token", error_description="wrong_audience"`, `{"error":"unauthorized","reason":"wrong_audience"}` + "\n"},
		{"no credential on /v1 has no challenge", "/v1/sandboxes", "", "", bare},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, env.server, http.MethodPost, tc.path, tc.bearer, "", nil)
			if tc.path == "/v1/sandboxes" {
				rec = do(t, env.server, http.MethodGet, tc.path, tc.bearer, "", nil)
			}
			if rec.Code != http.StatusUnauthorized || rec.Body.String() != tc.wantBody {
				t.Fatalf("got %d %q, want 401 %q", rec.Code, rec.Body.String(), tc.wantBody)
			}
			if got := rec.Header().Values("WWW-Authenticate"); (tc.wantHeader == "" && len(got) != 0) || (tc.wantHeader != "" && (len(got) != 1 || got[0] != tc.wantHeader)) {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, tc.wantHeader)
			}
		})
	}

	unchanged := func(t *testing.T, srv *Server, why string) {
		t.Helper()
		rec := do(t, srv, http.MethodPost, "/mcp?sandbox=agent", "", "", nil)
		if rec.Code != http.StatusUnauthorized || rec.Body.String() != bare || rec.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("%s: %d %v %q", why, rec.Code, rec.Header(), rec.Body.String())
		}
	}
	unchanged(t, NewServer(discardLogger(), nil, nil, nil, config.Config{MCPEnabled: true}, "pat-token", nil), "identity off")
	env.load(t, false)
	unchanged(t, env.server, "no mcp.resource")
	env.cfg.Store(nil)
	unchanged(t, env.server, "no good identity file")
}

// TestMCPAccessTokenOnlyOnMCP is the surface rule end to end: the
// connector's access token works on /mcp and is refused on /v1 and every
// facade, also when the verified-token cache already holds it; the same
// person's ID token works on both (§5.14's credential table).
func TestMCPAccessTokenOnlyOnMCP(t *testing.T) {
	env := newMCPOAuthEnv(t, config.Config{MCPEnabled: true}, nil)
	access := env.accessToken(t, "payments-eng")
	id := env.idToken(t, "payments-eng")

	for name, bearer := range map[string]string{"access token": access, "ID token": id} {
		if rec := postMCP(t, env.server, bearer); rec.Code != http.StatusOK {
			t.Fatalf("%s on /mcp = %d %s", name, rec.Code, rec.Body.String())
		}
	}
	for _, path := range []string{"/v1/whoami", "/v1/sandboxes", "/e2b/sandboxes", "/runloop/v1/devboxes", "/daytona/sandbox"} {
		rec := do(t, env.server, http.MethodGet, path, access, "", nil)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"reason":"wrong_audience"`) ||
			rec.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token", error_description="wrong_audience"` {
			t.Fatalf("access token on %s = %d %v %s", path, rec.Code, rec.Header(), rec.Body.String())
		}
	}
	rec := do(t, env.server, http.MethodGet, "/v1/whoami", id, "", nil)
	var who models.WhoAmI
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &who) != nil || who.Role != "runner" || who.Team != "payments" {
		t.Fatalf("ID token on /v1/whoami = %d %s", rec.Code, rec.Body.String())
	}
	if env.iss.JWKSHits.Load() != 1 {
		t.Fatalf("JWKS fetched %d times; the refusals above came from the cache", env.iss.JWKSHits.Load())
	}

	// The middleware view: the Access /mcp attaches is the MCP-only one.
	header := http.Header{}
	req := httptest.NewRequest(http.MethodPost, remotemcp.Path, nil)
	req.Header.Set("Authorization", "Bearer "+access)
	var c capture
	env.server.requireMCPAuth(c.handler()).ServeHTTP(httptest.NewRecorder(), req)
	if !c.called || !c.access.MCPOnly || c.access.Principal.ID != "oidc:okta:ana" || c.access.Team() != "payments" {
		t.Fatalf("/mcp access = %+v", c.access)
	}
	if _, c := env.edge(t, env.server.requireAuth, access, header); c.called {
		t.Fatal("/v1 ran its handler for an MCP-only token")
	}
}

// mcpSandbox is a sandbox owned by team payments with no shell: a tool
// that reaches it proves the inner call resolved it as the caller, then
// stops before any toolbox call.
func mcpSandbox(id string) *models.Sandbox {
	now := time.Now().UTC()
	return &models.Sandbox{
		ID: id, Name: "agent", Image: "alpine", Status: models.SandboxStatusStarted, Runtime: models.RuntimeIsolate,
		OwnerRef: controlplane.TeamOwnerRef("payments"), CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		AuditIncarnationID: "inc-" + id,
	}
}

func mcpClient(t *testing.T, url, sandbox, bearer string) *mcp.ClientSession {
	t.Helper()
	transport := &mcp.StreamableClientTransport{
		Endpoint:   url + "/mcp?sandbox=" + sandbox,
		HTTPClient: &http.Client{Transport: bearerTransport{bearer}},
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func toolText(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (*mcp.CallToolResult, string) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return res, b.String()
}

// TestMCPToolCallUsesTheHandoff: a connector's access token, valid only on
// /mcp, drives tools whose inner calls hit /v1 routes in-process. They work
// because the edge uses the Access hand-off instead of re-checking the
// bearer; each is still authorized by its route and recorded once, naming
// the caller with surface mcp. The same token sent to /v1 directly is
// refused.
func TestMCPToolCallUsesTheHandoff(t *testing.T) {
	st := storeWith(t, "mcp-oauth", mcpSandbox("sb-00000000000000aa"))
	svc := service.New(config.Config{}, discardLogger(), st, nil, nil, caddy.New(config.Config{HTTPClientTimeout: time.Second}), nil, nil, nil)
	sink := &recSink{}
	svc.UseAuditSinkForTest(sink)
	env := newMCPOAuthEnv(t, config.Config{MCPEnabled: true, MCPRateLimit: 100}, svc)
	srv := httptest.NewServer(env.server.Handler())
	defer srv.Close()
	access := env.accessToken(t, "payments-eng")

	cs := mcpClient(t, srv.URL, "agent", access)
	if res, text := toolText(t, cs, "exec", map[string]any{"command": "echo"}); !res.IsError || !strings.Contains(text, "isolate sandboxes have no shell") {
		t.Fatalf("exec = %q; the name lookup must succeed as the caller through the hand-off", text)
	}
	sink.reset()
	toolText(t, cs, "expose_port", map[string]any{"port": 8080})
	recs := sink.waitRecords(t, 1)
	if len(recs) != 1 {
		t.Fatalf("one tool call wrote %d records: %+v", len(recs), recs)
	}
	ev := recs[0]
	want := &auditlog.Caller{Kind: "oidc", ID: "oidc:okta:ana", Name: "ana@acme.com", Team: "payments"}
	if ev.Ref != "POST /v1/sandboxes/{id}/ports/{port}" || ev.Request.Surface != auditlog.SurfaceMCP || !reflect.DeepEqual(ev.Caller, want) {
		t.Fatalf("tool call record = %+v caller %+v request %+v", ev, ev.Caller, ev.Request)
	}

	rec := do(t, env.server, http.MethodGet, "/v1/sandboxes?name=agent", access, "", nil)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "wrong_audience") {
		t.Fatalf("the access token straight to /v1 = %d %s", rec.Code, rec.Body.String())
	}
}

// TestMCPMissingHandoffIsServerError is finding 2.5: an inner call that
// reaches the edge without the hand-off (here /mcp served with no
// authentication, so there is no Access to hand over) gets 500, and the
// bearer it carries, though it is the valid PAT, is never checked.
func TestMCPMissingHandoffIsServerError(t *testing.T) {
	sb := mcpSandbox("sb-00000000000000aa")
	sb.OwnerRef = ""
	svc := service.New(config.Config{}, discardLogger(), storeWith(t, "mcp-nohandoff", sb), nil, nil, nil, nil, nil, nil)
	api := NewServer(discardLogger(), svc, nil, nil, config.Config{}, "pat-token", nil)
	h := remotemcp.New(remotemcp.Config{}, api.Handler)
	srv := httptest.NewServer(h.Wrap(func(next http.Handler) http.Handler { return next }))
	defer srv.Close()

	operatorBefore := 0
	for _, origin := range []string{"host", "peer", "public"} {
		operatorBefore += int(authCount(authRequests, "operator", origin))
	}
	failBefore := authCount(authFailures, authKindMCPHandoff, "no_handoff")
	cs := mcpClient(t, srv.URL, "agent", "pat-token")
	res, text := toolText(t, cs, "exec", map[string]any{"command": "echo"})
	if !res.IsError || strings.Contains(text, "isolate sandboxes have no shell") || !strings.Contains(text, "without its caller") {
		t.Fatalf("exec without a hand-off = %q; it must fail with the 500, never resolve the sandbox as the PAT", text)
	}
	if authCount(authFailures, authKindMCPHandoff, "no_handoff") <= failBefore {
		t.Fatal("aerolvm_auth_failures_total{mcp_handoff,no_handoff} did not move")
	}
	operatorAfter := 0
	for _, origin := range []string{"host", "peer", "public"} {
		operatorAfter += int(authCount(authRequests, "operator", origin))
	}
	if operatorAfter != operatorBefore {
		t.Fatalf("the PAT authenticated %d inner calls; the edge fell back to the bearer", operatorAfter-operatorBefore)
	}

	// The edge itself, one inner call: 500 with the internal-error body.
	inner := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
	inner.Header.Set("Authorization", "Bearer pat-token")
	ctx := auditlog.ContextWithSurface(inner.Context(), auditlog.SurfaceMCP)
	access, failure := api.authenticate(inner.WithContext(ctx), "pat-token")
	if failure != nil || access.Principal.Kind != controlplane.PrincipalOperator {
		t.Fatalf("a request that only looks like MCP (surface, no hand-off) is an ordinary request: %+v %+v", access, failure)
	}
}

// TestMCPForwardMarker: on a peer's forward marked X-Cluster-Surface: mcp
// the owner accepts the caller's MCP-only token, attributes the edge as
// Via and records the call as MCP. The same marker from a non-peer is a 403
// in cluster mode (clusterControlHeaderGuard), and on a single node it is
// dropped, so the token is refused like anywhere off /mcp.
func TestMCPForwardMarker(t *testing.T) {
	svc := service.New(config.Config{EnableCluster: true}, discardLogger(), nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&apiLivePeerCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
	env := newMCPOAuthEnv(t, config.Config{MCPEnabled: true, EnableCluster: true}, svc)
	access := env.accessToken(t, "payments-eng")
	marked := func(peer bool) http.Header {
		h := http.Header{}
		h.Set(cluster.HeaderForwarded, "1")
		h.Set(cluster.HeaderSurface, auditlog.SurfaceMCP)
		h.Set(HeaderTeam, "payments")
		if peer {
			h.Set(cluster.PeerNodeIDHeader, "peer-test")
		}
		return h
	}

	rec, owner := env.edge(t, env.server.requireAuth, access, marked(true))
	if rec.Code != http.StatusNoContent || !owner.access.MCPOnly || owner.access.Via != "peer-test" || owner.access.Team() != "payments" {
		t.Fatalf("peer MCP forward = %d %+v", rec.Code, owner.access)
	}
	unmarked := marked(true)
	unmarked.Del(cluster.HeaderSurface)
	if rec, c := env.edge(t, env.server.requireAuth, access, unmarked); rec.Code != http.StatusUnauthorized || c.called {
		t.Fatalf("a peer forward without the MCP marker = %d", rec.Code)
	}
	if rec, c := env.edge(t, env.server.requireAuth, access, marked(false)); rec.Code != http.StatusForbidden || c.called {
		t.Fatalf("the MCP marker from a non-peer in cluster mode = %d %s", rec.Code, rec.Body.String())
	}

	single := newMCPOAuthEnv(t, config.Config{MCPEnabled: true}, nil)
	rec, c := single.edge(t, single.server.requireAuth, single.accessToken(t, "payments-eng"), marked(false))
	if rec.Code != http.StatusUnauthorized || c.called || !strings.Contains(rec.Body.String(), "wrong_audience") {
		t.Fatalf("single node: the marker must be dropped and the token refused, got %d %s", rec.Code, rec.Body.String())
	}
}

// TestRequestSurface: the surface a record names comes from the in-process
// context, or from a live peer's forward marker, never from a header alone.
func TestRequestSurface(t *testing.T) {
	cases := []struct {
		name              string
		ctxSurface        string
		peer, fwd, marker bool
		want              string
	}{
		{name: "edge inner call", ctxSurface: auditlog.SurfaceMCP, want: "mcp"},
		{name: "SSH", ctxSurface: auditlog.SurfaceSSH, want: "ssh"},
		{name: "peer MCP forward", peer: true, fwd: true, marker: true, want: "mcp"},
		{name: "marker without a peer", fwd: true, marker: true},
		{name: "marker from a peer that is not forwarding", peer: true, marker: true},
		{name: "plain request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/exec", nil)
			if tc.ctxSurface != "" {
				r = r.WithContext(auditlog.ContextWithSurface(r.Context(), tc.ctxSurface))
			}
			if tc.peer {
				r.TLS = peerTLS("edge-1")
			}
			if tc.fwd {
				r.Header.Set(cluster.HeaderForwarded, "1")
			}
			if tc.marker {
				r.Header.Set(cluster.HeaderSurface, auditlog.SurfaceMCP)
			}
			if got := requestSurface(r); got != tc.want {
				t.Fatalf("surface = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMCPForwardRecordedOnOwner is UC-286's cross-node half offline: a
// connector's tool call on a sandbox another node owns is forwarded with
// the caller's own bearer and X-Cluster-Surface: mcp; the owner verifies
// the MCP-only token itself, runs the call and writes the one record, with
// surface mcp and the edge as via. The edge writes none.
func TestMCPForwardRecordedOnOwner(t *testing.T) {
	const id = "sb-00000000000000bb"
	ownerSvc := service.New(config.Config{EnableCluster: true}, discardLogger(), storeWith(t, "owner", mcpSandbox(id)), nil, nil,
		caddy.New(config.Config{HTTPClientTimeout: time.Second}), nil, nil, nil)
	ownerSink := &recSink{}
	ownerSvc.UseAuditSinkForTest(ownerSink)
	ownerSvc.AttachCluster(&openGateCluster{peerSideCluster{Noop: cluster.NewNoop("owner-1", "", ""), edge: "edge-1"}})
	env := newMCPOAuthEnv(t, config.Config{MCPEnabled: true, EnableCluster: true}, ownerSvc)
	owner := env.server

	edgeSvc := service.New(config.Config{EnableCluster: true}, discardLogger(), storeWith(t, "edge"), nil, nil, nil, nil, nil, nil)
	edgeSink := &recSink{}
	edgeSvc.UseAuditSinkForTest(edgeSink)
	edgeSvc.AttachCluster(&forwardingCluster{Noop: cluster.NewNoop("edge-1", "", ""), owner: owner})
	edge := NewServer(discardLogger(), edgeSvc, nil, nil, config.Config{IdentityEnabled: true, EnableCluster: true, MCPEnabled: true, MCPRateLimit: 100},
		"pat-token", nil, env.options()...)
	srv := httptest.NewServer(edge.Handler())
	defer srv.Close()

	cs := mcpClient(t, srv.URL, id, env.accessToken(t, "payments-eng"))
	if res, text := toolText(t, cs, "exec", map[string]any{"command": "echo"}); !res.IsError || !strings.Contains(text, "isolate sandboxes have no shell") {
		t.Fatalf("exec on another node's sandbox = %q; the owner must accept the forwarded MCP-only token", text)
	}
	ownerSink.reset()
	edgeSink.reset()
	toolText(t, cs, "expose_port", map[string]any{"port": 8080})
	// The owner writes the record after the response it streams back, so
	// wait for it; the edge is checked after that wait, so a record it
	// wrongly wrote has had time to land too.
	got := ownerSink.waitRecords(t, 1)
	if got := edgeSink.records(); len(got) != 0 {
		t.Fatalf("the edge recorded a call it forwarded: %+v", got)
	}
	if len(got) != 1 {
		t.Fatalf("owner records = %d, want 1: %+v", len(got), got)
	}
	want := &auditlog.Caller{Kind: "oidc", ID: "oidc:okta:ana", Name: "ana@acme.com", Team: "payments", Via: "edge-1"}
	if got[0].Request == nil || got[0].Request.Surface != auditlog.SurfaceMCP || !reflect.DeepEqual(got[0].Caller, want) || got[0].SandboxID != id {
		t.Fatalf("owner record = %+v caller %+v", got[0], got[0].Caller)
	}
}

// TestEntraV1TokenHint: an Entra v1 access token for a trusted tenant gets
// unknown_issuer plus the accessTokenAcceptedVersion hint in the body, on
// /v1 and on /mcp (after the challenge); any other unknown issuer gets the
// plain D17 body.
func TestEntraV1TokenHint(t *testing.T) {
	env := newMCPOAuthEnv(t, config.Config{MCPEnabled: true}, nil)
	mint := func(iss string) string {
		c := env.iss.Claims(time.Now(), "0a1b-api-app", "ana", "payments-eng")
		c["iss"], c["ver"] = iss, "1.0"
		return env.iss.Mint(t, c)
	}
	v1 := mint("https://sts.windows.net/" + mcpTestTenant + "/")
	hinted := `{"error":"unauthorized (` + identity.EntraV1Hint + `)","reason":"unknown_issuer"}` + "\n"
	errParams := `error="invalid_token", error_description="unknown_issuer"`

	rec := do(t, env.server, http.MethodGet, "/v1/whoami", v1, "", nil)
	if rec.Code != http.StatusUnauthorized || rec.Body.String() != hinted || rec.Header().Get("WWW-Authenticate") != "Bearer "+errParams {
		t.Fatalf("v1: %d %v %q", rec.Code, rec.Header(), rec.Body.String())
	}
	rec = do(t, env.server, http.MethodPost, "/mcp?sandbox=agent", v1, "", nil)
	if rec.Code != http.StatusUnauthorized || rec.Body.String() != hinted || rec.Header().Get("WWW-Authenticate") != mcpTestChallenge+", "+errParams {
		t.Fatalf("mcp: %d %v %q", rec.Code, rec.Header(), rec.Body.String())
	}
	rec = do(t, env.server, http.MethodGet, "/v1/whoami", mint("https://evil.example"), "", nil)
	if rec.Body.String() != `{"error":"unauthorized","reason":"unknown_issuer"}`+"\n" {
		t.Fatalf("another unknown issuer: %q", rec.Body.String())
	}
}

// stampCapturingCluster is an edge whose every sandbox lives on owner-1: its
// ForwardHTTP stamps the outbound request the way the reverse-proxy
// Director does, keeps the headers the owner would have seen, and answers
// 404 instead of delivering it.
type stampCapturingCluster struct {
	*cluster.Noop
	mu   sync.Mutex
	seen []http.Header
}

func (c *stampCapturingCluster) AuditCallerWritesAllowed() bool { return true }
func (c *stampCapturingCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return cluster.OwnerInfo{NodeID: "owner-1", InternalURL: "https://owner-1.internal"}, nil
}
func (c *stampCapturingCluster) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	out := r.Clone(r.Context())
	access, _ := controlplane.AccessFromContext(r.Context())
	cluster.StampForward(out, access)
	c.mu.Lock()
	c.seen = append(c.seen, out.Header.Clone())
	c.mu.Unlock()
	apihttp.WriteError(w, http.StatusNotFound, "sandbox not found")
}

func (c *stampCapturingCluster) forwards() []http.Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]http.Header(nil), c.seen...)
}

// stampCapturingEdge is a cluster-mode edge with remote MCP on, over c.
func stampCapturingEdge(t *testing.T, cfg config.Config, c *stampCapturingCluster, opts ...ServerOption) *httptest.Server {
	t.Helper()
	svc := service.New(config.Config{EnableCluster: true}, discardLogger(), storeWith(t, "capture-edge"), nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(c)
	cfg.EnableCluster, cfg.MCPEnabled, cfg.MCPRateLimit = true, true, 100
	srv := httptest.NewServer(NewServer(discardLogger(), svc, nil, nil, cfg, "pat-token", nil, opts...).Handler())
	t.Cleanup(srv.Close)
	return srv
}

// teamTransport sends the bearer and an X-AerolVM-Team on every request, as
// a connector configured for one of the caller's teams would.
type teamTransport struct{ token, team string }

func (b teamTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	r.Header.Set(HeaderTeam, b.team)
	return http.DefaultTransport.RoundTrip(r)
}

// TestMCPInnerCallTeamIsTheCallers: an inner call acts for the team the
// caller selected on /mcp (here the second of two bindings), never for the
// team in sandboxd's own SB_TEAM, which the Go SDK client falls back to
// when its Team is empty (T9). Locally the hand-off carries the selection;
// on a forward, StampForward puts exactly that team on the wire.
func TestMCPInnerCallTeamIsTheCallers(t *testing.T) {
	t.Setenv("SB_TEAM", "daemon-team")
	connect := func(t *testing.T, url, sandbox, bearer string) *mcp.ClientSession {
		t.Helper()
		transport := &mcp.StreamableClientTransport{
			Endpoint:   url + "/mcp?sandbox=" + sandbox,
			HTTPClient: &http.Client{Transport: teamTransport{token: bearer, team: "billing"}},
		}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(context.Background(), transport, nil)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		t.Cleanup(func() { _ = cs.Close() })
		return cs
	}

	t.Run("local sandbox: the hand-off carries the selected team", func(t *testing.T) {
		sb := mcpSandbox("sb-00000000000000cc")
		sb.OwnerRef = controlplane.TeamOwnerRef("billing")
		svc := service.New(config.Config{}, discardLogger(), storeWith(t, "team-local", sb), nil, nil,
			caddy.New(config.Config{HTTPClientTimeout: time.Second}), nil, nil, nil)
		sink := &recSink{}
		svc.UseAuditSinkForTest(sink)
		env := newMCPOAuthEnv(t, config.Config{MCPEnabled: true, MCPRateLimit: 100}, svc)
		srv := httptest.NewServer(env.server.Handler())
		defer srv.Close()
		// Bound to payments first, billing second: without the selection
		// (or with the daemon's team) the billing sandbox is not visible.
		cs := connect(t, srv.URL, "agent", env.accessToken(t, "payments-eng", "billing-eng"))
		if res, text := toolText(t, cs, "exec", map[string]any{"command": "echo"}); !res.IsError || !strings.Contains(text, "isolate sandboxes have no shell") {
			t.Fatalf("exec on the selected team's sandbox = %q", text)
		}
		sink.reset()
		toolText(t, cs, "expose_port", map[string]any{"port": 8080})
		if got := sink.waitRecords(t, 1); len(got) != 1 || got[0].Caller == nil || got[0].Caller.Team != "billing" {
			t.Fatalf("the inner call's record must name team billing: %+v", got)
		}
	})

	t.Run("forwarded sandbox: the wire carries the selected team", func(t *testing.T) {
		env := newMCPOAuthEnv(t, config.Config{MCPEnabled: true}, nil)
		c := &stampCapturingCluster{Noop: cluster.NewNoop("edge-1", "", "")}
		srv := stampCapturingEdge(t, config.Config{IdentityEnabled: true}, c, env.options()...)
		cs := connect(t, srv.URL, "sb-00000000000000dd", env.accessToken(t, "payments-eng", "billing-eng"))
		toolText(t, cs, "exec", map[string]any{"command": "echo"})
		forwards := c.forwards()
		if len(forwards) == 0 {
			t.Fatal("the inner call on another node's sandbox was never forwarded")
		}
		for i, h := range forwards {
			if got := h.Values(HeaderTeam); len(got) != 1 || got[0] != "billing" {
				t.Fatalf("forward %d carried %s = %q, want exactly [billing]", i, HeaderTeam, got)
			}
			if h.Get(cluster.HeaderSurface) != auditlog.SurfaceMCP {
				t.Fatalf("forward %d has no MCP surface marker: %v", i, h)
			}
		}
	})
}

// TestMCPForwardKeepsThePATOrigin is T10's laundering rule through remote
// MCP: a forwarded inner call says where /mcp itself accepted the operator
// token. A PAT that Caddy relayed from a public client (X-AerolVM-Client-IP
// with PROXY protocol on) stays public on the forward, even though the inner
// call reaches the API in-process from a loopback address; a PAT from a
// loopback client stays host.
func TestMCPForwardKeepsThePATOrigin(t *testing.T) {
	cases := []struct {
		name     string
		clientIP string
		want     string
	}{
		{"PAT relayed by Caddy from a public client", "203.0.113.9", cluster.PATOriginPublic},
		{"PAT from a loopback client on the host", "", cluster.PATOriginHost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &stampCapturingCluster{Noop: cluster.NewNoop("edge-1", "", "")}
			srv := stampCapturingEdge(t, config.Config{L4FallbackProxyProtocol: true}, c)
			headers := map[string]string{"Authorization": "Bearer pat-token"}
			if tc.clientIP != "" {
				headers[HeaderClientIP] = tc.clientIP
			}
			transport := &mcp.StreamableClientTransport{
				Endpoint:   srv.URL + "/mcp?sandbox=sb-00000000000000ee",
				HTTPClient: &http.Client{Transport: headerSetTransport{headers}},
			}
			cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(context.Background(), transport, nil)
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			defer cs.Close()
			toolText(t, cs, "exec", map[string]any{"command": "echo"})
			forwards := c.forwards()
			if len(forwards) == 0 {
				t.Fatal("the inner call was never forwarded")
			}
			for i, h := range forwards {
				if got := h.Get(cluster.HeaderPATOrigin); got != tc.want {
					t.Fatalf("forward %d: %s = %q, want %q", i, cluster.HeaderPATOrigin, got, tc.want)
				}
			}
		})
	}
}

// TestMCPOAuthOnThePublicSocket: under SB_PAT_SCOPE=host Caddy reaches
// sandboxd through the public socket (PublicHandler), so the RFC 9728
// metadata and the /mcp challenge must be served there too; a PAT on /mcp
// there is refused with the host-scope text, still with the challenge.
func TestMCPOAuthOnThePublicSocket(t *testing.T) {
	env := newMCPOAuthEnv(t, config.Config{MCPEnabled: true, PATScope: config.PATScopeHost}, nil)
	public := env.server.PublicHandler()
	serve := func(method, path, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "@"
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		public.ServeHTTP(rec, req)
		return rec
	}
	if rec := serve(http.MethodGet, remotemcp.MetadataPath+remotemcp.Path, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), mcpTestResource) {
		t.Fatalf("metadata on the public socket = %d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(http.MethodPost, "/mcp?sandbox=agent", ""); rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != mcpTestChallenge {
		t.Fatalf("/mcp with no token on the public socket = %d %v", rec.Code, rec.Header())
	}
	rec := serve(http.MethodPost, "/mcp?sandbox=agent", "pat-token")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), patScopeMessage) || rec.Header().Get("WWW-Authenticate") != mcpTestChallenge {
		t.Fatalf("PAT on /mcp through the public socket = %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
}

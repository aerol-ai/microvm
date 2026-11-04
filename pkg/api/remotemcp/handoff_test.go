package remotemcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// mcpCaller is an MCP-only OIDC caller: the Access an OAuth access token
// for an mcp_audiences audience resolves to on /mcp.
func mcpCaller() controlplane.Access {
	a := controlplane.OIDCAccess(controlplane.Principal{Kind: controlplane.PrincipalOIDC, ID: "oidc:okta:00u1", Name: "ana@acme.com"},
		[]controlplane.TeamBinding{{Role: controlplane.RoleRunner, Team: "payments"}}, time.Time{})
	a.MCPOnly = true
	return a
}

func TestHandoffFromContext(t *testing.T) {
	var none context.Context // a nil context must not panic
	if _, inner, _ := Handoff(none); inner {
		t.Fatal("a nil context is not an inner call")
	}
	if _, inner, _ := Handoff(context.Background()); inner {
		t.Fatal("a plain context is not an inner call")
	}
	if _, inner, _ := Handoff(controlplane.ContextWithAccess(context.Background(), mcpCaller())); inner {
		t.Fatal("an Access in context is not the hand-off: only inProcessTransport marks an inner call")
	}
	access, inner, ok := Handoff(contextWithHandoff(context.Background(), mcpCaller(), true))
	if !inner || !ok || access.Principal.ID != "oidc:okta:00u1" || !access.MCPOnly {
		t.Fatalf("hand-off = %+v inner %v ok %v", access, inner, ok)
	}
	if _, inner, ok := Handoff(contextWithHandoff(context.Background(), controlplane.Access{}, false)); !inner || ok {
		t.Fatalf("a hand-off without an Access must still mark the inner call (inner %v ok %v)", inner, ok)
	}
}

// TestInProcessTransportCarriesHandoff: every inner request carries the
// hand-off, the MCP surface and the caller's own bearer (for forwards); a
// team header the SDK client set from its own defaults never reaches the
// API, because the team is the hand-off's.
func TestInProcessTransportCarriesHandoff(t *testing.T) {
	type seen struct {
		access         controlplane.Access
		inner, ok      bool
		surface        string
		auth, team     string
		remote, target string
		patOrigin      string
	}
	var got seen
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.access, got.inner, got.ok = Handoff(r.Context())
		got.surface = auditlog.SurfaceFromContext(r.Context())
		got.auth, got.team = r.Header.Get("Authorization"), r.Header.Get(cluster.HeaderTeam)
		got.remote, got.target = r.RemoteAddr, r.RequestURI
		got.patOrigin = cluster.PATOriginFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	for _, tc := range []struct {
		name      string
		hasAccess bool
		patOrigin string
	}{
		{name: "with the caller's Access", hasAccess: true},
		{name: "a PAT caller keeps the origin /mcp accepted it from", hasAccess: true, patOrigin: cluster.PATOriginPublic},
		{name: "without one (a bug the edge answers with 500)", hasAccess: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got = seen{}
			client := &http.Client{Transport: &inProcessTransport{handler: handler, remoteAddr: "203.0.113.9:1234",
				access: mcpCaller(), hasAccess: tc.hasAccess, patOrigin: tc.patOrigin}}
			req, _ := http.NewRequest(http.MethodGet, "http://in-process/v1/sandboxes?name=agent", nil)
			req.Header.Set("Authorization", "Bearer caller-token")
			req.Header.Set(cluster.HeaderTeam, "daemon-default-team")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if !got.inner || got.ok != tc.hasAccess || got.surface != auditlog.SurfaceMCP {
				t.Fatalf("inner %v ok %v surface %q", got.inner, got.ok, got.surface)
			}
			if tc.hasAccess && got.access.Principal.ID != "oidc:okta:00u1" {
				t.Fatalf("hand-off access = %+v", got.access)
			}
			if got.auth != "Bearer caller-token" || got.team != "" || got.remote != "203.0.113.9:1234" || got.target != "/v1/sandboxes?name=agent" {
				t.Fatalf("inner request: auth %q team %q remote %q target %q", got.auth, got.team, got.remote, got.target)
			}
			if req.Header.Get(cluster.HeaderTeam) != "daemon-default-team" {
				t.Fatal("the transport must not modify the SDK's own request")
			}
			if got.patOrigin != tc.patOrigin {
				t.Fatalf("PAT origin = %q, want %q", got.patOrigin, tc.patOrigin)
			}
		})
	}
}

// innerRecorder wraps the fake API and records what every inner call saw.
type innerRecorder struct {
	next  http.Handler
	mu    sync.Mutex
	calls []innerCall
}

type innerCall struct {
	auth, team string
	access     controlplane.Access
	inner, ok  bool
}

func (rec *innerRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	access, inner, ok := Handoff(r.Context())
	rec.mu.Lock()
	rec.calls = append(rec.calls, innerCall{auth: r.Header.Get("Authorization"), team: r.Header.Get(cluster.HeaderTeam),
		access: access, inner: inner, ok: ok})
	rec.mu.Unlock()
	rec.next.ServeHTTP(w, r)
}

func (rec *innerRecorder) snapshot() []innerCall {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]innerCall(nil), rec.calls...)
}

// handoffEndpoint is /mcp with an auth step that resolves the caller like
// the API edge does: it attaches the Access, or refuses a wrong bearer.
// With bearerless set it attaches an Access to a request that has no
// bearer at all, the shape E4 guards against.
func handoffEndpoint(t *testing.T, bearerless bool) (*endpoint, *innerRecorder) {
	t.Helper()
	fake := agenttoolstest.New(t)
	rec := &innerRecorder{next: fake.Config.Handler}
	h := New(Config{}, func() http.Handler { return rec })
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !bearerless && r.Header.Get("Authorization") != "Bearer "+agenttoolstest.Token {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), mcpCaller())))
		})
	}
	srv := httptest.NewServer(h.Wrap(auth))
	t.Cleanup(srv.Close)
	return &endpoint{t: t, fake: fake, server: srv}, rec
}

// TestRemoteToolCallsUseTheHandoff is ET7's inner-call identity test: every
// inner API call a tool makes carries the Access /mcp resolved and the
// caller's own bearer, never the daemon's SB_PAT_TOKEN (eng review E4), and
// never the team in the daemon's SB_TEAM, which the Go SDK client sends
// when its Team is empty (T9): the caller's team is the hand-off's.
func TestRemoteToolCallsUseTheHandoff(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "operator-pat")
	t.Setenv("SB_TEAM", "daemon-team")
	e, rec := handoffEndpoint(t, false)
	e.fake.AddSandbox(models.Sandbox{Name: "agent"})
	cs := e.connect("sandbox=agent")
	if res, text := callText(t, cs, "exec", map[string]any{"command": "echo hi"}); res.IsError {
		t.Fatalf("exec = %q", text)
	}
	calls := rec.snapshot()
	if len(calls) < 2 {
		t.Fatalf("a tool call made %d inner calls, want the lookup and the exec", len(calls))
	}
	for i, c := range calls {
		if !c.inner || !c.ok || c.access.Principal.ID != "oidc:okta:00u1" || !c.access.MCPOnly {
			t.Fatalf("inner call %d: hand-off %+v inner %v ok %v", i, c.access, c.inner, c.ok)
		}
		if c.auth != "Bearer "+agenttoolstest.Token || strings.Contains(c.auth, "operator-pat") {
			t.Fatalf("inner call %d carried %q, want the caller's own bearer", i, c.auth)
		}
		if c.team != "" || c.access.Team() != "payments" {
			t.Fatalf("inner call %d: team header %q, hand-off team %q; want no header and the caller's team", i, c.team, c.access.Team())
		}
	}
}

// TestRemoteEmptyBearerNeverReachesTools is E4: a request that got past
// authentication with no bearer at all is refused with 400 before any tool
// runs, so no inner call is ever made with the SDK's SB_PAT_TOKEN fallback.
func TestRemoteEmptyBearerNeverReachesTools(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "operator-pat")
	e, rec := handoffEndpoint(t, true)
	e.fake.AddSandbox(models.Sandbox{Name: "agent"})
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","arguments":{"command":"id"}}}`
	for name, body := range map[string]string{"initialize": "", "tools/call": call} {
		req, _ := http.NewRequest(http.MethodPost, e.server.URL+Path+"?sandbox=agent", strings.NewReader(body))
		if body == "" {
			req, _ = http.NewRequest(http.MethodPost, e.server.URL+Path+"?sandbox=agent",
				strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`))
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s with no bearer = %d, want 400", name, resp.StatusCode)
		}
	}
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("an empty bearer reached the API %d times: %+v", len(calls), calls)
	}
}

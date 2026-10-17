package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/daytona"
	"github.com/aerol-ai/microvm/pkg/api/e2b"
	"github.com/aerol-ai/microvm/pkg/api/remotemcp"
	"github.com/aerol-ai/microvm/pkg/api/runloop"
	v1 "github.com/aerol-ai/microvm/pkg/api/v1"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func TestRemoteMCPRouteIsOptIn(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	off := httptest.NewServer(NewServer(logger, nil, nil, nil, config.Config{}, "pat-token", nil).Handler())
	defer off.Close()
	resp, err := http.Post(off.URL+"/mcp?sandbox=a", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/mcp with SB_MCP_ENABLED off = %d, want 404", resp.StatusCode)
	}
}

// TestRemoteMCPThroughRealAPI drives /mcp on a real API server: the bearer
// check guards it, and a tool call reaches the v1 API in-process with the
// caller's token (the name lookup succeeds; the toolbox is absent here, so
// the call ends in a tool error rather than an auth failure).
func TestRemoteMCPThroughRealAPI(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "mcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-00000000000000aa", Name: "agent", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeIsolate, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	srv := httptest.NewServer(NewServer(logger, svc, nil, nil, config.Config{MCPEnabled: true, MCPRateLimit: 100}, "pat-token", nil).Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/mcp?sandbox=agent", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token = %d, want 401", resp.StatusCode)
	}

	transport := &mcp.StreamableClientTransport{
		Endpoint:   srv.URL + "/mcp?sandbox=agent",
		HTTPClient: &http.Client{Transport: bearerTransport{"pat-token"}},
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cs.Close()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "exec", Arguments: map[string]any{"command": "echo"}})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	// Resolving "agent" went through GET /v1/sandboxes?name= with the PAT;
	// the isolate guard then refuses before any toolbox call.
	if !res.IsError || !strings.Contains(text, "isolate sandboxes have no shell") {
		t.Fatalf("remote exec = %q", text)
	}
}

// TestCaddyForwardsRemoteMCP: in domain mode Caddy forwards only the paths
// its @api matcher lists, so a /mcp missing there is unreachable through the
// API domain even with SB_MCP_ENABLED=true. Both Caddyfile sources the
// installers write must list it.
// The stock Caddy configs answer anything outside their @api matcher with a
// 404 of their own, so every surface sandboxd mounts must be listed there —
// each facade's prefix and everything under it, and the two public
// discovery documents (§5.6 sign-in discovery; §5.14 RFC 9728 metadata, in
// both its root and path forms, through one prefix matcher).
func TestCaddyForwardsEverySurface(t *testing.T) {
	want := []string{remotemcp.Path, identitywire.AuthDiscoveryPath, "/.well-known/oauth-protected-resource*"}
	for _, prefix := range []string{v1.PathPrefix, daytona.PathPrefix, e2b.PathPrefix, runloop.PathPrefix} {
		want = append(want, prefix, prefix+"/*")
	}
	for _, file := range []string{"../../scripts/install.sh", "../../packaging/Caddyfile.template"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var matchers []string
		for _, line := range strings.Split(string(raw), "\n") {
			if fields := strings.Fields(line); len(fields) > 2 && fields[0] == "@api" && fields[1] == "path" {
				matchers = append(matchers, line)
				for _, path := range want {
					if !slices.Contains(fields[2:], path) {
						t.Errorf("%s: %q does not forward %s to sandboxd", file, strings.TrimSpace(line), path)
					}
				}
			}
		}
		if len(matchers) == 0 {
			t.Errorf("%s has no @api path matcher; the check would pass vacuously", file)
		}
	}
}

// TestRemoteMCPSubprotocolTokenIsNotOperator is a regression test for the
// privilege-escalation bug where a customer token sent via
// Sec-WebSocket-Protocol passed auth but the MCP handler read only the
// Authorization header, handed the tools an empty token, and the SDK then fell
// back to SB_PAT_TOKEN (the daemon's operator PAT) — running every tool as the
// operator against any sandbox the caller could name. The tools must act as the
// caller's own (owner-scoped) identity, so a user token can never resolve
// another tenant's sandbox by id.
func TestRemoteMCPSubprotocolTokenIsNotOperator(t *testing.T) {
	// A real daemon always has SB_PAT_TOKEN in its environment.
	t.Setenv("SB_PAT_TOKEN", "pat-token")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "mcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	const victimID = "sb-00000000000000aa"
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: victimID, Name: "victim", OwnerRef: "acct-A", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeIsolate, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	validator := stubValidator{accept: "tok-b", identity: controlplane.Identity{ExternalID: "user-b", OwnerRef: "acct-B"}}
	srv := httptest.NewServer(NewServer(logger, svc, nil, nil, config.Config{MCPEnabled: true, MCPRateLimit: 100}, "pat-token", validator).Handler())
	defer srv.Close()

	call := func(headers map[string]string) string {
		t.Helper()
		transport := &mcp.StreamableClientTransport{
			Endpoint:   srv.URL + "/mcp?sandbox=" + victimID,
			HTTPClient: &http.Client{Transport: headerSetTransport{headers}},
		}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(context.Background(), transport, nil)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer cs.Close()
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "exec", Arguments: map[string]any{"command": "echo"}})
		if err != nil {
			t.Fatal(err)
		}
		return res.Content[0].(*mcp.TextContent).Text
	}

	// Baseline: B via the Authorization header is owner-scoped and cannot see A's sandbox.
	hdr := call(map[string]string{"Authorization": "Bearer tok-b"})
	if strings.Contains(hdr, "isolate sandboxes have no shell") {
		t.Fatalf("B via Authorization resolved A's sandbox: %q", hdr)
	}
	// Regression: the same token via the subprotocol must also be owner-scoped —
	// it must NOT reach A's sandbox (which would prove it ran as the operator).
	sub := call(map[string]string{"Sec-WebSocket-Protocol": "sandbox.bearer, tok-b"})
	if strings.Contains(sub, "isolate sandboxes have no shell") {
		t.Fatalf("subprotocol token escalated to operator and reached A's sandbox: %q", sub)
	}
	if !strings.Contains(sub, "does not exist") {
		t.Fatalf("expected B to get a not-found for A's sandbox, got %q", sub)
	}
}

type headerSetTransport struct{ headers map[string]string }

func (h headerSetTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.headers {
		r.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r)
}

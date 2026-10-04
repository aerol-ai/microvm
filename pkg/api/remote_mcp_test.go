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
	"github.com/aerol-ai/microvm/pkg/api/remotemcp"
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
func TestCaddyForwardsRemoteMCP(t *testing.T) {
	for _, file := range []string{"../../scripts/install.sh", "../../packaging/Caddyfile.template"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var matchers []string
		for _, line := range strings.Split(string(raw), "\n") {
			if fields := strings.Fields(line); len(fields) > 2 && fields[0] == "@api" && fields[1] == "path" {
				matchers = append(matchers, line)
				if !slices.Contains(fields[2:], remotemcp.Path) {
					t.Errorf("%s: %q does not forward %s to sandboxd", file, strings.TrimSpace(line), remotemcp.Path)
				}
			}
		}
		if len(matchers) == 0 {
			t.Errorf("%s has no @api path matcher; the check would pass vacuously", file)
		}
	}
}

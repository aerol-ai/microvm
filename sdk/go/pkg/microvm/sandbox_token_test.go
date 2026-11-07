package microvm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Sandbox.CreateToken posts the scope to the sandbox's tokens route and
// returns the token as the server answered it; a 400 is an error.
func TestSandboxCreateToken(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	status := http.StatusCreated
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status >= 400 {
			_ = json.NewEncoder(w).Encode(models.ErrorResponse{Error: "invalid sandbox token request: expires_in is required"})
			return
		}
		_ = json.NewEncoder(w).Encode(models.SandboxToken{
			Token: "avmst_0.p.s", TokenID: "stk_abc", SandboxID: "sb1", PathPrefix: "/files",
			Methods: []string{"GET"}, ExpiresAt: time.Date(2026, 11, 6, 10, 15, 0, 0, time.UTC),
		})
	}))
	defer server.Close()
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{APIUrl: server.URL, PATToken: "pat"})
	if err != nil {
		t.Fatal(err)
	}
	sb := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb1"}, client: client}
	tok, err := sb.CreateToken(context.Background(), sdktypes.CreateSandboxTokenOptions{
		ExpiresIn: "15m", PathPrefix: "/files", Methods: []string{"GET"},
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/sandboxes/sb1/tokens" {
		t.Fatalf("request = %s %s", gotMethod, gotPath)
	}
	if gotBody["expires_in"] != "15m" || gotBody["path_prefix"] != "/files" || gotBody["port"] != nil {
		t.Fatalf("body = %v", gotBody)
	}
	if tok.Token != "avmst_0.p.s" || tok.TokenID != "stk_abc" || tok.SandboxID != "sb1" || tok.ExpiresAt.IsZero() {
		t.Fatalf("token = %+v", tok)
	}

	status = http.StatusBadRequest
	if _, err := sb.CreateToken(context.Background(), sdktypes.CreateSandboxTokenOptions{}); err == nil {
		t.Fatal("a 400 was not an error")
	}
}

// Sandbox.RevokeTokens and Client.RevokeSandboxTokens post to the revoke
// route and return the not-before; a 404 is an error.
func TestSandboxRevokeTokens(t *testing.T) {
	var gotPaths []string
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status >= 400 {
			_ = json.NewEncoder(w).Encode(models.ErrorResponse{Error: "sandbox not found"})
			return
		}
		_ = json.NewEncoder(w).Encode(models.RevokeSandboxTokensResponse{
			SandboxID: "sb1", TokensNotBefore: time.Date(2026, 11, 7, 10, 0, 1, 0, time.UTC),
		})
	}))
	defer server.Close()
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{APIUrl: server.URL, PATToken: "pat"})
	if err != nil {
		t.Fatal(err)
	}
	sb := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb1"}, client: client}
	got, err := sb.RevokeTokens(context.Background())
	if err != nil || got.SandboxID != "sb1" || got.TokensNotBefore.IsZero() {
		t.Fatalf("RevokeTokens = %+v, %v", got, err)
	}
	if _, err := client.RevokeSandboxTokens(context.Background(), "sb1"); err != nil {
		t.Fatalf("RevokeSandboxTokens: %v", err)
	}
	if len(gotPaths) != 2 || gotPaths[0] != "POST /v1/sandboxes/sb1/tokens/revoke" || gotPaths[1] != gotPaths[0] {
		t.Fatalf("requests = %v", gotPaths)
	}
	status = http.StatusNotFound
	if _, err := sb.RevokeTokens(context.Background()); err == nil {
		t.Fatal("a 404 was not an error")
	}
}

// ExposePort sends visibility only when WithVisibility set it.
func TestExposePortVisibility(t *testing.T) {
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, 256)
		n, _ := r.Body.Read(raw)
		bodies = append(bodies, string(raw[:n]))
		resp := models.ExposePortResponse{Protocol: "http", PublicURL: "https://sb1-3000.example"}
		if strings.Contains(string(raw[:n]), "token") {
			resp.Visibility = "token"
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{APIUrl: server.URL, PATToken: "pat"})
	if err != nil {
		t.Fatal(err)
	}
	sb := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb1"}, client: client}
	got, err := sb.ExposePort(context.Background(), 3000, WithVisibility(sdktypes.ExposeVisibilityToken))
	if err != nil || got.Visibility != "token" {
		t.Fatalf("token expose = %+v, %v", got, err)
	}
	if _, err := sb.ExposePort(context.Background(), 3000); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || strings.TrimSpace(bodies[0]) != `{"visibility":"token"}` || bodies[1] != "" {
		t.Fatalf("bodies = %q", bodies)
	}
}

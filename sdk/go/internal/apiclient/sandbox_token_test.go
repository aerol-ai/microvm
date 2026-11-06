package apiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// CreateSandboxToken posts to the sandbox's tokens route, from the client
// and from a Sandbox handle alike.
func TestCreateSandboxToken(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(models.SandboxToken{Token: "avmst_0.p.s", TokenID: "stk_x", SandboxID: "sb1", Port: 3000})
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "pat-token", HTTPClient: server.Client()})
	sb := &Sandbox{Sandbox: models.Sandbox{ID: "sb1"}, client: client}
	tok, err := sb.CreateToken(context.Background(), models.CreateSandboxTokenRequest{ExpiresIn: "1h", Port: 3000})
	if err != nil || tok.Port != 3000 || tok.TokenID != "stk_x" {
		t.Fatalf("CreateToken = %+v, %v", tok, err)
	}
	if len(paths) != 1 || paths[0] != "POST /v1/sandboxes/sb1/tokens" {
		t.Fatalf("requests = %v", paths)
	}
}

// RevokeSandboxTokens posts no body to the revoke route, from the client and
// from a Sandbox handle alike, and reads the not-before.
func TestRevokeSandboxTokens(t *testing.T) {
	var paths []string
	var bodies []int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		bodies = append(bodies, r.ContentLength)
		_ = json.NewEncoder(w).Encode(models.RevokeSandboxTokensResponse{SandboxID: "sb1", TokensNotBefore: time.Unix(1_800_000_001, 0).UTC()})
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "pat-token", HTTPClient: server.Client()})
	sb := &Sandbox{Sandbox: models.Sandbox{ID: "sb1"}, client: client}
	got, err := sb.RevokeTokens(context.Background())
	if err != nil || got.SandboxID != "sb1" || got.TokensNotBefore.Unix() != 1_800_000_001 {
		t.Fatalf("RevokeTokens = %+v, %v", got, err)
	}
	if _, err := client.RevokeSandboxTokens(context.Background(), "sb1"); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "POST /v1/sandboxes/sb1/tokens/revoke" || paths[1] != paths[0] || bodies[0] > 0 {
		t.Fatalf("requests = %v, body lengths %v", paths, bodies)
	}
}

package harness

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func shortPropagationPoll(t *testing.T) {
	prev := tokenPropagationPoll
	tokenPropagationPoll = 5 * time.Millisecond
	t.Cleanup(func() { tokenPropagationPoll = prev })
}

func TestAPIClientSendsCredentialAndTeam(t *testing.T) {
	var gotAuth, gotTeam, gotType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotTeam, gotType = r.Header.Get("Authorization"), r.Header.Get(HeaderTeam), r.Header.Get("Content-Type")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tokens":
			var req models.CreateAPITokenRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(models.CreatedAPIToken{APIToken: models.APIToken{ID: "tok_1", Name: req.Name, Role: req.Role, Team: req.Team}, Token: "avm_secret"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tokens":
			_ = json.NewEncoder(w).Encode(models.APITokenList{Tokens: []models.APIToken{{ID: "tok_1"}}})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/tokens/tok_1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/tokens/tok_gone":
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	c := NewAPIClient(srv.URL+"/", "pat")

	created, err := c.CreateToken(ctx, models.CreateAPITokenRequest{Name: "n", Role: "runner", Team: TeamPayments, ExpiresIn: "1h"})
	if err != nil || created.ID != "tok_1" || created.Token != "avm_secret" || created.Team != TeamPayments {
		t.Fatalf("create = %+v, %v", created, err)
	}
	if gotAuth != "Bearer pat" || gotTeam != "" || gotType != "application/json" {
		t.Fatalf("headers = %q %q %q", gotAuth, gotTeam, gotType)
	}
	if list, err := c.ListTokens(ctx); err != nil || len(list.Tokens) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	// As and WithTeam copy; the original keeps its credential.
	scoped := c.As("avm_x").WithTeam(TeamCheckout)
	if _, err := scoped.Do(ctx, http.MethodGet, "/v1/tokens", nil); err != nil || gotAuth != "Bearer avm_x" || gotTeam != TeamCheckout {
		t.Fatalf("scoped headers = %q %q (%v)", gotAuth, gotTeam, err)
	}
	if c.Bearer != "pat" || c.Team != "" {
		t.Fatal("As/WithTeam changed the original client")
	}
	if err := c.RevokeToken(ctx, "tok_1"); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeToken(ctx, "tok_gone"); err != nil {
		t.Fatalf("revoking a token already gone must count as revoked: %v", err)
	}
	if err := c.RevokeToken(ctx, "tok_other"); err == nil {
		t.Fatal("a 403 revoke reported success")
	}
	if _, err := c.At(srv.URL).CreateToken(ctx, models.CreateAPITokenRequest{}); err != nil {
		t.Fatalf("At: %v", err)
	}
	if !strings.HasPrefix(TokenName("uc268"), "itest-uc268-") || len(TokenName("a-long-prefix-for-one-case")) > 64 {
		t.Fatal("token names must be unique-suffixed and within the 64-character limit")
	}
}

// A token minted on one node reaches a worker within one mirror sync; until
// then the worker answers 401 unknown_or_revoked or 503. AwaitAccepted must
// ride that out, and must not ride out a real refusal.
func TestAwaitAcceptedRidesOutPropagationOnly(t *testing.T) {
	shortPropagationPoll(t)
	var calls atomic.Int32
	answers := []func(w http.ResponseWriter){
		func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized","reason":"unknown_or_revoked"}`))
		},
		func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"identity data is stale"}`))
		},
		func(w http.ResponseWriter) {
			_ = json.NewEncoder(w).Encode(models.WhoAmI{Role: "runner", Team: TeamPayments, Principal: models.WhoAmIPrincipal{Kind: "token", ID: "tok_1"}})
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(calls.Add(1)) - 1
		answers[min(n, len(answers)-1)](w)
	}))
	t.Cleanup(srv.Close)
	who, err := AwaitAccepted(context.Background(), NewAPIClient(srv.URL, "avm_x"), 5*time.Second)
	if err != nil || who.Role != "runner" || who.Principal.ID != "tok_1" {
		t.Fatalf("AwaitAccepted = %+v, %v", who, err)
	}

	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","reason":"expired"}`))
	}))
	t.Cleanup(refuse.Close)
	start := time.Now()
	if _, err := AwaitAccepted(context.Background(), NewAPIClient(refuse.URL, "avm_x"), 5*time.Second); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired token must fail at once with its reason: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("AwaitAccepted waited out a refusal that will never change")
	}

	stuck := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(stuck.Close)
	if _, err := AwaitAccepted(context.Background(), NewAPIClient(stuck.URL, "avm_x"), 50*time.Millisecond); err == nil || !strings.Contains(err.Error(), "still not accepted") {
		t.Fatalf("a credential never accepted must time out with the last answer: %v", err)
	}
}

// TestTokenMirrorNodes: a fresh token is awaited on every node that reads
// tokens from the mirror (workers and ingress, whatever the case of the
// role), never on Raft members, and on none when there are no targets.
func TestTokenMirrorNodes(t *testing.T) {
	targets := &IntegrationTargets{Nodes: []IntegrationNode{
		{Name: "server-1", Role: "server", Seed: true},
		{Name: "server-2", Role: "server"},
		{Name: "ingress-1", Role: "ingress"},
		{Name: "worker-w", Role: "worker"},
		{Name: "worker-x", Role: " Worker "},
		{Name: "node3", Role: "mixed"},
		{Name: "solo", Role: ""},
	}}
	var got []string
	for _, n := range TokenMirrorNodes(targets) {
		got = append(got, n.Name)
	}
	if want := []string{"ingress-1", "worker-w", "worker-x"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("TokenMirrorNodes = %v, want %v", got, want)
	}
	if TokenMirrorNodes(nil) != nil {
		t.Fatal("no targets must mean no nodes to wait on")
	}
}

func TestAwaitRefusedMeasuresTheRevoke(t *testing.T) {
	shortPropagationPoll(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			_ = json.NewEncoder(w).Encode(models.WhoAmI{Role: "runner"})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","reason":"unknown_or_revoked"}`))
	}))
	t.Cleanup(srv.Close)
	took, resp, err := AwaitRefused(context.Background(), NewAPIClient(srv.URL, "avm_x"), 5*time.Second)
	if err != nil || resp.Status != http.StatusUnauthorized || resp.Err().Reason != "unknown_or_revoked" || took <= 0 {
		t.Fatalf("AwaitRefused = %v %v %v", took, resp, err)
	}

	never := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(models.WhoAmI{Role: "runner"})
	}))
	t.Cleanup(never.Close)
	if _, _, err := AwaitRefused(context.Background(), NewAPIClient(never.URL, "avm_x"), 30*time.Millisecond); err == nil {
		t.Fatal("a credential that stays accepted reported refused")
	}
}

func TestAPIResponseHelpers(t *testing.T) {
	r := &APIResponse{Status: 403, Body: []byte(`{"error":"forbidden: needs sandbox.exec","required_permission":"sandbox.exec","role":"viewer"}`)}
	if e := r.Err(); e.RequiredPermission != "sandbox.exec" || e.Role != "viewer" {
		t.Fatalf("Err = %+v", e)
	}
	if e := (&APIResponse{Status: 502, Body: []byte("bad gateway\n")}).Err(); e.Error != "bad gateway" {
		t.Fatalf("a non-JSON body must surface as text: %+v", e)
	}
	var v map[string]any
	if err := (&APIResponse{Status: 200, Body: []byte("not json")}).JSON(&v); err == nil {
		t.Fatal("decoded garbage")
	}
	if s := (*APIResponse)(nil).String(); s != "<no response>" {
		t.Fatalf("nil String = %q", s)
	}
}

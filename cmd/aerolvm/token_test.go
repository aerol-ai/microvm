package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeTokenAPI is /v1/tokens in miniature: names unique per team (409),
// revoke 204 every time, and the operator token only.
type fakeTokenAPI struct {
	mu       sync.Mutex
	tokens   map[string]models.APIToken
	revoked  []string
	lastBody models.CreateAPITokenRequest
	status   int // forced status for every call, when set
}

func newFakeTokenAPI(t *testing.T) (*fakeTokenAPI, *httptest.Server) {
	f := &fakeTokenAPI{tokens: map[string]models.APIToken{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeTokenAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer test-token" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}
	if f.status != 0 {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(`{"error":"the token store did not confirm the write"}`))
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/tokens":
		var req models.CreateAPITokenRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.lastBody = req
		for _, tok := range f.tokens {
			if tok.Name == req.Name && tok.Team == req.Team {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"token name already used in this team"}`))
				return
			}
		}
		tok, _ := identitywire.NewAPIToken(nil)
		rec := models.APIToken{ID: tok.ID, Name: req.Name, Role: req.Role, Team: req.Team, CreatedBy: "operator",
			CreatedAt: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)}
		f.tokens[tok.ID] = rec
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(models.CreatedAPIToken{APIToken: rec, Token: tok.Plaintext()})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/tokens":
		out := models.APITokenList{Tokens: []models.APIToken{}}
		for _, tok := range f.tokens {
			out.Tokens = append(out.Tokens, tok)
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/tokens/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/tokens/")
		delete(f.tokens, id)
		f.revoked = append(f.revoked, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func newTokenHarness(t *testing.T) (*harness, *fakeTokenAPI) {
	h := newHarness(t)
	f, srv := newFakeTokenAPI(t)
	h.env = map[string]string{"SB_API_URL": srv.URL, "SB_PAT_TOKEN": "test-token"}
	return h, f
}

// TestTokenCreateListRevoke: create prints the token once on stdout and a
// note on stderr, a repeat create is a 409 (exit 1), list shows a table or
// JSON, and revoke takes an id or a pasted token and succeeds twice.
func TestTokenCreateListRevoke(t *testing.T) {
	h, f := newTokenHarness(t)
	if code := h.run("token", "create", "--name", "ci-deploy", "--role", "runner", "--team", "payments", "--expires-in", "90d"); code != exitOK {
		t.Fatalf("create = %d: %s", code, h.stderr.String())
	}
	plain := strings.TrimSpace(h.stdout.String())
	tok, err := identitywire.ParseAPIToken(plain)
	if err != nil {
		t.Fatalf("stdout is the token alone: %q (%v)", plain, err)
	}
	if !strings.Contains(h.stderr.String(), "only time the token is shown") || !strings.Contains(h.stderr.String(), "role runner on team payments") {
		t.Fatalf("create note: %s", h.stderr.String())
	}
	if f.lastBody != (models.CreateAPITokenRequest{Name: "ci-deploy", Role: "runner", Team: "payments", ExpiresIn: "90d"}) {
		t.Fatalf("request body = %+v", f.lastBody)
	}
	if code := h.run("token", "create", "--name", "ci-deploy", "--role", "runner", "--team", "payments", "--expires-in", "90d", "--json"); code != exitError {
		t.Fatalf("a repeat create = %d, want exit 1", code)
	}
	if e := h.errorEnvelope(); e.HTTPStatus != http.StatusConflict || e.Code != "conflict" {
		t.Fatalf("409 envelope = %+v", e)
	}
	if code := h.run("token", "create", "--name", "prom", "--role", "viewer", "--team", "*", "--expires-in", "30d", "--json"); code != exitOK {
		t.Fatalf("create --json = %d", code)
	}
	var created models.CreatedAPIToken
	h.jsonOut(&created)
	if created.Team != "*" || !strings.HasPrefix(created.Token, "avm_") {
		t.Fatalf("created = %+v", created)
	}
	if h.stderr.String() != "" {
		t.Fatalf("--json keeps stderr quiet on success: %q", h.stderr.String())
	}

	if code := h.run("token", "list"); code != exitOK || !strings.Contains(h.stdout.String(), "ID") || !strings.Contains(h.stdout.String(), tok.ID) {
		t.Fatalf("list = %d %s", code, h.stdout.String())
	}
	if code := h.run("token", "ls", "--json"); code != exitOK {
		t.Fatalf("list --json = %d", code)
	}
	var list models.APITokenList
	h.jsonOut(&list)
	if len(list.Tokens) != 2 {
		t.Fatalf("list --json = %+v", list)
	}

	// Revoke by pasted token: the id is what goes on the wire, twice.
	for i := 0; i < 2; i++ {
		if code := h.run("token", "revoke", plain); code != exitOK || !strings.Contains(h.stderr.String(), "revoked "+tok.ID) {
			t.Fatalf("revoke %d = %d %s", i, code, h.stderr.String())
		}
	}
	if len(f.revoked) != 2 || f.revoked[0] != tok.ID {
		t.Fatalf("revoked ids on the wire = %v", f.revoked)
	}
	if code := h.run("token", "rm", created.ID, "--json"); code != exitOK || !strings.Contains(h.stdout.String(), `"revoked": "`+created.ID+`"`) {
		t.Fatalf("revoke --json = %d %s", code, h.stdout.String())
	}
	if code := h.run("token", "list"); code != exitOK || !strings.Contains(h.stderr.String(), "no API tokens") {
		t.Fatalf("empty list = %d %q", code, h.stderr.String())
	}
}

func TestTokenUsageErrors(t *testing.T) {
	h, f := newTokenHarness(t)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"token"}, "expected a subcommand"},
		{[]string{"token", "mint"}, `unknown subcommand "mint"`},
		{[]string{"token", "create", "--role", "runner", "--team", "x", "--expires-in", "1d"}, "--name is required"},
		{[]string{"token", "create", "--name", "a b", "--role", "runner", "--team", "x", "--expires-in", "1d"}, "--name is required"},
		{[]string{"token", "create", "--name", "a", "--role", "owner", "--team", "x", "--expires-in", "1d"}, "--role"},
		{[]string{"token", "create", "--name", "a", "--role", "runner", "--expires-in", "1d"}, "--team is required"},
		{[]string{"token", "create", "--name", "a", "--role", "runner", "--team", "x"}, "--expires-in is required"},
		{[]string{"token", "create", "--name", "a", "--role", "runner", "--team", "x", "--expires-in", "soon"}, "positive lifetime"},
		{[]string{"token", "create", "--name", "a", "--role", "runner", "--team", "x", "--expires-in", "1d", "extra"}, "unexpected argument"},
		{[]string{"token", "create", "--bogus"}, "bogus"},
		{[]string{"token", "list", "extra"}, "unexpected argument"},
		{[]string{"token", "list", "--bogus"}, "bogus"},
		{[]string{"token", "revoke"}, "expected one token id"},
		{[]string{"token", "revoke", "tok_short"}, "is not a token id"},
		{[]string{"token", "revoke", "--bogus"}, "bogus"},
	}
	for _, tc := range cases {
		if code := h.run(tc.args...); code != exitUsage || !strings.Contains(h.stderr.String(), tc.want) {
			t.Errorf("%v = %d, stderr %q; want usage naming %q", tc.args, code, h.stderr.String(), tc.want)
		}
	}
	if f.lastBody.Name != "" || len(f.revoked) != 0 {
		t.Fatal("a usage error never reaches sandboxd")
	}
}

// Refusals word themselves like every other verb's: a 401 names the token
// that was refused, a 503 is retryable, and an unreachable server is an
// error.
func TestTokenServerRefusals(t *testing.T) {
	h, f := newTokenHarness(t)
	h.env["SB_PAT_TOKEN"] = "wrong"
	if code := h.run("token", "list"); code != exitError || !strings.Contains(h.stderr.String(), "refused the token in SB_PAT_TOKEN") {
		t.Fatalf("401 = %d %s", code, h.stderr.String())
	}
	h.env["SB_PAT_TOKEN"] = "test-token"
	f.status = http.StatusServiceUnavailable
	if code := h.run("token", "revoke", "tok_aaaaaaaaaaaa", "--json"); code != exitError {
		t.Fatalf("503 = %d", code)
	}
	if e := h.errorEnvelope(); !e.Retryable || e.HTTPStatus != http.StatusServiceUnavailable || !strings.Contains(e.Message, "did not confirm") {
		t.Fatalf("503 envelope = %+v", e)
	}
	f.status = 0
	h.env["SB_API_URL"] = "http://127.0.0.1:1"
	if code := h.run("token", "list", "--debug"); code != exitError {
		t.Fatalf("unreachable = %d", code)
	}
	h.env = map[string]string{"HOME": t.TempDir()}
	if code := h.run("token", "list"); code != exitError || !strings.Contains(h.stderr.String(), "not logged in") {
		t.Fatalf("no connection = %d %s", code, h.stderr.String())
	}
}

func TestTokenAPIBodies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/tokens/bad" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv.Close()
	h := newHarness(t)
	h.env = map[string]string{"SB_API_URL": srv.URL, "SB_PAT_TOKEN": "x"}
	if code := h.run("token", "list"); code != exitError || !strings.Contains(h.stderr.String(), "unreadable response") {
		t.Fatalf("garbled body = %d %s", code, h.stderr.String())
	}
	var out any
	if err := h.app.tokenAPI(t.Context(), nil, http.MethodGet, "/v1/tokens/bad", nil, &out); err == nil || !strings.Contains(err.Error(), "I'm a teapot") {
		t.Fatalf("a bodiless error falls back to the status text: %v", err)
	}
	if teamWords("*") != "every team" || teamWords("x") != "team x" {
		t.Fatal("teamWords")
	}
}

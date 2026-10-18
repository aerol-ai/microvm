package v1

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func newTokensV1Mux(t *testing.T) (*http.ServeMux, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{IdentityEnabled: true}, logger, st, &noopRuntime{}, nil, nil, nil, nil, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth: func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.OperatorAccess())))
			})
		},
	})
	return mux, st
}

// TestV1Tokens: create is 201 with the token once (never cached), a
// duplicate name is 409, list never carries a hash, and revoke is 204 every
// time; a malformed id is a 400, never a silent 204.
func TestV1Tokens(t *testing.T) {
	mux, st := newTokensV1Mux(t)
	req := models.CreateAPITokenRequest{Name: "ci-deploy", Role: "runner", Team: "payments", ExpiresIn: "90d"}
	rr := do(t, mux, http.MethodPost, "/v1/tokens", req)
	if rr.Code != http.StatusCreated || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %q %s", rr.Code, rr.Header().Get("Cache-Control"), rr.Body.String())
	}
	var created models.CreatedAPIToken
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	if !strings.HasPrefix(created.Token, "avm_") || !strings.HasPrefix(created.ID, "tok_") || created.Role != "runner" || created.Team != "payments" || created.CreatedBy != "operator" {
		t.Fatalf("created = %+v", created)
	}
	if rr := do(t, mux, http.MethodPost, "/v1/tokens", req); rr.Code != http.StatusConflict || strings.Contains(rr.Body.String(), "avm_") {
		t.Fatalf("duplicate name: %d %s", rr.Code, rr.Body.String())
	}
	bad := req
	bad.Role = "admin"
	if rr := do(t, mux, http.MethodPost, "/v1/tokens", bad); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "every team") {
		t.Fatalf("admin on one team: %d %s", rr.Code, rr.Body.String())
	}
	raw := httptest.NewRequest(http.MethodPost, "/v1/tokens", strings.NewReader("{not json"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, raw)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON: %d", rec.Code)
	}
	rr = do(t, mux, http.MethodGet, "/v1/tokens", nil)
	var list models.APITokenList
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if rr.Code != http.StatusOK || len(list.Tokens) != 1 || list.Tokens[0].ID != created.ID ||
		strings.Contains(rr.Body.String(), "secret") || strings.Contains(rr.Body.String(), created.Token) {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	for i := 0; i < 2; i++ {
		if rr := do(t, mux, http.MethodDelete, "/v1/tokens/"+created.ID, nil); rr.Code != http.StatusNoContent {
			t.Fatalf("revoke %d: %d %s", i, rr.Code, rr.Body.String())
		}
	}
	if rr := do(t, mux, http.MethodDelete, "/v1/tokens/not-a-token-id", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed id: %d", rr.Code)
	}
	rr = do(t, mux, http.MethodGet, "/v1/tokens", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list.Tokens) != 0 {
		t.Fatalf("after revoke: %+v", list.Tokens)
	}
	_ = st.Close()
	if rr := do(t, mux, http.MethodGet, "/v1/tokens", nil); rr.Code < 400 {
		t.Fatalf("a broken store fails the list: %d", rr.Code)
	}
}

// tokenFeedCluster is a Raft server's token surface for the internal
// handlers.
type tokenFeedCluster struct {
	*cluster.Noop
	writeErr error
	changed  bool
}

func (c *tokenFeedCluster) WriteAPIToken(_ context.Context, req cluster.APITokenWriteRequest) (cluster.APITokenWriteResponse, error) {
	if c.writeErr != nil {
		return cluster.APITokenWriteResponse{}, c.writeErr
	}
	return cluster.APITokenWriteResponse{Token: req.Token}, nil
}

func (c *tokenFeedCluster) APITokenChanges(since uint64) (identity.TokenChanges, bool) {
	return identity.TokenChanges{Changes: []identity.TokenChange{{Index: since + 1, ID: "tok_aaaaaaaaaaaa", Deleted: true}}, Next: since + 1}, c.changed
}

func (c *tokenFeedCluster) APITokenPage(after string, limit int) identity.TokenPage {
	return identity.TokenPage{Tokens: []identity.TokenRecord{{ID: "tok_bbbbbbbbbbbb", Name: after}}, Version: uint64(limit)}
}

func TestV1TokensClusterInternal(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &tokenFeedCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	serve := func(fn http.HandlerFunc, method, target, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		fn(rec, httptest.NewRequest(method, target, rdr))
		return rec
	}

	write := func(body string) *httptest.ResponseRecorder {
		return serve(h.clusterInternalAPITokenWrite, http.MethodPost, cluster.PublicInternalAPITokenWritePath, body)
	}
	if rr := write(`{"token":{"id":"tok_aaaaaaaaaaaa"}}`); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "tok_aaaaaaaaaaaa") {
		t.Fatalf("write: %d %s", rr.Code, rr.Body.String())
	}
	stub.writeErr = cluster.ErrAPITokenNameTaken
	if rr := write(`{}`); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"code":"name_taken"`) {
		t.Fatalf("an FSM verdict rides a 200: %d %s", rr.Code, rr.Body.String())
	}
	stub.writeErr = errors.New("raft: timeout")
	if rr := write(`{}`); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("an apply failure is a 503: %d", rr.Code)
	}
	if rr := write(`{nope`); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON: %d", rr.Code)
	}

	changes := func(q string) *httptest.ResponseRecorder {
		return serve(h.clusterInternalAPITokenChanges, http.MethodGet, cluster.PublicInternalAPITokenChangesPath+q, "")
	}
	if rr := changes("?since=7"); rr.Code != http.StatusNotModified || rr.Body.Len() != 0 {
		t.Fatalf("a current cursor is a bodiless 304: %d %q", rr.Code, rr.Body.String())
	}
	stub.changed = true
	rr := changes("?since=7")
	var resp identity.TokenChanges
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if rr.Code != http.StatusOK || resp.Next != 8 || len(resp.Changes) != 1 {
		t.Fatalf("delta: %d %s", rr.Code, rr.Body.String())
	}
	if rr := changes(""); rr.Code != http.StatusOK {
		t.Fatalf("no since means 0: %d", rr.Code)
	}
	if rr := changes("?since=-1"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad since: %d", rr.Code)
	}

	page := func(q string) *httptest.ResponseRecorder {
		return serve(h.clusterInternalAPITokenPage, http.MethodGet, cluster.PublicInternalAPITokenPagePath+q, "")
	}
	rr = page("?after=tok_a&limit=50")
	var p identity.TokenPage
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	if rr.Code != http.StatusOK || p.Version != 50 || p.Tokens[0].Name != "tok_a" {
		t.Fatalf("page: %d %s", rr.Code, rr.Body.String())
	}
	if rr := page("?limit=x"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad limit: %d", rr.Code)
	}

	// A node without the token FSM (a worker, or single node) serves none.
	plain := newClusterInternalHandler(t)
	for _, fn := range []http.HandlerFunc{plain.clusterInternalAPITokenWrite, plain.clusterInternalAPITokenChanges, plain.clusterInternalAPITokenPage} {
		if rr := serve(fn, http.MethodGet, "/", "{}"); rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("not served here: %d", rr.Code)
		}
	}
}

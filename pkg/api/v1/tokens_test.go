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
	writes   int
}

// AuditCallerWritesAllowed: every server runs a build that records callers.
func (c *tokenFeedCluster) AuditCallerWritesAllowed() bool { return true }

// tokenAuditSink keeps the records the handler had the service write.
type tokenAuditSink struct{ events []service.SecretAuditEvent }

func (k *tokenAuditSink) Emit(ev service.SecretAuditEvent) { k.events = append(k.events, ev) }

// IsTokenWritePeer plays the admitted roles: wkr-1 is a worker.
func (c *tokenFeedCluster) IsTokenWritePeer(peerID string) bool {
	return peerID != "" && peerID != "wkr-1"
}

func (c *tokenFeedCluster) WriteAPIToken(_ context.Context, req cluster.APITokenWriteRequest) (cluster.APITokenWriteResponse, error) {
	c.writes++
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
	sink := &tokenAuditSink{}
	svc.UseAuditSinkForTest(sink)
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

	writeFrom := func(peer, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, cluster.PublicInternalAPITokenWritePath, strings.NewReader(body))
		h.clusterInternalAPITokenWrite(rec, req.WithContext(context.WithValue(req.Context(), clusterPeerNodeIDContextKey{}, peer)))
		return rec
	}
	write := func(body string) *httptest.ResponseRecorder { return writeFrom("gw-1", body) }

	// Token writes come only from servers and gateways: a worker's, or one
	// with no peer at all, is refused before it reaches the cluster.
	forged := `{"token":{"id":"tok_aaaaaaaaaaaa","name":"prometheus-2","role":"admin","created_by":"operator","expires_at":"2200-01-01T00:00:00Z"}}`
	for _, peer := range []string{"wkr-1", ""} {
		if rr := writeFrom(peer, forged); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"code":"writer_refused"`) || stub.writes != 0 {
			t.Fatalf("a token write from %q: %d %s, %d writes reached the cluster", peer, rr.Code, rr.Body.String(), stub.writes)
		}
	}
	// Each refusal is on the record, naming the node and the created_by
	// the forged record claims.
	if len(sink.events) != 2 || sink.events[0].Caller == nil || sink.events[0].Caller.ID != "node:wkr-1" ||
		sink.events[0].Kind != service.KindAPITokenPeerWrite || sink.events[0].Result != "denied" ||
		sink.events[0].Reason != "created_by=operator" {
		t.Fatalf("refused writes recorded: %+v", sink.events)
	}
	if rr := write(`{"token":{"id":"tok_aaaaaaaaaaaa"}}`); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "tok_aaaaaaaaaaaa") {
		t.Fatalf("write: %d %s", rr.Code, rr.Body.String())
	}
	if last := sink.events[len(sink.events)-1]; last.Caller.ID != "node:gw-1" || last.Result != "ok" || last.Request.Target != "tok_aaaaaaaaaaaa" {
		t.Fatalf("a gateway's write recorded: %+v %+v", last, last.Request)
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

// forwardingCluster is a worker's cluster: ForwardToServer plays the
// server's answer.
type forwardingCluster struct {
	*cluster.Noop
	forwarded []string
}

func (c *forwardingCluster) ForwardToServer(w http.ResponseWriter, r *http.Request) {
	c.forwarded = append(c.forwarded, r.Method+" "+r.Header.Get("Authorization"))
	w.WriteHeader(http.StatusCreated)
}

// A worker sends a caller's token create or revoke on to a server with the
// caller's own credential (PR 2 review: a cluster whose API address
// reaches only worker,ingress nodes must still create and revoke tokens).
// A call with no credential of its own is refused, never sent as the node.
// A gateway and a server write tokens themselves.
func TestV1TokenWritesForwardFromAWorker(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		role     string
		forwards bool
	}{{"worker", true}, {"worker,ingress", true}, {"ingress", false}, {"server", false}} {
		svc := service.New(config.Config{EnableCluster: true, NodeRole: tc.role}, logger, nil, nil, nil, nil, nil, nil, nil)
		stub := &forwardingCluster{Noop: cluster.NewNoop("n-1", "http://n-1", "")}
		svc.AttachCluster(stub)
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		send := func(fn http.HandlerFunc, method, path, bearer string) *httptest.ResponseRecorder {
			req := httptest.NewRequest(method, path, strings.NewReader(`{"name":"ci","role":"runner","team":"payments","expires_in":"30d"}`))
			if bearer != "" {
				req.Header.Set("Authorization", "Bearer "+bearer)
			}
			rr := httptest.NewRecorder()
			fn(rr, req)
			return rr
		}
		create := send(h.createToken, http.MethodPost, "/v1/tokens", "avm_caller")
		send(h.revokeToken, http.MethodDelete, "/v1/tokens/tok_aaaaaaaaaaaa", "avm_caller")
		if !tc.forwards {
			if len(stub.forwarded) != 0 {
				t.Errorf("%s: forwarded %v; it writes tokens itself", tc.role, stub.forwarded)
			}
			continue
		}
		if create.Code != http.StatusCreated || len(stub.forwarded) != 2 ||
			stub.forwarded[0] != "POST Bearer avm_caller" || stub.forwarded[1] != "DELETE Bearer avm_caller" {
			t.Fatalf("%s: %d, forwarded %v", tc.role, create.Code, stub.forwarded)
		}
		if rr := send(h.createToken, http.MethodPost, "/v1/tokens", ""); rr.Code != http.StatusBadRequest || len(stub.forwarded) != 2 {
			t.Fatalf("%s: a call with no credential of its own: %d, forwarded %v", tc.role, rr.Code, stub.forwarded)
		}
	}
}

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// listGateServer is a cluster-mode API server whose list gate has one slot
// and no queue wait, so a test can fill it by hand.
func listGateServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := config.Config{EnableCluster: true, APIListMaxInflight: 1}
	svc := service.New(cfg, discardLogger(), st, nil, nil, caddy.New(config.Config{HTTPClientTimeout: time.Second}), nil, nil, nil)
	// Not the *cluster.Noop type itself, so every list fans out (ListMode).
	svc.AttachCluster(&apiLivePeerCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
	return NewServer(discardLogger(), svc, nil, nil, cfg, "pat-token", nil)
}

func serveList(t *testing.T, s *Server, path string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer pat-token")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// Every cluster-wide list — v1 and the three facades — sheds with a fast 503
// + Retry-After when this node's list slots are taken, each in its own error
// envelope; nothing else on the node is gated.
func TestListGateShedsEveryClusterListAndNothingElse(t *testing.T) {
	s := listGateServer(t)
	if s.listGate.Limit() != 1 {
		t.Fatalf("list gate limit = %d, want SB_API_LIST_MAX_INFLIGHT=1", s.listGate.Limit())
	}
	lists := []struct {
		path   string
		header map[string]string
	}{
		{path: "/v1/sandboxes"},
		{path: "/daytona/sandbox"},
		{path: "/daytona/sandbox/paginated"},
		{path: "/e2b/sandboxes", header: map[string]string{"X-API-KEY": "pat-token"}},
		{path: "/e2b/v2/sandboxes", header: map[string]string{"X-API-KEY": "pat-token"}},
		{path: "/runloop/v1/devboxes"},
	}
	// Free slot: every list answers.
	for _, l := range lists {
		if rec := serveList(t, s, l.path, l.header); rec.Code != http.StatusOK {
			t.Fatalf("GET %s with a free slot = %d: %s", l.path, rec.Code, rec.Body.String())
		}
	}

	release, err := s.listGate.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	shedBefore := listGateMetrics.Shed.Value()
	for _, l := range lists {
		start := time.Now()
		rec := serveList(t, s, l.path, l.header)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("GET %s with every slot taken = %d, want 503: %s", l.path, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Retry-After"); got != strconv.Itoa(apihttp.OverloadedRetryAfterSeconds) {
			t.Fatalf("GET %s: Retry-After = %q", l.path, got)
		}
		if took := time.Since(start); took > time.Second {
			t.Fatalf("GET %s took %v to shed; a shed must be fast", l.path, took)
		}
		if strings.HasPrefix(l.path, "/v1/") && !strings.Contains(rec.Body.String(), models.ErrorCodeOverloaded) {
			t.Fatalf("GET %s: body %s lacks code %q", l.path, rec.Body.String(), models.ErrorCodeOverloaded)
		}
	}
	if got := listGateMetrics.Shed.Value() - shedBefore; got != int64(len(lists)) {
		t.Fatalf("aerolvm_api_list_shed_total rose by %d, want %d", got, len(lists))
	}

	// Cheap routes never wait on the list gate.
	if rec := serveList(t, s, "/v1/whoami", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/whoami with the list gate full = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := serveList(t, s, "/v1/sandboxes/sb-missing", nil); rec.Code == http.StatusServiceUnavailable {
		t.Fatalf("GET /v1/sandboxes/{id} was shed: %s", rec.Body.String())
	}

	release()
	if rec := serveList(t, s, "/v1/sandboxes", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/sandboxes after the slot freed = %d", rec.Code)
	}
}

// /health never waits on the list gate. (Its store is closed so the handler
// answers 500 without an engine to ping: reaching it is what is checked.)
func TestListGateLeavesHealthAlone(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "health.db"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{EnableCluster: true, APIListMaxInflight: 1}
	svc := service.New(cfg, discardLogger(), st, nil, nil, nil, nil, nil, nil)
	_ = st.Close()
	s := NewServer(discardLogger(), svc, nil, nil, cfg, "pat-token", nil)
	release, err := s.listGate.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GET /health with the list gate full = %d, want the health handler's own answer (500 here): %s", rec.Code, rec.Body.String())
	}
}

// SB_API_LIST_MAX_INFLIGHT=0 means no gate at all.
func TestListGateOffWithNoLimit(t *testing.T) {
	s := NewServer(discardLogger(), nil, nil, nil, config.Config{APIListMaxInflight: 0}, "pat-token", nil)
	if s.listGate != nil {
		t.Fatal("a zero limit built a gate")
	}
}

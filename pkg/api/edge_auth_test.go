package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// The fleet's metrics are the operator's: a tenant's user token
// authenticates but is refused, and no token is refused before that.
func TestMetricsAreOperatorOnly(t *testing.T) {
	server := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, config.Config{}, "pat-token",
		stubValidator{accept: "user-token", identity: controlplane.Identity{OwnerRef: "acme"}})
	for _, path := range []string{"/debug/vars", "/v1/metrics"} {
		for token, want := range map[string]int{"pat-token": http.StatusOK, "user-token": http.StatusForbidden, "": http.StatusUnauthorized} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != want {
				t.Errorf("GET %s with %q = %d, want %d", path, token, rec.Code, want)
			}
		}
	}
}

// A validated user token must name an account: an empty owner would be
// scoped to "", which is everything the operator created.
func TestUserTokenWithoutAnAccountIsRefused(t *testing.T) {
	srv := &Server{patToken: "pat", validator: stubValidator{accept: "user-token", identity: controlplane.Identity{OwnerRef: "  ", ExternalID: "ext"}}}
	called := false
	handler := srv.requireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("user token with no account = %d (handler called %v); want 401", rec.Code, called)
	}
}

// A single node has no peers, so cluster control headers can only come from
// a caller; they are dropped, and the request goes on without them. In a
// cluster they still need an authenticated peer.
func TestSingleNodeDropsClusterControlHeaders(t *testing.T) {
	var seen http.Header
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		r.Header.Set("X-Cluster-Create-Target", "node-1")
		r.Header.Set("x-cluster-create-id", "chosen-id")
		r.Header.Set("X-Request-Id", "kept")
		return r
	}
	single := &Server{}
	rec := httptest.NewRecorder()
	single.clusterControlHeaderGuard(next).ServeHTTP(rec, req())
	if rec.Code != http.StatusOK || seen.Get("X-Cluster-Create-Target") != "" || seen.Get("X-Cluster-Create-Id") != "" || seen.Get("X-Request-Id") != "kept" {
		t.Fatalf("single node passed %d with headers %v", rec.Code, seen)
	}
	seen = nil
	clustered := &Server{clusterEnabled: true}
	rec = httptest.NewRecorder()
	clustered.clusterControlHeaderGuard(next).ServeHTTP(rec, req())
	if rec.Code != http.StatusForbidden || seen != nil {
		t.Fatalf("cluster without a peer certificate = %d (handler reached %v); want 403", rec.Code, seen != nil)
	}
}

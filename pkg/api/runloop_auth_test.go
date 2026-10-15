package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func TestRequireRunloopAuth(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	validator := stubValidator{accept: "user-token", identity: controlplane.Identity{OwnerRef: "tenant-1"}}
	server := NewServer(logger, nil, nil, nil, config.Config{}, "pat-token", validator)

	var gotAccess controlplane.Access
	handler := server.requireRunloopAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccess, _ = controlplane.AccessFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	serve := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/runloop/v1/devboxes", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := serve("pat-token"); rec.Code != http.StatusNoContent || !gotAccess.Operator {
		t.Fatalf("PAT: status %d access %+v", rec.Code, gotAccess)
	}
	if rec := serve("user-token"); rec.Code != http.StatusNoContent || gotAccess.Operator || gotAccess.Identity.OwnerRef != "tenant-1" {
		t.Fatalf("user token: status %d access %+v", rec.Code, gotAccess)
	}
	for _, token := range []string{"", "wrong"} {
		rec := serve(token)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: status = %d", token, rec.Code)
		}
		// The Runloop SDKs read `message` from the error body.
		var body struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Message == "" {
			t.Fatalf("token %q: body %q", token, rec.Body.String())
		}
	}
}

// TestRunloopRoutesMounted checks the facade is reachable through the
// server's mux behind its auth.
func TestRunloopRoutesMounted(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewServer(logger, nil, nil, nil, config.Config{}, "pat-token", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/runloop/v1/devboxes", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list: status = %d, want 401", rec.Code)
	}
}

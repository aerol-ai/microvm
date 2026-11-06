package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// TestPprofIsOffByDefaultAndAdminOnly is plan O2: with SB_ENABLE_PPROF off
// (the default) /debug/pprof/ is not served at all, even to the operator;
// on, only fleet.admin reads it: no token is a 401 and a tenant's token a
// 403.
func TestPprofIsOffByDefaultAndAdminOnly(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	validator := stubValidator{accept: "user-token", identity: controlplane.Identity{OwnerRef: "acme"}}
	paths := []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/symbol", "/debug/pprof/heap", "/debug/pprof/goroutine?debug=1"}
	get := func(h http.Handler, method, path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	off := NewServer(logger, nil, nil, nil, config.Config{}, "pat-token", validator).Handler()
	for _, path := range paths {
		if rec := get(off, http.MethodGet, path, "pat-token"); rec.Code != http.StatusNotFound {
			t.Fatalf("pprof off by default, but GET %s as the operator = %d, want 404", path, rec.Code)
		}
	}

	on := NewServer(logger, nil, nil, nil, config.Config{EnablePprof: true}, "pat-token", validator).Handler()
	for _, path := range paths {
		for token, want := range map[string]int{"pat-token": http.StatusOK, "user-token": http.StatusForbidden, "": http.StatusUnauthorized} {
			if rec := get(on, http.MethodGet, path, token); rec.Code != want {
				t.Fatalf("GET %s with %q = %d, want %d", path, token, rec.Code, want)
			}
		}
	}
	if rec := get(on, http.MethodGet, "/debug/pprof/", "pat-token"); !strings.Contains(rec.Body.String(), "goroutine") {
		t.Fatalf("pprof index = %q", rec.Body.String())
	}
	if rec := get(on, http.MethodPost, "/debug/pprof/symbol", "user-token"); rec.Code != http.StatusForbidden {
		t.Fatalf("POST symbol as a tenant = %d, want 403", rec.Code)
	}
	if rec := get(on, http.MethodGet, "/debug/pprof/profile?seconds=1", "pat-token"); rec.Code != http.StatusOK {
		t.Fatalf("CPU profile = %d", rec.Code)
	}
	if rec := get(on, http.MethodGet, "/debug/pprof/trace?seconds=1", "pat-token"); rec.Code != http.StatusOK {
		t.Fatalf("trace = %d", rec.Code)
	}
}

package toolhost

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHostRoutesAndAuth(t *testing.T) {
	h := New(Config{
		SandboxID: "sb-routes",
		AuthToken: "secret-token",
		WorkDir:   t.TempDir(),
	})
	handler := h.Handler()

	// 1. GET /
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / expected 200, got %d", rec.Code)
	}

	// 2. GET /version
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/version", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /version expected 200, got %d", rec.Code)
	}

	// 3. GET /process/interpreter/foo (auth required, first test auth fail)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/process/interpreter/foo", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
	}

	// GET /process/interpreter/foo (with correct auth, returns 501 Not Implemented)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/process/interpreter/foo", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 Not Implemented, got %d", rec.Code)
	}

	// 4. Default Not Found route
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/nonexistent-route-12345", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	// 5. Auth validation on all auth-protected routes
	authProtectedRoutes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/process/code-run"},
		{http.MethodPost, "/process/session"},
		{http.MethodPost, "/files/upload"},
		{http.MethodGet, "/files/download"},
		{http.MethodGet, "/files"},
		{http.MethodGet, "/state/kv/foo"},
		{http.MethodGet, "/process/exec/stream"},
		{http.MethodGet, "/sessions"},
	}

	for _, route := range authProtectedRoutes {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(route.method, route.path, nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for %s %s, got %d", route.method, route.path, rec.Code)
		}
	}

	// 6. Auth validation: bad token format (e.g. not Bearer prefix)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/execute", nil)
	req.Header.Set("Authorization", "Basic secret-token")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

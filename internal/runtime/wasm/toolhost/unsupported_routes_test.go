package toolhost

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The Daytona facade forwards these to every sandbox; a WASM sandbox has no
// filesystem or terminal for them, so it answers a clear 501 rather than the
// default 404 (plan B1). Auth still comes first.
func TestUnsupportedDaytonaRoutesAnswer501(t *testing.T) {
	handler := New(Config{SandboxID: "sb", AuthToken: "tok", WorkDir: t.TempDir()}).Handler()
	routes := [][2]string{
		{http.MethodDelete, "/files"},
		{http.MethodPost, "/files/folder"},
		{http.MethodPost, "/files/replace"},
		{http.MethodPost, "/files/permissions"},
		{http.MethodPost, "/lsp/start"},
		{http.MethodGet, "/lsp"},
		{http.MethodPost, "/process/pty"},
		{http.MethodGet, "/process/pty/s1/connect"},
	}
	for _, route := range routes {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(route[0], route[1], nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without a token = %d, want 401", route[0], route[1], rec.Code)
		}
		rec = httptest.NewRecorder()
		req := httptest.NewRequest(route[0], route[1], nil)
		req.Header.Set("Authorization", "Bearer tok")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s = %d, want 501", route[0], route[1], rec.Code)
		}
	}
	// GET /files is the WASM list and must not be swallowed by the 501s.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/files?path=/", nil)
	req.Header.Set("Authorization", "Bearer tok")
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotImplemented {
		t.Fatalf("GET /files answered 501")
	}
}

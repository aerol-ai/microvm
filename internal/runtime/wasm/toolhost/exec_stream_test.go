package toolhost

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Streaming exec must fail closed on the wasm toolhost: it runs in-process in
// sandboxd, so a host shell here would be a sandbox escape. The endpoint returns
// 501 and never upgrades the connection or spawns a process.
func TestHandleExecStreamDisabled(t *testing.T) {
	h := New(Config{SandboxID: "sb-test", WorkDir: t.TempDir()})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/exec/stream", nil)
	h.handleExecStream(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not supported") {
		t.Fatalf("body = %q, want a not-supported message", rec.Body.String())
	}
}

// The route is wired to the disabled handler (behind auth), so a request that
// reaches it gets 501, not a host process. This guards against the handler being
// re-pointed at a host-exec implementation.
func TestExecStreamRouteReturns501(t *testing.T) {
	h := New(Config{SandboxID: "sb-test", WorkDir: t.TempDir(), AuthToken: "tok"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/exec/stream", nil)
	req.Header.Set("Authorization", "Bearer tok")
	h.serveHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("route status = %d, want 501 (body %q)", rec.Code, rec.Body.String())
	}
}

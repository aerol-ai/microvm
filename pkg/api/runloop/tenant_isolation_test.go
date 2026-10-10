package runloop

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// asTenant serves one request as a user token scoped to owner, the way the
// auth middleware would attach it.
func (e *testEnv) asTenant(t *testing.T, owner, method, path, body string, out any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, devboxesPath+path, reader)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(controlplane.ContextWithAccess(req.Context(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: owner, ExternalID: owner},
	}))
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	if out != nil && rr.Code < 300 {
		if err := json.Unmarshal(rr.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %q: %v", rr.Body.String(), err)
		}
	}
	return rr
}

// TestTenantIsolation pins that the facade's in-memory state — captured
// execution results, shutdown tombstones — is as owner-scoped as the
// sandbox rows: another tenant reads 404, never the data.
func TestTenantIsolation(t *testing.T) {
	env := newTestEnv(t)
	var devbox devboxView
	expectStatus(t, env.asTenant(t, "acct-a", http.MethodPost, "/create_and_await_running", `{"name":"private"}`, &devbox), http.StatusOK)
	var exec executionView
	expectStatus(t, env.asTenant(t, "acct-a", http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo secret","command_id":"c"}`, &exec), http.StatusOK)
	waitFor(t, "result capture", func() bool { return env.toolbox.sessionCount() == 0 })

	execPath := "/" + devbox.ID + "/executions/" + exec.ExecutionID
	expectStatus(t, env.asTenant(t, "acct-a", http.MethodGet, execPath, "", nil), http.StatusOK)
	for _, path := range []string{"/" + devbox.ID, execPath, execPath + "/stream_stdout_updates"} {
		expectStatus(t, env.asTenant(t, "acct-b", http.MethodGet, path, "", nil), http.StatusNotFound)
	}
	expectStatus(t, env.asTenant(t, "acct-b", http.MethodPost, execPath+"/kill", "", nil), http.StatusNotFound)

	expectStatus(t, env.asTenant(t, "acct-a", http.MethodPost, "/"+devbox.ID+"/shutdown", "", nil), http.StatusOK)
	expectStatus(t, env.asTenant(t, "acct-b", http.MethodGet, "/"+devbox.ID, "", nil), http.StatusNotFound)
	expectStatus(t, env.asTenant(t, "acct-b", http.MethodPost, "/"+devbox.ID+"/shutdown", "", nil), http.StatusNotFound)
	var gone devboxView
	expectStatus(t, env.asTenant(t, "acct-a", http.MethodGet, "/"+devbox.ID, "", &gone), http.StatusOK)
	if gone.Status != statusShutdown {
		t.Fatalf("owner after shutdown = %q", gone.Status)
	}
	// Operator (no scoped Access) still sees it.
	expectStatus(t, env.do(t, http.MethodGet, "/"+devbox.ID, nil, nil), http.StatusOK)
}

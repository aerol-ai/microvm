package toolhost_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/statekv"
	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
)

// ─── State KV with rate-limited store ────────────────────────────────────────

func TestHostStateKVRateLimited(t *testing.T) {
	inner := newMemStateKV()
	rl := statekv.NewRateLimitedStore(inner, 1 /*per sec*/, 1 /*burst*/)

	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   rl,
	})
	handler := h.Handler()

	// First write should succeed
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/state/kv/mykey", bytes.NewReader([]byte("value")))
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("first put status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Second write (immediately) should be rate-limited → 429
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPut, "/state/kv/mykey", bytes.NewReader([]byte("value2")))
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited put status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVDeleteRateLimited(t *testing.T) {
	inner := newMemStateKV()
	// Pre-load a key so delete is meaningful
	_ = inner.Set(context.Background(), "sb", "delkey", []byte("v"))
	rl := statekv.NewRateLimitedStore(inner, 1 /*per sec*/, 1 /*burst*/)

	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   rl,
	})
	handler := h.Handler()

	// First delete should succeed
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/state/kv/delkey", nil)
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("first delete status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Second delete (immediately) should be rate-limited → 429
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodDelete, "/state/kv/delkey", nil)
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited delete status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVGetNotFound(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   newMemStateKV(),
	})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/state/kv/missing", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get not found status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVSetError(t *testing.T) {
	kv := &errStateKV{}
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   kv,
	})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/state/kv/key", bytes.NewReader([]byte("val")))
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("set error status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVDeleteError(t *testing.T) {
	kv := &errStateKV{}
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   kv,
	})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/state/kv/key", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete error status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVInvalidKeyGet(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   newMemStateKV(),
	})
	// A key longer than 512 bytes → 400
	oversizedKey := string(make([]byte, 513))
	for i := range []byte(oversizedKey) {
		oversizedKey = oversizedKey[:i] + "a" + oversizedKey[i+1:]
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/state/kv/"+oversizedKey, nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized key GET status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVInvalidKeyPut(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   newMemStateKV(),
	})
	// A key longer than 512 bytes → 400
	oversizedKey := string(make([]byte, 513))
	for i := 0; i < len(oversizedKey); i++ {
		oversizedKey = oversizedKey[:i] + "x" + oversizedKey[i+1:]
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/state/kv/"+oversizedKey, bytes.NewReader([]byte("val")))
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized key PUT status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVInvalidKeyDelete(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   newMemStateKV(),
	})
	// A key longer than 512 bytes → 400
	oversizedKey := string(make([]byte, 513))
	for i := 0; i < len(oversizedKey); i++ {
		oversizedKey = oversizedKey[:i] + "k" + oversizedKey[i+1:]
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/state/kv/"+oversizedKey, nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized key DELETE status = %d body=%s", rec.Code, rec.Body.String())
	}
}

// ─── Daytona process routes with real sessions manager ────────────────────────

func TestDaytonaSessionCreateAndExec(t *testing.T) {
	h, _ := newHostWithSessions(t)

	// Create a daytona session
	payload, _ := json.Marshal(map[string]string{"sessionId": "ds1"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("daytona create status = %d body=%s", rec.Code, rec.Body.String())
	}

	// List sessions
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/process/session", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("daytona list status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Get session
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/process/session/ds1", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("daytona get status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionGetNotFound(t *testing.T) {
	h, _ := newHostWithSessions(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/process/session/no-such-session", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("daytona get unknown status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionDeleteNotFound(t *testing.T) {
	h, _ := newHostWithSessions(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/process/session/no-such-session", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("daytona delete unknown status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionExecBadJSON(t *testing.T) {
	h, _ := newHostWithSessions(t)

	// Create session first
	payload, _ := json.Marshal(map[string]string{"sessionId": "ds-exec-bad"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	// Exec with bad JSON
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/process/session/ds-exec-bad/exec", bytes.NewReader([]byte("notjson")))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("daytona exec bad json status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionExecEmptyCommand(t *testing.T) {
	h, _ := newHostWithSessions(t)

	payload, _ := json.Marshal(map[string]string{"sessionId": "ds-empty-cmd"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	execPayload, _ := json.Marshal(map[string]string{"command": "   "})
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/process/session/ds-empty-cmd/exec", bytes.NewReader(execPayload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("daytona exec empty cmd status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionExecAsync(t *testing.T) {
	h, _ := newHostWithSessions(t)

	// Create session
	payload, _ := json.Marshal(map[string]string{"sessionId": "ds-async"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("session create status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Exec async
	async := true
	execPayload, _ := json.Marshal(map[string]interface{}{
		"command":  "echo async-hello",
		"runAsync": async,
	})
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/process/session/ds-async/exec", bytes.NewReader(execPayload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("daytona async exec status = %d body=%s", rec.Code, rec.Body.String())
	}
	var execResp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &execResp); err != nil {
		t.Fatalf("async exec json: %v", err)
	}
	if execResp["cmdId"] == nil {
		t.Fatalf("async exec should return cmdId: %v", execResp)
	}
}

func TestDaytonaSessionCommandGetAndLogs(t *testing.T) {
	h, _ := newHostWithSessions(t)

	// Create session
	payload, _ := json.Marshal(map[string]string{"sessionId": "ds-cmdget"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	// Exec a synchronous command
	execPayload, _ := json.Marshal(map[string]string{"command": "echo getme"})
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/process/session/ds-cmdget/exec", bytes.NewReader(execPayload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("exec status = %d body=%s", rec.Code, rec.Body.String())
	}
	var execResp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &execResp); err != nil {
		t.Fatalf("exec json: %v", err)
	}
	cmdID, _ := execResp["cmdId"].(string)
	if cmdID == "" {
		t.Fatalf("no cmdId in response: %v", execResp)
	}

	// GET /process/session/ds-cmdget/command/{cmdID}
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/process/session/ds-cmdget/command/"+cmdID, nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("command get status = %d body=%s", rec.Code, rec.Body.String())
	}

	// GET /process/session/ds-cmdget/command/{cmdID}/logs
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/process/session/ds-cmdget/command/"+cmdID+"/logs", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("command logs status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionCommandNotFound(t *testing.T) {
	h, _ := newHostWithSessions(t)

	// Create session
	payload, _ := json.Marshal(map[string]string{"sessionId": "ds-cmdnotfound"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	// GET command that doesn't exist
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/process/session/ds-cmdnotfound/command/bogus-id", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("command not found status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionCommandLogsNotFound(t *testing.T) {
	h, _ := newHostWithSessions(t)

	payload, _ := json.Marshal(map[string]string{"sessionId": "ds-lognotfound"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/process/session/ds-lognotfound/command/bogus/logs", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("command logs not found status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionCommandRouteMethodNotAllowed(t *testing.T) {
	h, _ := newHostWithSessions(t)

	payload, _ := json.Marshal(map[string]string{"sessionId": "ds-mna"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	// POST to command GET endpoint
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/process/session/ds-mna/command/abc", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("command method not allowed status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionRouteMethodNotAllowed(t *testing.T) {
	h, _ := newHostWithSessions(t)

	payload, _ := json.Marshal(map[string]string{"sessionId": "ds-rmna"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	// PATCH to session
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPatch, "/process/session/ds-rmna", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("session method not allowed status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionCreateBadJSON(t *testing.T) {
	h, _ := newHostWithSessions(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader([]byte("notjson")))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create bad json status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionCreateEmptySessionID(t *testing.T) {
	h, _ := newHostWithSessions(t)

	payload, _ := json.Marshal(map[string]string{"sessionId": ""})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty session id status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionExecMethodNotAllowed(t *testing.T) {
	h, _ := newHostWithSessions(t)

	payload, _ := json.Marshal(map[string]string{"sessionId": "ds-execmna"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	// GET on exec endpoint
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/process/session/ds-execmna/exec", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("exec method not allowed status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionRouteNotFound(t *testing.T) {
	h, _ := newHostWithSessions(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/process/session/ds1/unknown-action", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown action status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaProcessRouteMethodNotAllowed(t *testing.T) {
	h, _ := newHostWithSessions(t)

	// PATCH to /process/session root
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/process/session", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("process session PATCH status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionCommandInputNotFound(t *testing.T) {
	h, _ := newHostWithSessions(t)

	payload, _ := json.Marshal(map[string]string{"data": "hello"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session/no-sess/command/abc/input", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("input not found status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionCommandInputCommandNotFound(t *testing.T) {
	h, _ := newHostWithSessions(t)

	// Create session but don't add any command
	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-input-no-cmd"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	payload, _ := json.Marshal(map[string]string{"data": "hello"})
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/process/session/ds-input-no-cmd/command/bogus-cmd/input", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("input cmd not found status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionCommandInputConflict(t *testing.T) {
	h, _ := newHostWithSessions(t)

	// Create session
	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-input-conflict"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	// Exec a synchronous command (which will already be done by the time we try input)
	execPayload, _ := json.Marshal(map[string]string{"command": "echo done"})
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/process/session/ds-input-conflict/exec", bytes.NewReader(execPayload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("exec status = %d body=%s", rec.Code, rec.Body.String())
	}
	var execResp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &execResp)
	cmdID, _ := execResp["cmdId"].(string)

	// Try to input to a finished command → 409 Conflict
	payload, _ := json.Marshal(map[string]string{"data": "hello"})
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/process/session/ds-input-conflict/command/"+cmdID+"/input", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusConflict {
		t.Fatalf("input to finished cmd status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionCommandLogsMethodNotAllowed(t *testing.T) {
	h, _ := newHostWithSessions(t)

	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-logsmna"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/process/session/ds-logsmna/command/abc/logs", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("logs method not allowed status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionCommandInputMethodNotAllowed(t *testing.T) {
	h, _ := newHostWithSessions(t)

	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-inputmna"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/process/session/ds-inputmna/command/abc/input", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("input method not allowed status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionCommandUnknownSubroute(t *testing.T) {
	h, _ := newHostWithSessions(t)

	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-cmdunknown"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/process/session", bytes.NewReader(pl))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/process/session/ds-cmdunknown/command/abc/unknown-sub", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown subroute status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionEntrypointNotImplemented(t *testing.T) {
	h, _ := newHostWithSessions(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/process/session/entrypoint", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("entrypoint status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionDeleteOK(t *testing.T) {
	h, _ := newHostWithSessions(t)

	// Create session
	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-del"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)

	// Delete it
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodDelete, "/process/session/ds-del", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("daytona delete status = %d body=%s", rec.Code, rec.Body.String())
	}
}

// Verify we satisfy the StateKV interface with errStateKV.
var _ toolhost.StateKV = (*errStateKV)(nil)

// Dummy reference for errors to prevent import erasure.
var _ = errors.New

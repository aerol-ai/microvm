package toolhost_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func newHost(t *testing.T, opts ...func(*toolhost.Config)) *toolhost.Host {
	t.Helper()
	cfg := toolhost.Config{
		SandboxID: "sb-test",
		WorkDir:   t.TempDir(),
		Exec:      &stubExec{},
		StateKV:   newMemStateKV(),
	}
	for _, o := range opts {
		o(&cfg)
	}
	return toolhost.New(cfg)
}

func serve(h *toolhost.Host, method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	var reqBody *bytes.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reqBody)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, req)
	return rec
}

// ─── Root / version / health ─────────────────────────────────────────────────

func TestHostRootInfo(t *testing.T) {
	h := newHost(t)
	rec := serve(h, http.MethodGet, "/", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("root status = %d", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("root json: %v", err)
	}
	if resp["runtime"] != "wasm" {
		t.Fatalf("runtime = %v", resp["runtime"])
	}
}

func TestHostVersionEndpoint(t *testing.T) {
	h := newHost(t)
	rec := serve(h, http.MethodGet, "/version", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("version status = %d", rec.Code)
	}
}

func TestHostDefaultRoute(t *testing.T) {
	h := newHost(t)
	rec := serve(h, http.MethodGet, "/unknown-path", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d", rec.Code)
	}
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

func TestHostAuthRequired(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		AuthToken: "secret",
		Exec:      &stubExec{},
	})

	// No auth header → 401
	rec := serve(h, http.MethodPost, "/process/execute", []byte(`{"command":"echo"}`), map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth status = %d", rec.Code)
	}

	// Wrong token → 401
	rec = serve(h, http.MethodPost, "/process/execute", []byte(`{"command":"echo"}`), map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer wrong",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong auth status = %d", rec.Code)
	}
}

func TestHostAuthTokenAccepted(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		AuthToken: "tok",
		Exec:      &stubExec{},
	})
	payload, _ := json.Marshal(models.ExecRequest{Command: "ls"})
	rec := serve(h, http.MethodPost, "/process/execute", payload, map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer tok",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid auth status = %d body=%s", rec.Code, rec.Body.String())
	}
}

// ─── Sandbox prefix stripping ─────────────────────────────────────────────────

func TestHostSandboxPrefixStripped(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "mysandbox",
		WorkDir:   t.TempDir(),
	})
	// /mysandbox → root
	rec := serve(h, http.MethodGet, "/mysandbox", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/mysandbox status = %d body=%s", rec.Code, rec.Body.String())
	}
	// /mysandbox/ → root
	rec = serve(h, http.MethodGet, "/mysandbox/", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/mysandbox/ status = %d body=%s", rec.Code, rec.Body.String())
	}
	// /mysandbox/health → health
	rec = serve(h, http.MethodGet, "/mysandbox/health", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/mysandbox/health status = %d body=%s", rec.Code, rec.Body.String())
	}
}

// ─── Exec ─────────────────────────────────────────────────────────────────────

func TestHostExecBadJSON(t *testing.T) {
	h := newHost(t)
	rec := serve(h, http.MethodPost, "/process/execute", []byte("notjson"), map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json status = %d", rec.Code)
	}
}

func TestHostExecEmptyCommand(t *testing.T) {
	h := newHost(t)
	payload, _ := json.Marshal(models.ExecRequest{Command: "   "})
	rec := serve(h, http.MethodPost, "/process/execute", payload, map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty command status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostExecNilExecutor(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	payload, _ := json.Marshal(models.ExecRequest{Command: "echo"})
	rec := serve(h, http.MethodPost, "/process/execute", payload, map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil exec status = %d body=%s", rec.Code, rec.Body.String())
	}
}

type errExec struct{}

func (e *errExec) Exec(_ *http.Request, _ models.ExecRequest) (models.ExecResult, error) {
	return models.ExecResult{}, errors.New("exec error")
}

func TestHostExecError(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		Exec:      &errExec{},
	})
	payload, _ := json.Marshal(models.ExecRequest{Command: "fail"})
	rec := serve(h, http.MethodPost, "/process/execute", payload, map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("exec error status = %d body=%s", rec.Code, rec.Body.String())
	}
}

// ─── Code-run interpreter routes ─────────────────────────────────────────────

func TestHostCodeRunBadJSON(t *testing.T) {
	h := newHost(t)
	rec := serve(h, http.MethodPost, "/process/code-run", []byte("notjson"), map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json status = %d", rec.Code)
	}
}

func TestHostCodeRunMissingCode(t *testing.T) {
	h := newHost(t)
	payload, _ := json.Marshal(map[string]string{"language": "python"})
	rec := serve(h, http.MethodPost, "/process/code-run", payload, map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing code status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostCodeRunUnsupportedLanguage(t *testing.T) {
	h := newHost(t)
	payload, _ := json.Marshal(map[string]string{"code": "x", "language": "cobol"})
	rec := serve(h, http.MethodPost, "/process/code-run", payload, map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported language status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostCodeRunInterpreterNotInstalled(t *testing.T) {
	h := newHost(t)
	// ts-node is unlikely to be installed in test environment
	payload, _ := json.Marshal(map[string]string{"code": "console.log(1)", "language": "typescript"})
	rec := serve(h, http.MethodPost, "/process/code-run", payload, map[string]string{
		"Content-Type": "application/json",
	})
	// 400 if ts-node not found, 200 if it is — either is valid
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusOK {
		t.Fatalf("ts-node status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostCodeRunBash(t *testing.T) {
	h := newHost(t)
	payload, _ := json.Marshal(map[string]string{"code": "echo hello", "language": "bash"})
	rec := serve(h, http.MethodPost, "/process/code-run", payload, map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("bash status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bash json: %v", err)
	}
}

func TestHostCodeInterpreterNotImplemented(t *testing.T) {
	h := newHost(t)
	rec := serve(h, http.MethodPost, "/process/interpreter/python", nil, nil)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("interpreter status = %d body=%s", rec.Code, rec.Body.String())
	}
}

// ─── Files ────────────────────────────────────────────────────────────────────

func TestHostUploadMissingPath(t *testing.T) {
	h := newHost(t)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	part, _ := w.CreateFormFile("file", "f.txt")
	_, _ = part.Write([]byte("data"))
	_ = w.Close()
	rec := serve(h, http.MethodPost, "/files/upload", body.Bytes(), map[string]string{
		"Content-Type": w.FormDataContentType(),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing path status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostUploadMissingFile(t *testing.T) {
	h := newHost(t)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	_ = w.WriteField("path", "/file.txt")
	_ = w.Close()
	rec := serve(h, http.MethodPost, "/files/upload", body.Bytes(), map[string]string{
		"Content-Type": w.FormDataContentType(),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing file status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostUploadPathEscape(t *testing.T) {
	h := newHost(t)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	_ = w.WriteField("path", "/../escape.txt")
	part, _ := w.CreateFormFile("file", "escape.txt")
	_, _ = part.Write([]byte("x"))
	_ = w.Close()
	rec := serve(h, http.MethodPost, "/files/upload", body.Bytes(), map[string]string{
		"Content-Type": w.FormDataContentType(),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("escape status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostDownloadMissingPath(t *testing.T) {
	h := newHost(t)
	rec := serve(h, http.MethodGet, "/files/download", nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing path status = %d", rec.Code)
	}
}

func TestHostDownloadNotFound(t *testing.T) {
	h := newHost(t)
	rec := serve(h, http.MethodGet, "/files/download?path=/nofile.txt", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("not found status = %d", rec.Code)
	}
}

func TestHostListFilesRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   dir,
	})
	rec := serve(h, http.MethodGet, "/files", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list files status = %d body=%s", rec.Code, rec.Body.String())
	}
	var names []string
	if err := json.Unmarshal(rec.Body.Bytes(), &names); err != nil {
		t.Fatalf("list files json: %v", err)
	}
	found := false
	for _, n := range names {
		if n == "hello.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("hello.txt not in listing: %v", names)
	}
}

func TestHostListFilesPathError(t *testing.T) {
	h := newHost(t)
	rec := serve(h, http.MethodGet, "/files?path=/../escape", nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("escape list files status = %d", rec.Code)
	}
}

func TestHostListFilesNonExistent(t *testing.T) {
	h := newHost(t)
	rec := serve(h, http.MethodGet, "/files?path=/no-such-subdir", nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("non-existent dir status = %d", rec.Code)
	}
}

// ─── State KV extra coverage ───────────────────────────────────────────────────

func TestHostStateKVNotConfigured(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		// no StateKV
	})
	rec := serve(h, http.MethodGet, "/state/kv/mykey", nil, nil)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("no stateKV status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVMethodNotAllowed(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   newMemStateKV(),
	})
	rec := serve(h, http.MethodPatch, "/state/kv/key", nil, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method not allowed status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVPutEmptyKey(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   newMemStateKV(),
	})
	rec := serve(h, http.MethodPut, "/state/kv/", []byte("val"), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty key PUT status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVDeleteEmptyKey(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   newMemStateKV(),
	})
	rec := serve(h, http.MethodDelete, "/state/kv/", nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty key DELETE status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVGetError(t *testing.T) {
	kv := &errStateKV{}
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   kv,
	})
	rec := serve(h, http.MethodGet, "/state/kv/key", nil, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("get error status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVListError(t *testing.T) {
	kv := &errStateKV{}
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   kv,
	})
	rec := serve(h, http.MethodGet, "/state/kv/", nil, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("list error status = %d body=%s", rec.Code, rec.Body.String())
	}
}

type errStateKV struct{}

func (e *errStateKV) Get(_ context.Context, _, _ string) ([]byte, bool, error) {
	return nil, false, errors.New("get error")
}
func (e *errStateKV) Set(_ context.Context, _, _ string, _ []byte) error {
	return errors.New("set error")
}
func (e *errStateKV) Delete(_ context.Context, _, _ string) error {
	return errors.New("delete error")
}
func (e *errStateKV) ListKeys(_ context.Context, _ string) ([]string, error) {
	return nil, errors.New("list error")
}

// ─── Sessions (nil manager) ────────────────────────────────────────────────────

func TestHostSessionsWithoutManager(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	// GET /sessions → 200 with empty list (sessions == nil)
	rec := serve(h, http.MethodGet, "/sessions", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("sessions list nil manager status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsCreateNilManager(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	payload, _ := json.Marshal(map[string]string{"name": "my-sess"})
	rec := serve(h, http.MethodPost, "/sessions", payload, map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("create nil sessions status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsGetNilManager(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	rec := serve(h, http.MethodGet, "/sessions/abc", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get nil sessions status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsDeleteNilManager(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	rec := serve(h, http.MethodDelete, "/sessions/abc", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete nil sessions status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsSignalNilManager(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	rec := serve(h, http.MethodPost, "/sessions/abc/signal", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("signal nil sessions status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsResizeNilManager(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	rec := serve(h, http.MethodPost, "/sessions/abc/resize", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("resize nil sessions status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsLogNilManager(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	rec := serve(h, http.MethodGet, "/sessions/abc/log", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("log nil sessions status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsRecordingNilManager(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	rec := serve(h, http.MethodGet, "/sessions/abc/recording", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("recording nil sessions status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsAttachNilManager(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	rec := serve(h, http.MethodGet, "/sessions/abc/attach", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("attach nil sessions status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsMethodNotAllowed(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	// PUT to /sessions root — method not allowed
	rec := serve(h, http.MethodPut, "/sessions", nil, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("sessions put status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsEmptyIDDeleteMethodNotAllowed(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	// DELETE /sessions → method not allowed (only POST and GET supported at root)
	rec := serve(h, http.MethodDelete, "/sessions", nil, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE /sessions status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsUnknownAction(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	rec := serve(h, http.MethodGet, "/sessions/abc/bogus-action", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown action status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsMethodOnID(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	// PUT to /sessions/abc — method not allowed on id
	rec := serve(h, http.MethodPut, "/sessions/abc", nil, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT on session id status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsSignalMethodNotAllowed(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	rec := serve(h, http.MethodGet, "/sessions/abc/signal", nil, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("signal GET status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsResizeMethodNotAllowed(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	rec := serve(h, http.MethodGet, "/sessions/abc/resize", nil, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("resize GET status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsLogMethodNotAllowed(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	rec := serve(h, http.MethodPost, "/sessions/abc/log", nil, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("log POST status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsRecordingMethodNotAllowed(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	rec := serve(h, http.MethodPost, "/sessions/abc/recording", nil, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("recording POST status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostSessionsAttachMethodNotAllowed(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	rec := serve(h, http.MethodPost, "/sessions/abc/attach", nil, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("attach POST status = %d body=%s", rec.Code, rec.Body.String())
	}
}

// ─── Daytona process route (sessions disabled) ────────────────────────────────

func TestHostDaytonaProcessSessionsDisabled(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		// sessions == nil, so daytona routes → 501
	})
	rec := serve(h, http.MethodPost, "/process/session", []byte(`{"sessionId":"s1"}`), map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("daytona sessions disabled status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostDaytonaProcessNotFound(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		// sessions == nil triggers 501 before returning false
	})
	rec := serve(h, http.MethodGet, "/process/session/unknown/bogus", nil, nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("bogus daytona route status = %d body=%s", rec.Code, rec.Body.String())
	}
}

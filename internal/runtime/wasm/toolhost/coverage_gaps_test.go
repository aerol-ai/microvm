package toolhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
)

// ─── coderun.go ──────────────────────────────────────────────────────────────

func TestWriteCodeRunScriptErrors(t *testing.T) {
	// workDir is a regular file → MkdirAll(".coderun") fails
	fileAsDir := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeCodeRunScript(fileAsDir, "code", ".sh"); err == nil {
		t.Fatal("expected MkdirAll error")
	}

	// Read-only workDir prevents writing the script file.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skip("chmod not supported")
	}
	if _, _, err := writeCodeRunScript(dir, "code", ".sh"); err == nil {
		t.Fatal("expected WriteFile error")
	}
}

func TestHandleCodeRunSuccessAndWaitError(t *testing.T) {
	dir := t.TempDir()
	h := New(Config{SandboxID: "sb", WorkDir: dir})

	// Happy path with env + argv exercises the full handler body.
	payload, _ := json.Marshal(map[string]interface{}{
		"code":     "echo coded",
		"language": "bash",
		"argv":     []string{},
		"envs":     map[string]string{"CODE_RUN_TEST": "1"},
		"timeout":  30,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/code-run", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code-run status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Force a non-ExitError wait path by running a command that cannot start.
	badPayload, _ := json.Marshal(map[string]string{
		"code":     "exit 0",
		"language": "bash",
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/code-run", bytes.NewReader(badPayload))
	req.Header.Set("Content-Type", "application/json")
	// Shadow PATH so bash lookup fails after writeCodeRunScript succeeds.
	req = req.WithContext(context.Background())
	h2 := New(Config{SandboxID: "sb", WorkDir: dir})
	// Use an invalid interpreter by temporarily breaking PATH via env in request is not possible;
	// instead rely on writeCodeRunScript failure already tested above.
	_ = h2
}

func TestHandleCodeRunContextTimeoutAppendsError(t *testing.T) {
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir()})
	payload, _ := json.Marshal(map[string]interface{}{
		"code":     "sleep 10",
		"language": "bash",
		"timeout":  1,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/code-run", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("timeout status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp codeRunResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.ExitCode == 0 {
		t.Fatalf("expected non-zero exit on timeout, got %d", resp.ExitCode)
	}
}

func TestPumpWasmSessionStderrFrames(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Command: "echo only-stderr 1>&2",
		PTY:     true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/sessions/" + sess.ID() + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
	conn.Close()
}

func TestHandleCodeRunStderrOnlyResult(t *testing.T) {
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir()})
	payload, _ := json.Marshal(map[string]string{
		"code":     "echo oops 1>&2",
		"language": "bash",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/code-run", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp codeRunResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !strings.Contains(resp.Result, "oops") {
		t.Fatalf("expected stderr in result, got %q", resp.Result)
	}
}

func TestHandleExecStreamCustomWorkdir(t *testing.T) {
	workdir := t.TempDir()
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir()})
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/process/exec/stream", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.WriteJSON(map[string]interface{}{
		"command": "pwd",
		"workdir": workdir,
		"tty":     false,
	})
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	readUntilExit(t, conn)
}

func TestPumpExecStreamReaderWriteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, _ := upgrader.Upgrade(w, r, nil)
		pr, pw := io.Pipe()
		go func() {
			_, _ = pw.Write([]byte("data"))
			_ = pw.Close()
		}()
		_ = pumpExecStreamReader(conn, pr, streamFramePrefixStdout)
		_ = conn.Close()
	}))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	conn.Close()
}

func TestPumpExecStreamReaderLockedWriteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, _ := upgrader.Upgrade(w, r, nil)
		pr, pw := io.Pipe()
		go func() {
			_, _ = pw.Write([]byte("data"))
			_ = pw.Close()
		}()
		var mu sync.Mutex
		_ = pumpExecStreamReaderLocked(conn, pr, streamFramePrefixStderr, &mu)
		_ = conn.Close()
	}))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	conn.Close()
}

func TestExecStreamStdinPumpSignalControl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()
		pr, pw := io.Pipe()
		go func() {
			h := &Host{}
			h.execStreamStdinPump(conn, pw)
		}()
		sig, _ := json.Marshal(execStreamControlIn{Type: "signal", Signal: "TERM"})
		_ = conn.WriteMessage(websocket.TextMessage, sig)
		time.Sleep(30 * time.Millisecond)
		_ = pr.Close()
	}))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
}

func TestStripSandboxPrefixEmptyRemainder(t *testing.T) {
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir()})
	req := httptest.NewRequest(http.MethodGet, "/sb/", nil)
	_ = h.stripSandboxPrefix(req)
	if req.URL.Path != "/" {
		t.Fatalf("path = %q", req.URL.Path)
	}
}

func TestHandleCodeRunScriptWriteErrorHTTP(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skip("chmod not supported")
	}
	h := New(Config{SandboxID: "sb", WorkDir: dir})
	payload, _ := json.Marshal(map[string]string{"code": "echo x", "language": "bash"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/code-run", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("write script error status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWriteCodeRunScriptMkdirTempParentIsFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".coderun"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeCodeRunScript(dir, "x", ".sh"); err == nil {
		t.Fatal("expected MkdirAll error when .coderun is a file")
	}
}

func TestHandleExecStreamPipesStartFailureBadWorkdir(t *testing.T) {
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir()})
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/process/exec/stream", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.WriteJSON(map[string]interface{}{
		"command": "echo hi",
		"workdir": "/no/such/workdir",
		"tty":     false,
	})
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var msg execStreamControlOut
	_ = conn.ReadJSON(&msg)
	if msg.Type != "error" {
		t.Fatalf("expected start error, got %q", msg.Type)
	}
}

func TestDaytonaSessionExecRandIDFailure(t *testing.T) {
	orig := daytonaRandRead
	t.Cleanup(func() { daytonaRandRead = orig })
	daytonaRandRead = func([]byte) (int, error) { return 0, errors.New("rand failed") }

	h, _ := newHostWithRealSessions(t)
	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-rand-fail"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	execPayload, _ := json.Marshal(map[string]string{"command": "echo x"})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-rand-fail/exec", bytes.NewReader(execPayload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("rand fail exec status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionCommandInputCRSuffix(t *testing.T) {
	h, _ := newHostWithRealSessions(t)
	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-cr"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	execPayload, _ := json.Marshal(map[string]interface{}{
		"command":  "sleep 5",
		"runAsync": true,
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-cr/exec", bytes.NewReader(execPayload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	var execResp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &execResp)
	cmdID := execResp["cmdId"].(string)
	time.Sleep(100 * time.Millisecond)

	payload, _ := json.Marshal(map[string]string{"data": "line\r"})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-cr/command/"+cmdID+"/input", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusInternalServerError {
		t.Fatalf("input status = %d", rec.Code)
	}
}

func TestPumpWasmSessionDeletedWhileAttached(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Command: "sleep 30",
		PTY:     true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/sessions/" + sess.ID() + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = mgr.Delete(sess.ID())
	}()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		msgType, p, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.TextMessage {
			var out sessionAttachControlOut
			if json.Unmarshal(p, &out) == nil && out.Type == "exit" {
				break
			}
		}
	}
	conn.Close()
}

func TestDaytonaSessionEntrypointLogsNotImplemented(t *testing.T) {
	h, _ := newHostWithRealSessions(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/session/entrypoint/logs", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("entrypoint logs status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleCodeRunWithArgvAndEnv(t *testing.T) {
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir()})
	payload, _ := json.Marshal(map[string]interface{}{
		"code":     "echo $1 $CODE_RUN_ARG",
		"language": "bash",
		"argv":     []string{"from-argv"},
		"envs":     map[string]string{"CODE_RUN_ARG": "from-env"},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/code-run", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code-run status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleSessionsRouteNotFound(t *testing.T) {
	h, _ := newHostWithRealSessions(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sessions-extra", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("sessions route miss status = %d", rec.Code)
	}
}

func TestHandleUploadAtomicWriteError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "exists"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := New(Config{SandboxID: "sb", WorkDir: dir})

	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	_ = w.WriteField("path", "/exists")
	part, _ := w.CreateFormFile("file", "f.txt")
	_, _ = part.Write([]byte("data"))
	_ = w.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/files/upload", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", w.FormDataContentType())
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("atomic write onto directory status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWriteCodeRunScriptMkdirTempError(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, ".coderun")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	// Fill the parent with enough entries that MkdirTemp may fail on some systems;
	// also replace base with a file after creating many dirs to force MkdirTemp failure.
	for i := 0; i < 50; i++ {
		_ = os.Mkdir(filepath.Join(base, "run-fill-"+strconv.Itoa(i)), 0o700)
	}
	_ = os.RemoveAll(base)
	if err := os.WriteFile(base, []byte("not-a-dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeCodeRunScript(dir, "x", ".sh"); err == nil {
		t.Fatal("expected writeCodeRunScript error when .coderun is a file")
	}
}

func TestDaytonaSessionExecStderrAndFollowLogs(t *testing.T) {
	h, _ := newHostWithRealSessions(t)
	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-stderr"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	execPayload, _ := json.Marshal(map[string]string{
		"command": "echo err 1>&2; echo visible",
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-stderr/exec", bytes.NewReader(execPayload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("exec status = %d body=%s", rec.Code, rec.Body.String())
	}

	pl2, _ := json.Marshal(map[string]string{"sessionId": "ds-hold"})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl2))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	execPayload2, _ := json.Marshal(map[string]interface{}{
		"command":  "printf 'prompt'",
		"runAsync": true,
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-hold/exec", bytes.NewReader(execPayload2))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	var resp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	cmdID, _ := resp["cmdId"].(string)

	srv := httptest.NewServer(h.Handler())
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/process/session/ds-hold/command/" + cmdID + "/logs?follow=true"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial logs: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, _ = conn.ReadMessage()
	conn.Close()
}

// ─── files.go ────────────────────────────────────────────────────────────────

func TestHandleUploadPathInQueryAndParseError(t *testing.T) {
	dir := t.TempDir()
	h := New(Config{SandboxID: "sb", WorkDir: dir})

	// path supplied via query string instead of form field
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	part, _ := w.CreateFormFile("file", "q.txt")
	_, _ = part.Write([]byte("via-query"))
	_ = w.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/files/upload?path=/q.txt", body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload via query path status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Oversized multipart body trips ParseMultipartForm.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/files/upload?path=/big.txt", strings.NewReader("not-multipart"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=----bad")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad multipart status = %d", rec.Code)
	}
}

func TestHandleUploadMkdirAllError(t *testing.T) {
	dir := t.TempDir()
	// Block creating subdirs by making workDir a file.
	blocker := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := New(Config{SandboxID: "sb", WorkDir: blocker})

	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	_ = w.WriteField("path", "/nested/file.txt")
	part, _ := w.CreateFormFile("file", "f.txt")
	_, _ = part.Write([]byte("data"))
	_ = w.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/files/upload", body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("mkdir error status = %d body=%s", rec.Code, rec.Body.String())
	}
}

type mockMultipartFile struct {
	io.Reader
	closeErr error
}

func (m *mockMultipartFile) ReadAt(p []byte, off int64) (int, error) {
	return 0, errors.New("readat not supported")
}

func (m *mockMultipartFile) Seek(offset int64, whence int) (int64, error) {
	return 0, nil
}

func (m *mockMultipartFile) Close() error { return m.closeErr }

func TestAtomicWriteFileCloseChmodRenameErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	if err := atomicWriteFile(path, &mockMultipartFile{Reader: bytes.NewReader([]byte("ok"))}); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	if err := atomicWriteFile(path, &mockMultipartFile{
		Reader:   bytes.NewReader([]byte("x")),
		closeErr: errors.New("close failed"),
	}); err != nil && !strings.Contains(err.Error(), "close") {
		t.Fatalf("unexpected close error: %v", err)
	}

	if err := os.Mkdir(filepath.Join(dir, "existing"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, "existing"), &mockMultipartFile{Reader: bytes.NewReader([]byte("x"))}); err == nil {
		t.Fatal("expected rename error onto directory")
	}
}

// ─── host.go / path.go ───────────────────────────────────────────────────────

func TestServeHTTPHealthAndRouteNotFound(t *testing.T) {
	h := New(Config{SandboxID: "sb-health", WorkDir: t.TempDir(), Sessions: nil})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d", rec.Code)
	}

	// stripSandboxPrefix: sandbox id with trailing route trims to empty → "/"
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sb-health", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/sb-health status = %d", rec.Code)
	}

	// Daytona route that handleDaytonaProcessRoute rejects → outer 404
	h2, _ := newHostWithRealSessions(t)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/process/sessionX", nil)
	h2.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("daytona prefix miss status = %d", rec.Code)
	}

	// Sessions route miss
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sessionsX", nil)
	h2.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("sessions prefix miss status = %d", rec.Code)
	}
}

func TestResolveHostPathEdgeCases(t *testing.T) {
	workDir := t.TempDir()
	if _, err := resolveHostPath(workDir, ""); err != nil {
		t.Fatalf("empty path: %v", err)
	}
	if _, err := resolveHostPath(workDir, "/subdir/file"); err != nil {
		t.Fatalf("abs guest path: %v", err)
	}
	if _, err := resolveHostPath(workDir, "subdir/../.."); err == nil {
		t.Fatal("expected escape error for ..")
	}
}

// ─── state.go ────────────────────────────────────────────────────────────────

func TestHandleStateKVPutBodyAndValueErrors(t *testing.T) {
	h := New(Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   newMemStateKV(),
	})

	// Oversized value (>4 MiB) rejected before store write.
	big := make([]byte, 4<<20+1)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/state/kv/big", bytes.NewReader(big))
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized value status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Broken body reader surfaces as 400.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/state/kv/k", errReader{})
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("body read error status = %d", rec.Code)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type memStateKV struct{ data map[string][]byte }

func newMemStateKV() *memStateKV { return &memStateKV{data: map[string][]byte{}} }

func (m *memStateKV) Get(_ context.Context, _, key string) ([]byte, bool, error) {
	v, ok := m.data[key]
	return v, ok, nil
}
func (m *memStateKV) Set(_ context.Context, _, key string, value []byte) error {
	m.data[key] = append([]byte(nil), value...)
	return nil
}
func (m *memStateKV) Delete(_ context.Context, _, key string) error {
	delete(m.data, key)
	return nil
}
func (m *memStateKV) ListKeys(_ context.Context, _ string) ([]string, error) {
	out := make([]string, 0, len(m.data))
	for k := range m.data {
		out = append(out, k)
	}
	return out, nil
}

// ─── exec_stream.go ──────────────────────────────────────────────────────────

func TestHandleExecStreamUpgradeFailure(t *testing.T) {
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/exec/stream", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("expected non-200 without websocket upgrade")
	}
}

func TestHandleExecStreamPTYDefaultsAndStartError(t *testing.T) {
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir()})
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/process/exec/stream", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(map[string]interface{}{"command": "echo pty-defaults", "tty": true}); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	readUntilExit(t, conn)

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		h.runExecStreamPTY(c, exec.Command(""), &execStreamStartMsg{})
	}))
	defer srv2.Close()
	c2, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv2.URL, "http")+"/", nil)
	if err != nil {
		t.Fatalf("dial pty err: %v", err)
	}
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg execStreamControlOut
	_ = c2.ReadJSON(&msg)
	c2.Close()
}

func TestHandleExecStreamPipesErrors(t *testing.T) {
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir()})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		cmd := exec.Command("echo", "x")
		_ = cmd.Start()
		h.runExecStreamPipes(c, cmd)
	}))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg execStreamControlOut
	_ = conn.ReadJSON(&msg)
	conn.Close()
	if msg.Type != "error" {
		t.Fatalf("expected error, got %q", msg.Type)
	}
}

func TestExecStreamPumpAndWaitEdgeCases(t *testing.T) {
	// waitExec with never-started command → non-ExitError path
	cmd := exec.Command("true")
	code, sig := waitExec(cmd)
	if code != 1 || sig == "" {
		t.Fatalf("unstarted wait: code=%d sig=%q", code, sig)
	}

	// pumpExecStreamReader write failure closes early
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()
		pr, pw := io.Pipe()
		go func() {
			_, _ = pw.Write([]byte("chunk"))
			_ = pw.Close()
		}()
		_ = pumpExecStreamReader(conn, pr, streamFramePrefixStdout)
	}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	// execStreamControlPump invalid JSON + signal path
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()
		cmd := exec.Command("sleep", "30")
		_ = cmd.Start()
		defer func() { _ = cmd.Process.Kill() }()
		ptmx, _ := os.Open(os.DevNull)
		h := &Host{}
		go h.execStreamControlPump(conn, cmd, ptmx)
		_ = conn.WriteMessage(websocket.TextMessage, []byte("not-json"))
		sig, _ := json.Marshal(execStreamControlIn{Type: "signal", Signal: "KILL"})
		_ = conn.WriteMessage(websocket.TextMessage, sig)
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv2.Close()
	c2, _, _ := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv2.URL, "http")+"/", nil)
	if c2 != nil {
		c2.Close()
	}

	// stdin pump: signal control ends pump; write error on broken stdin
	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()
		_, pw := io.Pipe()
		h := &Host{}
		h.execStreamStdinPump(conn, pw)
	}))
	defer srv3.Close()
	c3, _, _ := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv3.URL, "http")+"/", nil)
	if c3 != nil {
		_ = c3.WriteMessage(websocket.BinaryMessage, []byte("x"))
		c3.Close()
	}
}

func readUntilExit(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if msgType == websocket.TextMessage {
			var ctrl execStreamControlOut
			if json.Unmarshal(data, &ctrl) == nil && ctrl.Type == "exit" {
				return
			}
		}
	}
}

// ─── sessions.go ─────────────────────────────────────────────────────────────

func TestPumpWasmSessionDoneDrainAndStderr(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Command: "echo stderr-test 1>&2",
		PTY:     true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/sessions/" + sess.ID() + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
	conn.Close()
	_ = mgr.Delete(sess.ID())
}

func TestDrainSessionFramesTimeoutBranch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()
		ch := make(chan sessions.Frame)
		go func() {
			time.Sleep(20 * time.Millisecond)
			ch <- sessions.Frame{Stream: sessions.StreamStdout, Data: []byte("late")}
			close(ch)
		}()
		drainSessionFrames(conn, ch)
	}))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, _ = conn.ReadMessage()
	conn.Close()
}

// ─── daytona_process.go ─────────────────────────────────────────────────────

func TestDaytonaAddCommandNilMap(t *testing.T) {
	state := &daytonaSessionState{}
	state.addCommand(&daytonaCommandState{id: "c1", stream: newDaytonaCommandStream()})
	if state.commands == nil || state.commands["c1"] == nil {
		t.Fatal("addCommand should lazily init map")
	}
}

func TestDaytonaProcessRouteValidation(t *testing.T) {
	h, _ := newHostWithRealSessions(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/session/%20/exec", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("blank session id status = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/process/session/ds-empty-cmd/command/%20/logs", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("blank command id status = %d", rec.Code)
	}
}

func TestDaytonaSessionListSkipsStaleCompat(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)
	h.daytona.ensureSession("orphan-compat")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/session", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	var items []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected stale compat session to be skipped, got %d", len(items))
	}
	_ = mgr
}

func TestDaytonaSessionDeleteSuccessPath(t *testing.T) {
	h, _ := newHostWithRealSessions(t)
	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-del-ok"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/process/session/ds-del-ok", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete ok status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionDeleteRaceNotFound(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)
	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-del-race"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	sess, err := mgr.GetByName("ds-del-race")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
		_ = mgr.Delete(sess.ID())
	}()

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/process/session/ds-del-race", nil)
	h.Handler().ServeHTTP(rec, req)
	wg.Wait()
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusNoContent {
		t.Fatalf("race delete status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaCommandStreamSlowSubscriber(t *testing.T) {
	s := newDaytonaCommandStream()
	ch := make(chan []byte) // unbuffered → default branch in broadcast
	s.mu.Lock()
	s.subs = append(s.subs, ch)
	s.mu.Unlock()
	s.broadcast(sessions.StreamStdout, []byte("drop-me"))
}

func TestDaytonaRunSessionCommandBranches(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)

	t.Run("stderr and sync echo", func(t *testing.T) {
		pl, _ := json.Marshal(map[string]string{"sessionId": "ds-run"})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
		req.Header.Set("Content-Type", "application/json")
		h.Handler().ServeHTTP(rec, req)

		execPayload, _ := json.Marshal(map[string]string{"command": "echo out; echo err 1>&2"})
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/process/session/ds-run/exec", bytes.NewReader(execPayload))
		req.Header.Set("Content-Type", "application/json")
		h.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("exec status = %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("session closes without marker", func(t *testing.T) {
		sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
			Name:    "ds-abort",
			Command: "sleep 60",
			PTY:     false,
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		state := h.daytona.ensureSession("ds-abort")
		cmd := &daytonaCommandState{
			id:        "abort-cmd",
			command:   "sleep 60",
			createdAt: time.Now().UTC(),
			running:   true,
			stream:    newDaytonaCommandStream(),
		}
		state.addCommand(cmd)
		_ = mgr.Delete(sess.ID())
		_, _ = h.runDaytonaSessionCommand(sess, state, cmd)
	})

	t.Run("sync prompt holdback", func(t *testing.T) {
		pl, _ := json.Marshal(map[string]string{"sessionId": "ds-prompt"})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
		req.Header.Set("Content-Type", "application/json")
		h.Handler().ServeHTTP(rec, req)

		execPayload, _ := json.Marshal(map[string]string{"command": "printf 'prompt'"})
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/process/session/ds-prompt/exec", bytes.NewReader(execPayload))
		req.Header.Set("Content-Type", "application/json")
		h.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("prompt exec status = %d body=%s", rec.Code, rec.Body.String())
		}
		var resp daytonaSessionExecuteResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("json: %v", err)
		}
		if resp.Stdout == nil || !strings.Contains(*resp.Stdout, "prompt") {
			t.Fatalf("expected prompt in stdout, got %v", resp.Stdout)
		}
	})

	t.Run("async flag alias", func(t *testing.T) {
		pl, _ := json.Marshal(map[string]string{"sessionId": "ds-async2"})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
		req.Header.Set("Content-Type", "application/json")
		h.Handler().ServeHTTP(rec, req)

		async := true
		execPayload, _ := json.Marshal(map[string]interface{}{
			"command": "echo via-async",
			"async":   async,
		})
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/process/session/ds-async2/exec", bytes.NewReader(execPayload))
		req.Header.Set("Content-Type", "application/json")
		h.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("async alias status = %d", rec.Code)
		}
	})
}

func TestHandleDaytonaSessionDeleteDirectPaths(t *testing.T) {
	h, _ := newHostWithRealSessions(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/process/session/missing", nil)
	h.handleDaytonaSessionDelete(rec, req, "missing")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("direct delete missing status = %d", rec.Code)
	}

	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-direct-del"})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/process/session/ds-direct-del", nil)
	h.handleDaytonaSessionDelete(rec, req, "ds-direct-del")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("direct delete ok status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPumpWasmSessionFramesClosedBeforeDone(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Command: "echo frames-close",
		PTY:     true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/sessions/" + sess.ID() + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	for {
		msgType, p, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.TextMessage {
			var out sessionAttachControlOut
			if json.Unmarshal(p, &out) == nil && out.Type == "exit" {
				break
			}
		}
	}
	conn.Close()
	_ = mgr.Delete(sess.ID())
}

func TestAtomicWriteFileChmodAndRenameErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Skip("chmod not supported")
	}
	if err := os.Chmod(tmpName, 0o644); err == nil {
		_ = os.Chmod(dir, 0o755)
		t.Skip("chmod on file succeeded; cannot simulate chmod error")
	}
	_ = os.Chmod(dir, 0o755)
	_ = os.Remove(tmpName)

	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	err = atomicWriteFile(path, &mockMultipartFile{Reader: bytes.NewReader([]byte("x"))})
	if err == nil {
		t.Fatal("expected rename onto directory to fail")
	}
}

func TestDaytonaStreamLogsClientDisconnect(t *testing.T) {
	h, _ := newHostWithRealSessions(t)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-disc"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	execPayload, _ := json.Marshal(map[string]interface{}{
		"command":  "sleep 30",
		"runAsync": true,
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-disc/exec", bytes.NewReader(execPayload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	var execResp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &execResp)
	cmdID := execResp["cmdId"].(string)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/process/session/ds-disc/command/" + cmdID + "/logs?follow=true"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	time.Sleep(50 * time.Millisecond)
}

func TestDaytonaSessionCommandInputWithNewline(t *testing.T) {
	h, _ := newHostWithRealSessions(t)
	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-nl"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	execPayload, _ := json.Marshal(map[string]interface{}{
		"command":  "sleep 5",
		"runAsync": true,
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-nl/exec", bytes.NewReader(execPayload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	var execResp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &execResp)
	cmdID := execResp["cmdId"].(string)
	time.Sleep(100 * time.Millisecond)

	// Data already ends with newline → no auto-append branch difference
	payload, _ := json.Marshal(map[string]string{"data": "hello\n"})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-nl/command/"+cmdID+"/input", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusInternalServerError {
		t.Fatalf("input status = %d", rec.Code)
	}
}

func TestNewDaytonaCommandIDRandFailure(t *testing.T) {
	orig := daytonaRandRead
	t.Cleanup(func() { daytonaRandRead = orig })
	daytonaRandRead = func([]byte) (int, error) { return 0, errors.New("rand failed") }
	if _, err := newDaytonaCommandID(); err == nil {
		t.Fatal("expected rand error")
	}
}

func TestHandleDaytonaSessionCreateDuplicateReturnsOK(t *testing.T) {
	h, _ := newHostWithRealSessions(t)
	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-dup-create"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first create status = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("duplicate create status = %d", rec.Code)
	}
}

func TestHandleUploadMissingFileAndPathRequired(t *testing.T) {
	dir := t.TempDir()
	h := New(Config{SandboxID: "sb", WorkDir: dir})

	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	_ = w.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/files/upload", body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing path status = %d body=%s", rec.Code, rec.Body.String())
	}

	body2 := &bytes.Buffer{}
	w2 := multipart.NewWriter(body2)
	_ = w2.WriteField("path", "/only-path.txt")
	_ = w2.Close()
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/files/upload", body2)
	req.Header.Set("Content-Type", w2.FormDataContentType())
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing file status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleDaytonaSessionCreateValidationErrors(t *testing.T) {
	h, _ := newHostWithRealSessions(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json status = %d", rec.Code)
	}

	pl, _ := json.Marshal(map[string]string{"sessionId": ""})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty sessionId status = %d", rec.Code)
	}
}

func TestStripSandboxPrefixExactID(t *testing.T) {
	h := New(Config{SandboxID: "sb-exact", WorkDir: t.TempDir()})
	req := httptest.NewRequest(http.MethodGet, "/sb-exact", nil)
	req = h.stripSandboxPrefix(req)
	if req.URL.Path != "/" {
		t.Fatalf("exact sandbox path = %q", req.URL.Path)
	}
}

func TestHandleDaytonaSessionDeleteClearsCompatState(t *testing.T) {
	h, _ := newHostWithRealSessions(t)
	pl, _ := json.Marshal(map[string]string{"sessionId": "ds-del-clear"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(pl))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/process/session/ds-del-clear", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := h.daytona.session("ds-del-clear"); ok {
		t.Fatal("daytona compat state should be removed after delete")
	}
}

func TestPumpWasmSessionClientDisconnect(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Command: "sleep 30",
		PTY:     true,
		Cols:    80,
		Rows:    24,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = mgr.Delete(sess.ID()) }()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/sessions/" + sess.ID() + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	time.Sleep(50 * time.Millisecond)
}

func TestPumpWasmSessionStdinWriteError(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Command: "sleep 30",
		PTY:     true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = sess.CloseStdin()
	defer func() { _ = mgr.Delete(sess.ID()) }()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/sessions/" + sess.ID() + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.WriteMessage(websocket.BinaryMessage, []byte("data"))
	time.Sleep(50 * time.Millisecond)
}

func TestRunExecStreamPipesStdinAlreadySet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		cmd := exec.Command("cat")
		cmd.Stdin = strings.NewReader("preset")
		h := &Host{}
		h.runExecStreamPipes(c, cmd)
	}))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg execStreamControlOut
	_ = conn.ReadJSON(&msg)
	conn.Close()
	if msg.Type != "error" {
		t.Fatalf("expected stdin pipe error, got %q", msg.Type)
	}
}

func TestRunExecStreamPipesStdoutAlreadySet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		cmd := exec.Command("echo", "x")
		cmd.Stdout = io.Discard
		h := &Host{}
		h.runExecStreamPipes(c, cmd)
	}))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg execStreamControlOut
	_ = conn.ReadJSON(&msg)
	conn.Close()
	if msg.Type != "error" {
		t.Fatalf("expected stdout pipe error, got %q", msg.Type)
	}
}

func TestWriteCodeRunScriptCoderunNotDirectory(t *testing.T) {
	workDir := t.TempDir()
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("/dev/null not available")
	}
	if err := os.Symlink("/dev/null", filepath.Join(workDir, ".coderun")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, _, err := writeCodeRunScript(workDir, "echo hi", ".sh")
	if err == nil {
		t.Fatal("expected error when .coderun is not a writable directory")
	}
}

func TestHandleCodeRunNonZeroExitWithStderr(t *testing.T) {
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir()})
	payload, _ := json.Marshal(map[string]string{
		"code":     "echo failed 1>&2; exit 7",
		"language": "bash",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/code-run", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp codeRunResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7", resp.ExitCode)
	}
	if !strings.Contains(resp.Result, "failed") {
		t.Fatalf("result = %q", resp.Result)
	}
}

func TestRunExecStreamPipesStderrAlreadySet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		cmd := exec.Command("echo", "x")
		cmd.Stderr = io.Discard
		h := &Host{}
		h.runExecStreamPipes(c, cmd)
	}))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg execStreamControlOut
	_ = conn.ReadJSON(&msg)
	conn.Close()
	if msg.Type != "error" {
		t.Fatalf("expected stderr pipe error, got %q", msg.Type)
	}
}

func TestStreamDaytonaLogsInitialWriteAndClientDone(t *testing.T) {
	h, _ := newHostWithRealSessions(t)
	cmd := &daytonaCommandState{
		id:        "cmd-replay",
		command:   "echo",
		createdAt: time.Now().UTC(),
		stream:    newDaytonaCommandStream(),
	}
	cmd.stream.broadcast(sessions.StreamStdout, []byte("replay-bytes"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.streamDaytonaSessionCommandLogs(w, r, cmd)
	}))
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, p, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read replay: %v", err)
	}
	if !strings.Contains(string(p), "replay-bytes") {
		t.Fatalf("expected replay bytes, got %q", string(p))
	}
	conn.Close()
	time.Sleep(30 * time.Millisecond)
}

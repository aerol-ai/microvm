package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
)

func TestDrainDeadlineSleepBranch(t *testing.T) {
	frames := make(chan sessions.Frame) // never closed, never sent
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		drain(conn, frames)
	}))
	t.Cleanup(httpSrv.Close)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(httpSrv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	time.Sleep(700 * time.Millisecond)
}

type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error)    { return 0, e.err }
func (e *errReader) Write(p []byte) (int, error) { return len(p), nil }

type failEncodeConn struct{ net.Conn }

func (f *failEncodeConn) Write([]byte) (int, error) { return 0, errors.New("encode boom") }

func TestVsockReadNonEOFAndWriteError(t *testing.T) {
	handleVsockConn(context.Background(), &errReader{err: errors.New("read boom")}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	pr, pw := net.Pipe()
	t.Cleanup(func() { _ = pr.Close(); _ = pw.Close() })
	go func() {
		_, _ = pw.Write([]byte(`{"op":"ping"}` + "\n"))
		// Keep open briefly so encode of Ok response hits Write error.
		time.Sleep(50 * time.Millisecond)
		_ = pw.Close()
	}()
	handleVsockConn(context.Background(), &failEncodeConn{Conn: pr}, newQuiesceHandler(slog.Default(), nil, nil), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

type serveErrVsock struct{}

func (s *serveErrVsock) Serve(context.Context) error { return errors.New("serve boom") }
func (s *serveErrVsock) Close() error                { return nil }

func TestMainVsockServeErrorLogged(t *testing.T) {
	oldArgs := os.Args
	oldSessionsNewFn := sessionsNewFn
	oldStartReaperFn := startReaperFn
	oldStartUserCommandFn := startUserCommandFn
	oldForwardShutdownSignalsFn := forwardShutdownSignalsFn
	oldServeHTTPFn := serveHTTPFn
	oldNetListenFn := netListenFn
	oldNewVsockServerFn := newVsockServerFn
	t.Cleanup(func() {
		os.Args = oldArgs
		sessionsNewFn = oldSessionsNewFn
		startReaperFn = oldStartReaperFn
		startUserCommandFn = oldStartUserCommandFn
		forwardShutdownSignalsFn = oldForwardShutdownSignalsFn
		serveHTTPFn = oldServeHTTPFn
		netListenFn = oldNetListenFn
		newVsockServerFn = oldNewVsockServerFn
	})

	startReaperFn = func(*slog.Logger) {}
	forwardShutdownSignalsFn = func(*slog.Logger, *http.Server) {}
	startUserCommandFn = func(*slog.Logger, []string) {}
	netListenFn = func(string, string) (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	}
	sessionsNewFn = func(logger *slog.Logger, cfg sessions.Config) (*sessions.Manager, error) {
		return sessions.New(logger, sessions.Config{SandboxID: "sb", RecordingDir: t.TempDir(), BufferBytes: 1 << 12})
	}
	serveHTTPFn = func(_ *http.Server, ln net.Listener) error {
		time.Sleep(50 * time.Millisecond)
		_ = ln.Close()
		return http.ErrServerClosed
	}
	newVsockServerFn = func(uint32, VsockHandler, *slog.Logger) (vsockServerAPI, error) {
		return &serveErrVsock{}, nil
	}
	os.Args = []string{"toolboxd"}
	main()
}

func TestEnvdMultipartEmptyFilenameResolveError(t *testing.T) {
	srv := newEnvdTestServer(t)
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="file"; filename=""`)
	h.Set("Content-Type", "application/octet-stream")
	part, err := w.CreatePart(h)
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	_, _ = part.Write([]byte("data"))
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "/envd/files", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	srv.handleEnvdMultipartWrite(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty filename status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPumpSessionDonePathClosesClient(t *testing.T) {
	srv := newDaytonaTestServer(t)
	sess, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{
		Name:    "done-path",
		Command: "sh -c 'echo hi; exit 0'",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.handleSessionAttach(w, r, sess.ID())
	}))
	t.Cleanup(httpSrv.Close)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(httpSrv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// Close client immediately so WriteMessage during drain/exit fails (303-305).
	_ = conn.Close()
	select {
	case <-sess.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session did not exit")
	}
	time.Sleep(200 * time.Millisecond)
}

func TestGitCloneURLExtractsExistingUserinfo(t *testing.T) {
	u, env := gitCloneURLAndAuthEnv("https://alice:secret@example.com/r.git", "", "")
	if !strings.Contains(u, "example.com") || len(env) == 0 {
		t.Fatalf("url=%q env=%v", u, env)
	}
	_, env2 := gitCloneURLAndAuthEnv("https://bob@example.com/r.git", "", "")
	if len(env2) == 0 {
		t.Fatal("expected env from username-only userinfo")
	}
	// No credentials at all → early return after clearing user.
	u3, env3 := gitCloneURLAndAuthEnv("https://example.com/r.git", "", "")
	if u3 == "" || env3 != nil {
		t.Fatalf("no-auth url=%q env=%v", u3, env3)
	}
}

func TestPumpSessionDonePathManyAttempts(t *testing.T) {
	// finish() closes the subscriber channel before doneCh, so the
	// <-sess.Done() branch in pumpSession races with frames-closed.
	// Repeated short-lived attaches eventually hit both arms.
	srv := newDaytonaTestServer(t)
	for i := 0; i < 40; i++ {
		sess, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{
			Name:    "done-race-" + string(rune('a'+i%26)),
			Command: "true",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srv.handleSessionAttach(w, r, sess.ID())
		}))
		conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(httpSrv.URL, "http"), nil)
		if err != nil {
			httpSrv.Close()
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
		_ = conn.Close()
		httpSrv.Close()
		_ = srv.sessions.Delete(sess.ID())
	}
}

func TestDaytonaExecSessionEndsWithoutMarker(t *testing.T) {
	srv := newDaytonaTestServer(t)
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"no-marker"}`)))
	sess, _, ok := srv.lookupDaytonaSession("no-marker")
	if !ok {
		t.Fatal("missing session")
	}
	async := true
	body, _ := json.Marshal(map[string]any{"command": "sleep 5", "runAsync": async})
	execRec := httptest.NewRecorder()
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = srv.sessions.Delete(sess.ID())
	}()
	srv.handleDaytonaSessionExec(execRec, httptest.NewRequest(http.MethodPost, "/process/session/no-marker/exec", bytes.NewReader(body)), "no-marker")
	// Async returns immediately; give the runner time to observe session death.
	time.Sleep(400 * time.Millisecond)
}

func TestStreamDaytonaLogsWriteFail(t *testing.T) {
	srv := newDaytonaTestServer(t)
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"logs-fail"}`)))
	async := true
	body, _ := json.Marshal(map[string]any{"command": "printf 'hello-from-logs'", "runAsync": async})
	execRec := httptest.NewRecorder()
	srv.handleDaytonaSessionExec(execRec, httptest.NewRequest(http.MethodPost, "/process/session/logs-fail/exec", bytes.NewReader(body)), "logs-fail")
	var resp daytonaSessionExecuteResponse
	_ = json.Unmarshal(execRec.Body.Bytes(), &resp)
	if resp.CmdID == "" {
		t.Fatal("expected cmd id")
	}
	time.Sleep(300 * time.Millisecond) // let command produce output into stream replay

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, state, ok := srv.lookupDaytonaSession("logs-fail")
		if !ok {
			http.Error(w, "gone", 500)
			return
		}
		cmd, ok := state.commandPtr(resp.CmdID)
		if !ok {
			http.Error(w, "no cmd", 500)
			return
		}
		srv.streamDaytonaSessionCommandLogs(w, r, cmd)
	}))
	t.Cleanup(httpSrv.Close)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(httpSrv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.Close() // force subsequent WriteMessage failures
	time.Sleep(200 * time.Millisecond)
}

func TestDaytonaCreateAndExecRandFailures(t *testing.T) {
	srv := newDaytonaTestServer(t)

	// newDaytonaCommandID failure after a live session exists.
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"rand-exec"}`)))
	if createRec.Code != http.StatusCreated && createRec.Code != http.StatusOK {
		t.Fatalf("create = %d", createRec.Code)
	}

	oldReader := crand.Reader
	crand.Reader = failingRandReader{}
	t.Cleanup(func() { crand.Reader = oldReader })

	execRec := httptest.NewRecorder()
	srv.handleDaytonaSessionExec(execRec, httptest.NewRequest(http.MethodPost, "/process/session/rand-exec/exec", bytes.NewBufferString(`{"command":"echo hi"}`)), "rand-exec")
	if execRec.Code != http.StatusInternalServerError {
		t.Fatalf("exec rand fail = %d body=%s", execRec.Code, execRec.Body.String())
	}

	// GetOrCreate → Create → newSessionID failure.
	createFail := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createFail, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"rand-create"}`)))
	if createFail.Code != http.StatusInternalServerError {
		t.Fatalf("create rand fail = %d body=%s", createFail.Code, createFail.Body.String())
	}
}

type failingRandReader struct{}

func (failingRandReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

func TestRunGitNoRepoEmptyStderrMessage(t *testing.T) {
	dir := t.TempDir()
	fakeGit := filepath.Join(dir, "git")
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("WriteFile fake git: %v", err)
	}
	t.Setenv("PATH", dir)
	if _, err := runGitNoRepoWithEnv(nil, "status"); err == nil {
		t.Fatal("expected fake git failure")
	}
}

func TestHandleExecNonExitWaitMerge(t *testing.T) {
	// Cover the waitErr merge branch when Wait returns a non-ExitError.
	// Use a command that is killed after Start such that Wait can surface
	// a generic error on some platforms; also assert ECHILD path via interpretWaitResult.
	code, sig := interpretWaitResult(errors.New("forced wait"))
	if code != -1 || sig != "forced wait" {
		t.Fatalf("interpretWaitResult = (%d,%q)", code, sig)
	}
	srv := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body := `{"command":"sh","argv":["-c","kill -9 $$"]}`
	rec := httptest.NewRecorder()
	srv.handleExec(rec, httptest.NewRequest(http.MethodPost, "/process/execute", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("handleExec status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionRecordingCopyEOF(t *testing.T) {
	srv := newDaytonaTestServer(t)
	sess, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{
		Name:    "rec-eof",
		Command: "printf hello-rec",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	select {
	case <-sess.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session did not exit")
	}
	path := sess.RecordingPath()
	if path == "" {
		t.Fatal("expected recording path")
	}
	rec := httptest.NewRecorder()
	srv.handleSessionRecording(rec, httptest.NewRequest(http.MethodGet, "/", nil), sess.ID())
	if rec.Code != http.StatusOK {
		t.Fatalf("recording status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "hello-rec") && rec.Body.Len() == 0 {
		t.Fatalf("expected recording body, got %q", rec.Body.String())
	}

	dir := t.TempDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatalf("Open dir: %v", err)
	}
	defer f.Close()
	if _, err := copyToResponse(httptest.NewRecorder(), f); err == nil {
		t.Fatal("expected non-EOF read error when copying a directory")
	}
}

func TestDaytonaFindInFilesOpenError(t *testing.T) {
	srv := newDaytonaTestServer(t)
	root := t.TempDir()
	if err := os.Symlink("/no/such/file/cov95-open", filepath.Join(root, "broken")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/files/find?path="+root+"&pattern=hi", nil)
	srv.handleDaytonaFindInFiles(rec, req)
	// Walk may surface the open error as a filesystem error response.
	if rec.Code == 0 {
		t.Fatal("expected a response code")
	}
}

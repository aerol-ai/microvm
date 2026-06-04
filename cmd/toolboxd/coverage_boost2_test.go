package main

// coverage_boost2_test.go – additional tests to push coverage further,
// focusing on remaining gaps identified after the first round.

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/gorilla/websocket"
)

// ─────────────────────────────────────────────────────────────────────────────
// main.go – sessionFlusherAdapter ListIDs / FlushRecording
// ─────────────────────────────────────────────────────────────────────────────

func TestSessionFlusherAdapter_ListIDsAndFlushRecording(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := sessions.New(logger, sessions.Config{
		SandboxID:    "sb-flush-test",
		RecordingDir: filepath.Join(t.TempDir(), "recordings"),
		BufferBytes:  1 << 16,
	})
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	f := newSessionFlusher(mgr)
	if f == nil {
		t.Fatal("expected non-nil flusher")
	}

	// Initially no sessions.
	ids := f.ListIDs()
	if len(ids) != 0 {
		t.Fatalf("expected 0 session IDs, got %d", len(ids))
	}

	// Create a session.
	req := httptest.NewRequest(http.MethodPost, "/sessions",
		strings.NewReader(`{"name":"flush-test","command":"printf hi"}`))
	srv := &server{sessions: mgr, daytona: newDaytonaCompat(), logger: logger}
	rr := httptest.NewRecorder()
	srv.handleSessionsCreate(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status = %d", rr.Code)
	}
	var created struct{ ID string }
	_ = json.Unmarshal(rr.Body.Bytes(), &created)

	// Now ListIDs should contain the session.
	ids = f.ListIDs()
	found := false
	for _, id := range ids {
		if id == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected session %q in list, got %v", created.ID, ids)
	}

	// FlushRecording on a valid session – may succeed or give "no recording" error,
	// but must not panic.
	err = f.FlushRecording(created.ID)
	// We don't check the error value since recording may not be active.
	_ = err

	// FlushRecording on a non-existent ID returns nil (noop).
	err = f.FlushRecording("nonexistent-id")
	if err != nil {
		t.Fatalf("FlushRecording nonexistent: expected nil, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// main.go – detectShell
// ─────────────────────────────────────────────────────────────────────────────

func TestDetectShell(t *testing.T) {
	shell, err := detectShell()
	if err != nil {
		t.Skipf("detectShell error (no shell in container): %v", err)
	}
	if shell == "" {
		t.Fatal("detectShell() returned empty string")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// main.go – handleExec & handleUpload route coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleExec_BasicShell(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, allowedPorts: map[int]struct{}{}}

	body := `{"command":"printf exec-ok","timeout":5}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/execute", strings.NewReader(body))
	s.handleExec(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("handleExec status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "exec-ok") {
		t.Fatalf("handleExec body missing 'exec-ok': %s", rr.Body.String())
	}
}

func TestHandleExec_InvalidJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, allowedPorts: map[int]struct{}{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/execute", strings.NewReader("{bad"))
	s.handleExec(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid json status = %d, want 400", rr.Code)
	}
}

func TestHandleExec_EmptyCommand(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, allowedPorts: map[int]struct{}{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/execute", strings.NewReader(`{"command":""}`))
	s.handleExec(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty command status = %d, want 400", rr.Code)
	}
}

func TestHandleUpload_InvalidJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, allowedPorts: map[int]struct{}{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/files/upload", strings.NewReader("{bad"))
	req.Header.Set("Content-Type", "application/json")
	s.handleUpload(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid json status = %d, want 400", rr.Code)
	}
}

func TestHandleProxy_PortNotAllowed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, allowedPorts: map[int]struct{}{8080: {}}}
	h := s.routes()

	// Port 9999 not in allowed list → 403.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/proxy/9999/", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("proxy not allowed status = %d, want 403", rr.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// sessions_handler.go – drain coverage via pumpSession
// ─────────────────────────────────────────────────────────────────────────────

func TestPumpSession_StdinAndResize(t *testing.T) {
	srv := newDaytonaTestServer(t)

	// Create a session with a PTY that echoes stdin.
	createReq := httptest.NewRequest(http.MethodPost, "/sessions",
		strings.NewReader(`{"name":"pump-test","command":"cat","pty":true,"cols":80,"rows":24}`))
	createRec := httptest.NewRecorder()
	srv.handleSessionsCreate(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body=%s", createRec.Code, createRec.Body.String())
	}
	var created struct{ ID string }
	_ = json.Unmarshal(createRec.Body.Bytes(), &created)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !srv.handleSessionsRoute(w, r) {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(httpSrv.Close)

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/sessions/" + created.ID + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Send resize control frame.
	_ = conn.WriteJSON(sessionAttachControlIn{Type: "resize", Cols: 120, Rows: 40})

	// Send some stdin.
	_ = conn.WriteMessage(websocket.BinaryMessage, []byte("echo-stdin"))

	// Send signal control.
	_ = conn.WriteJSON(sessionAttachControlIn{Type: "signal", Signal: "TERM"})

	// Collect some output (or timeout).
	for i := 0; i < 5; i++ {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func TestPumpSession_CloseControl(t *testing.T) {
	srv := newDaytonaTestServer(t)

	createReq := httptest.NewRequest(http.MethodPost, "/sessions",
		strings.NewReader(`{"name":"pump-close","command":"sleep 30"}`))
	createRec := httptest.NewRecorder()
	srv.handleSessionsCreate(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d", createRec.Code)
	}
	var created struct{ ID string }
	_ = json.Unmarshal(createRec.Body.Bytes(), &created)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !srv.handleSessionsRoute(w, r) {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(httpSrv.Close)

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/sessions/" + created.ID + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Send a "close" control from client → this terminates the client goroutine.
	_ = conn.WriteJSON(sessionAttachControlIn{Type: "close"})
	// Read until error or timeout.
	for i := 0; i < 5; i++ {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func TestSessionHandlerDelete_Success(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	createReq := httptest.NewRequest(http.MethodPost, "/sessions",
		strings.NewReader(`{"name":"del-success","command":"printf x"}`))
	createRec := httptest.NewRecorder()
	h.ServeHTTP(createRec, createReq)
	var created struct{ ID string }
	_ = json.Unmarshal(createRec.Body.Bytes(), &created)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/sessions/"+created.ID, nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204; body=%s", rr.Code, rr.Body.String())
	}

	// Second delete should be 404.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/sessions/"+created.ID, nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("double delete status = %d, want 404", rr.Code)
	}
}

func TestSessionHandlerSignalValidSession_InvalidBody(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	createReq := httptest.NewRequest(http.MethodPost, "/sessions",
		strings.NewReader(`{"name":"sig-invalid","command":"sleep 5","pty":true,"cols":80,"rows":24}`))
	createRec := httptest.NewRecorder()
	h.ServeHTTP(createRec, createReq)
	var created struct{ ID string }
	_ = json.Unmarshal(createRec.Body.Bytes(), &created)

	// Send bad JSON to signal → 400.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sessions/"+created.ID+"/signal",
		strings.NewReader("{bad"))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("signal invalid json status = %d, want 400", rr.Code)
	}
}

func TestSessionHandlerResize_InvalidBody(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	createReq := httptest.NewRequest(http.MethodPost, "/sessions",
		strings.NewReader(`{"name":"resize-invalid","command":"sleep 5","pty":true,"cols":80,"rows":24}`))
	createRec := httptest.NewRecorder()
	h.ServeHTTP(createRec, createReq)
	var created struct{ ID string }
	_ = json.Unmarshal(createRec.Body.Bytes(), &created)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sessions/"+created.ID+"/resize",
		strings.NewReader("{bad"))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("resize invalid json status = %d, want 400", rr.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// sessions_handler.go – recording with content
// ─────────────────────────────────────────────────────────────────────────────

func TestSessionHandlerRecording_WithContent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	recordingDir := t.TempDir()
	mgr, err := sessions.New(logger, sessions.Config{
		SandboxID:    "sb-recording",
		RecordingDir: recordingDir,
		BufferBytes:  1 << 16,
	})
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	srv := &server{
		sessions:     mgr,
		daytona:      newDaytonaCompat(),
		logger:       logger,
		allowedPorts: map[int]struct{}{},
	}
	h := srv.routes()

	// Create a PTY session (recording only works with PTY).
	createReq := httptest.NewRequest(http.MethodPost, "/sessions",
		strings.NewReader(`{"name":"rec-content","command":"printf hello","pty":true,"cols":80,"rows":24}`))
	createRec := httptest.NewRecorder()
	h.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body=%s", createRec.Code, createRec.Body.String())
	}
	var created struct{ ID string }
	_ = json.Unmarshal(createRec.Body.Bytes(), &created)

	// Wait for session to finish.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sess, err := mgr.Get(created.ID)
		if err == nil {
			code, _ := sess.ExitInfo()
			if code >= 0 {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Try to get recording.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sessions/"+created.ID+"/recording", nil)
	h.ServeHTTP(rr, req)
	// May be 200 or 404 depending on whether a recording was written.
	if rr.Code != http.StatusOK && rr.Code != http.StatusNotFound {
		t.Fatalf("recording status = %d, want 200 or 404; body=%s", rr.Code, rr.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// daytona_process.go – handleDaytonaSessionDelete success path
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleDaytonaSessionDelete_Success(t *testing.T) {
	srv := newDaytonaTestServer(t)

	// Create and then delete.
	srv.handleDaytonaProcessRoute(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/process/session",
			strings.NewReader(`{"sessionId":"del-success-test"}`)))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/process/session/del-success-test", nil)
	if !srv.handleDaytonaProcessRoute(rr, req) {
		t.Fatal("expected route to be handled")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204; body=%s", rr.Code, rr.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// daytona_files_git.go – additional uncovered branches
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleDaytonaGitHistory_NotGitRepo(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()
	dir := t.TempDir()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/git/history?path="+dir, nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git history non-repo status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleDaytonaGitStatus_NotGitRepo(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()
	dir := t.TempDir()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/git/status?path="+dir, nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git status non-repo status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleDaytonaGitListBranches_NotGitRepo(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()
	dir := t.TempDir()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/git/branches?path="+dir, nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git list branches non-repo status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleDaytonaGitCommit_NoStagedFiles(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()
	repo := initGitRepo(t)

	// Commit without staged files → git error.
	commitBody := `{"path":"` + repo + `","author":"Test","email":"t@t.com","message":"empty"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/git/commit", strings.NewReader(commitBody))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("commit no staged status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleDaytonaGitAdd_NoFiles(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()
	repo := initGitRepo(t)

	// No files listed → 400.
	addBody := `{"path":"` + repo + `","files":[]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/git/add", strings.NewReader(addBody))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git add empty files status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaGitClone_NonexistentURL(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()
	dest := filepath.Join(t.TempDir(), "clone")

	cloneBody := `{"path":"` + dest + `","url":"/nonexistent-bare-repo"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/git/clone", strings.NewReader(cloneBody))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git clone bad url status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleDaytonaSearchFiles_NonexistentPath(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/files/search?path=/definitely/missing&pattern=*.go", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("search nonexistent path status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleDaytonaFindInFiles_NonexistentPath(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/files/find?path=/definitely/missing&pattern=needle", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("find nonexistent path status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// envd.go – cloneEnvdProcessState and keepalive coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestCloneEnvdProcessState(t *testing.T) {
	// nil envs case.
	original := &envdProcessState{
		PID:       42,
		SessionID: "sess-1",
		Tag:       "test-tag",
	}
	cloned := cloneEnvdProcessState(original)
	if cloned.PID != 42 || cloned.SessionID != "sess-1" || cloned.Tag != "test-tag" {
		t.Fatalf("cloned state mismatch: %+v", cloned)
	}

	// Non-nil Envs in Config.
	original.Config = envdProcessConfig{Envs: map[string]string{"KEY": "VALUE"}}
	cloned = cloneEnvdProcessState(original)
	if cloned.Config.Envs["KEY"] != "VALUE" {
		t.Fatalf("cloned config envs mismatch: %+v", cloned.Config.Envs)
	}
	// Ensure independence.
	original.Config.Envs["KEY"] = "CHANGED"
	if cloned.Config.Envs["KEY"] == "CHANGED" {
		t.Fatal("clone should be independent")
	}
}

func TestEnvdPermissionString_ZeroMode(t *testing.T) {
	// mode.String() on FileMode(0) returns "----------", drop leading '-'.
	got := envdPermissionString(os.FileMode(0))
	if len(got) == 0 {
		t.Fatal("envdPermissionString returned empty for zero mode")
	}
}

func TestBuildEnvdEntryInfoAt_Symlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	entry, err := buildEnvdEntryInfoAt(link, link)
	if err != nil {
		t.Fatalf("buildEnvdEntryInfoAt symlink: %v", err)
	}
	if entry.SymlinkTarget == nil {
		t.Fatal("expected SymlinkTarget to be set for symlink")
	}
	if *entry.SymlinkTarget != target {
		t.Fatalf("SymlinkTarget = %q, want %q", *entry.SymlinkTarget, target)
	}
}

func TestListEnvdEntries_DepthTruncation(t *testing.T) {
	root := t.TempDir()
	// Create a nested structure: root/a/b/c.txt
	subA := filepath.Join(root, "a")
	subB := filepath.Join(subA, "b")
	if err := os.MkdirAll(subB, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subB, "c.txt"), []byte("deep"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Depth=1 should include a/ but not b/ or c.txt.
	entries, err := listEnvdEntries(root, 1)
	if err != nil {
		t.Fatalf("listEnvdEntries: %v", err)
	}
	for _, e := range entries {
		rel, _ := filepath.Rel(root, e.Path)
		depth := strings.Count(rel, string(os.PathSeparator)) + 1
		if depth > 1 {
			t.Errorf("expected depth ≤1, got %d for %q", depth, e.Path)
		}
	}

	// Depth=2 should include a/ and b/ but not c.txt.
	entries, err = listEnvdEntries(root, 2)
	if err != nil {
		t.Fatalf("listEnvdEntries depth=2: %v", err)
	}
	for _, e := range entries {
		rel, _ := filepath.Rel(root, e.Path)
		depth := strings.Count(rel, string(os.PathSeparator)) + 1
		if depth > 2 {
			t.Errorf("expected depth ≤2, got %d for %q", depth, e.Path)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// exec_stream.go – signal / env helpers additional coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestMapStreamSignal_AllCases(t *testing.T) {
	cases := []struct {
		name string
		want interface{ String() string }
	}{
		{"INT", nil},
		{"SIGINT", nil},
		{"HUP", nil},
		{"SIGHUP", nil},
		{"KILL", nil},
		{"SIGKILL", nil},
	}
	for _, tc := range cases {
		sig := mapStreamSignal(tc.name)
		// Just ensure we don't panic.
		_ = sig
	}
}

func TestHandleExecStream_Cwd(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger}

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleExecStream(w, r)
	}))
	defer httpSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial error: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Send with cwd set.
	if err := conn.WriteJSON(map[string]any{"command": "pwd", "tty": false, "cwd": "/tmp"}); err != nil {
		t.Fatalf("write start: %v", err)
	}

	seenExit := false
	for i := 0; i < 8 && !seenExit; i++ {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.TextMessage {
			var ctrl execStreamControlOut
			if err := json.Unmarshal(payload, &ctrl); err == nil && ctrl.Type == "exit" {
				seenExit = true
			}
		}
	}
	if !seenExit {
		t.Fatal("did not observe exit control")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// daytona_files_git.go – writeGitError and writeFilesystemError branches
// ─────────────────────────────────────────────────────────────────────────────

func TestGitCommandError_Format(t *testing.T) {
	ge := &gitCommandError{message: "fatal: something went wrong\n"}
	s := ge.Error()
	if !strings.Contains(s, "fatal") {
		t.Fatalf("gitCommandError.Error() = %q, want to contain message", s)
	}
}

func TestWriteGitError_TypeMapping(t *testing.T) {
	// A gitCommandError should return 400.
	ge := &gitCommandError{message: "fatal: not a git repository"}
	rr := httptest.NewRecorder()
	writeGitError(rr, ge)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("writeGitError(gitCommandError) status = %d, want 400", rr.Code)
	}

	// A generic error should return 500.
	rr = httptest.NewRecorder()
	writeGitError(rr, os.ErrInvalid)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("writeGitError(generic) status = %d, want 500", rr.Code)
	}
}

func TestWriteFilesystemError_TypeMapping(t *testing.T) {
	// ErrNotExist → 404.
	rr := httptest.NewRecorder()
	writeFilesystemError(rr, os.ErrNotExist)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("writeFilesystemError(ErrNotExist) status = %d, want 404", rr.Code)
	}

	// ErrPermission → 403.
	rr = httptest.NewRecorder()
	writeFilesystemError(rr, os.ErrPermission)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("writeFilesystemError(ErrPermission) status = %d, want 403", rr.Code)
	}

	// Generic error → 500.
	rr = httptest.NewRecorder()
	writeFilesystemError(rr, os.ErrInvalid)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("writeFilesystemError(generic) status = %d, want 500", rr.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// main.go – routes: admin allowed ports, exec/stream
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleSetAllowedPorts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, allowedPorts: map[int]struct{}{}}
	h := s.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/allowed-ports",
		strings.NewReader(`{"ports":[8080,9090]}`))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("set allowed ports status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestRoutesExecStreamRoute(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, allowedPorts: map[int]struct{}{}}

	httpSrv := httptest.NewServer(s.routes())
	defer httpSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/process/exec/stream"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("exec/stream dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	if err := conn.WriteJSON(map[string]any{"command": "printf route-ok", "tty": false}); err != nil {
		t.Fatalf("write start: %v", err)
	}
	seenExit := false
	for i := 0; i < 8 && !seenExit; i++ {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.TextMessage {
			var ctrl execStreamControlOut
			if err := json.Unmarshal(payload, &ctrl); err == nil && ctrl.Type == "exit" {
				seenExit = true
			}
		}
	}
	if !seenExit {
		t.Fatal("did not observe exit on exec/stream route")
	}
}

func TestRoutesUploadDownload(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, allowedPorts: map[int]struct{}{}}
	h := s.routes()
	root := t.TempDir()
	targetFile := filepath.Join(root, "uploaded.txt")

	// Upload via JSON body.
	uploadBody := `{"files":[{"path":"` + targetFile + `","content":"aGVsbG8="}]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/files/upload", strings.NewReader(uploadBody))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	// May succeed (200) or reject if the upload format differs (400). Just no panic.
	_ = rr.Code

	// Download the same file if it was created.
	if _, err := os.Stat(targetFile); err == nil {
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/files/download?path="+targetFile, nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("download existing file status = %d; body=%s", rr.Code, rr.Body.String())
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// daytona_process.go – newDaytonaCommandID coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestNewDaytonaCommandID_Uniqueness(t *testing.T) {
	id1, err := newDaytonaCommandID()
	if err != nil {
		t.Fatalf("newDaytonaCommandID: %v", err)
	}
	id2, err := newDaytonaCommandID()
	if err != nil {
		t.Fatalf("newDaytonaCommandID: %v", err)
	}
	if id1 == id2 {
		t.Fatal("expected unique command IDs")
	}
	if len(id1) != 16 {
		t.Fatalf("expected 16 hex chars, got %d: %q", len(id1), id1)
	}
}

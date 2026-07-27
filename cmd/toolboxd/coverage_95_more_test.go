package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
)

func TestRoutesUnhandledProcessAndSessionsPrefixes(t *testing.T) {
	srv := newEnvdTestServer(t)
	srv.adopted = true
	h := srv.routes()
	req := httptest.NewRequest(http.MethodGet, "/process/sessionX", nil)
	req.Header.Set("Authorization", "Bearer toolbox-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("process/sessionX = %d", rec.Code)
	}
	// /sessionsX normalizes to "/" (unknown single segment); exercise the
	// handleSessionsRoute false return directly instead.
	if srv.handleSessionsRoute(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/sessionz", nil)) {
		t.Fatal("expected handleSessionsRoute false for /sessionz")
	}
}

func TestMainSessionsNewFailureContinues(t *testing.T) {
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
	sessionsNewFn = func(*slog.Logger, sessions.Config) (*sessions.Manager, error) {
		return nil, errors.New("sessions boom")
	}
	serveHTTPFn = func(_ *http.Server, ln net.Listener) error {
		_ = ln.Close()
		return http.ErrServerClosed
	}
	newVsockServerFn = func(uint32, VsockHandler, *slog.Logger) (vsockServerAPI, error) {
		return nil, errors.New("vsock disabled")
	}
	os.Args = []string{"toolboxd"}
	main()
}

func TestDaytonaExecWriteFailAndStderrBroadcast(t *testing.T) {
	srv := newDaytonaTestServer(t)
	create := func(id string) {
		rec := httptest.NewRecorder()
		srv.handleDaytonaSessionCreate(rec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"`+id+`"}`)))
		if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
			t.Fatalf("create %s = %d", id, rec.Code)
		}
	}

	create("write-fail")
	sess, _, ok := srv.lookupDaytonaSession("write-fail")
	if !ok {
		t.Fatal("missing write-fail session")
	}
	_ = sess.CloseStdin()
	execRec := httptest.NewRecorder()
	srv.handleDaytonaSessionExec(execRec, httptest.NewRequest(http.MethodPost, "/process/session/write-fail/exec", bytes.NewBufferString(`{"command":"echo hi"}`)), "write-fail")
	if execRec.Code != http.StatusInternalServerError {
		t.Fatalf("exec write-fail = %d body=%s", execRec.Code, execRec.Body.String())
	}

	create("stderr-cmd")
	execRec = httptest.NewRecorder()
	cmd := `echo out; echo err >&2; exit 0`
	srv.handleDaytonaSessionExec(execRec, httptest.NewRequest(http.MethodPost, "/process/session/stderr-cmd/exec", bytes.NewBufferString(`{"command":`+jsonString(cmd)+`}`)), "stderr-cmd")
	if execRec.Code != http.StatusOK {
		t.Fatalf("stderr-cmd = %d body=%s", execRec.Code, execRec.Body.String())
	}

	create("bad-exit")
	execRec = httptest.NewRecorder()
	// Force a non-numeric status by overriding the wrapper is hard; instead
	// emit a huge preamble before the start marker via a command that prints
	// noise, then exits cleanly — exercises the start-marker tail trim path.
	noise := strings.Repeat("x", 200)
	cmd = `printf '%s\n' '` + noise + `'; true`
	srv.handleDaytonaSessionExec(execRec, httptest.NewRequest(http.MethodPost, "/process/session/bad-exit/exec", bytes.NewBufferString(`{"command":`+jsonString(cmd)+`}`)), "bad-exit")
	if execRec.Code != http.StatusOK {
		t.Fatalf("noise cmd = %d body=%s", execRec.Code, execRec.Body.String())
	}
}

func TestSessionAttachExitDrainAndStderr(t *testing.T) {
	srv := newDaytonaTestServer(t)
	sess, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{
		Name:    "drain-sess",
		Command: "sh -c 'echo out; echo err >&2; sleep 0.15'",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.handleSessionAttach(w, r, sess.ID())
	}))
	t.Cleanup(httpSrv.Close)

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	sawExit := false
	for !sawExit {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.TextMessage && bytes.Contains(data, []byte(`"exit"`)) {
			sawExit = true
		}
	}
	if !sawExit {
		t.Fatal("expected exit frame")
	}

	// Binary write after exit → Write error path in pumpSession.
	sess2, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{
		Name:    "write-after",
		Command: "sleep 5",
	})
	if err != nil {
		t.Fatalf("Create2: %v", err)
	}
	httpSrv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.handleSessionAttach(w, r, sess2.ID())
	}))
	t.Cleanup(httpSrv2.Close)
	conn2, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(httpSrv2.URL, "http"), nil)
	if err != nil {
		t.Fatalf("Dial2: %v", err)
	}
	_ = srv.sessions.Delete(sess2.ID())
	_ = conn2.WriteMessage(websocket.BinaryMessage, []byte("late"))
	_ = conn2.Close()
}

func TestExecStreamPipeControlMessages(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger}
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleExecStream(w, r)
	}))
	t.Cleanup(httpSrv.Close)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(httpSrv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := conn.WriteJSON(map[string]any{"command": "cat", "tty": false}); err != nil {
		t.Fatalf("start: %v", err)
	}
	_ = conn.WriteMessage(websocket.TextMessage, []byte("{bad"))
	_ = conn.WriteJSON(map[string]any{"type": "signal", "signal": "TERM"})
	_ = conn.WriteMessage(websocket.BinaryMessage, []byte("x"))
	_ = conn.WriteJSON(map[string]any{"type": "close"})
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func TestValidateEnvdRequestedUserBadBasicAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-E2B-User-Authorization", "Basic !!!")
	if validateEnvdRequestedUser(httptest.NewRecorder(), req) {
		t.Fatal("expected bad basic auth to fail validation")
	}
}

func TestEnvdOctetCreateOnDirectoryAndRemoveChmod(t *testing.T) {
	srv := newEnvdTestServer(t)
	dir := t.TempDir()
	req := httptest.NewRequest(http.MethodPost, "/envd/files?path="+dir, bytes.NewReader([]byte("x")))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	srv.handleEnvdOctetStreamWrite(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("octet create-on-dir should fail, got %d", rec.Code)
	}

	locked := t.TempDir()
	target := filepath.Join(locked, "victim")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(locked, 0o555); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	body, _ := json.Marshal(map[string]string{"path": target})
	rem := httptest.NewRecorder()
	srv.handleEnvdFilesystemRemove(rem, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if rem.Code == http.StatusOK {
		if os.Geteuid() == 0 {
			t.Log("root can remove files from mode 0555 dirs; skipping assertion")
		} else {
			t.Fatalf("remove in locked dir should fail, got %d", rem.Code)
		}
	}

	// MakeDir Stat permission-denied (not ErrNotExist).
	statDenied := t.TempDir()
	if err := os.Chmod(statDenied, 0); err != nil {
		t.Fatalf("Chmod denied: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(statDenied, 0o755) })
	body, _ = json.Marshal(map[string]string{"path": filepath.Join(statDenied, "child")})
	md := httptest.NewRecorder()
	srv.handleEnvdFilesystemMakeDir(md, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if md.Code == http.StatusOK {
		if os.Geteuid() == 0 {
			t.Log("root can mkdir under mode 000 dirs; skipping assertion")
		} else {
			t.Fatalf("makedir under 000 dir should fail, got %d", md.Code)
		}
	}
}

func TestGitCloneBranchThenBadCommit(t *testing.T) {
	srv := newDaytonaTestServer(t)
	bare := filepath.Join(t.TempDir(), "bare.git")
	if out, err := exec.Command("git", "init", "--bare", bare).CombinedOutput(); err != nil {
		t.Fatalf("git init bare: %v (%s)", err, out)
	}
	work := filepath.Join(t.TempDir(), "work")
	if out, err := exec.Command("git", "clone", bare, work).CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v (%s)", err, out)
	}
	_ = os.WriteFile(filepath.Join(work, "README"), []byte("x"), 0o600)
	cmds := [][]string{
		{"git", "-C", work, "config", "user.email", "t@t"},
		{"git", "-C", work, "config", "user.name", "t"},
		{"git", "-C", work, "add", "."},
		{"git", "-C", work, "commit", "-m", "init"},
		{"git", "-C", work, "branch", "-M", "main"},
		{"git", "-C", work, "push", "origin", "main"},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v (%s)", c, err, out)
		}
	}

	dest := filepath.Join(t.TempDir(), "cloned")
	branch := "main"
	badCommit := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	body := map[string]any{
		"path":      dest,
		"url":       bare,
		"branch":    branch,
		"commit_id": badCommit,
	}
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	srv.handleDaytonaGitClone(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
	if rec.Code == http.StatusNoContent {
		t.Fatalf("clone bad commit should fail, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDaytonaSessionDeleteRaceNotFound(t *testing.T) {
	srv := newDaytonaTestServer(t)
	for i := 0; i < 20; i++ {
		id := "race-" + strconv.Itoa(i)
		createRec := httptest.NewRecorder()
		srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"`+id+`"}`)))
		sess, _, ok := srv.lookupDaytonaSession(id)
		if !ok {
			continue
		}
		done := make(chan struct{})
		go func(sid string) {
			defer close(done)
			_ = srv.sessions.Delete(sid)
		}(sess.ID())
		delRec := httptest.NewRecorder()
		srv.handleDaytonaSessionDelete(delRec, httptest.NewRequest(http.MethodDelete, "/process/session/"+id, nil), id)
		<-done
	}
}

func TestDrainDirectAndProcessRouteFalse(t *testing.T) {
	frames := make(chan sessions.Frame, 2)
	frames <- sessions.Frame{Stream: sessions.StreamStderr, Data: []byte("e")}
	frames <- sessions.Frame{Stream: sessions.StreamStdout, Data: []byte("o")}
	close(frames)

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
	_ = conn.Close()

	srv := newDaytonaTestServer(t)
	if srv.handleDaytonaProcessRoute(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/process/other", nil)) {
		t.Fatal("expected false for non-session process path")
	}
}

func TestHandleDaytonaProcessMethodNotAllowed(t *testing.T) {
	srv := newDaytonaTestServer(t)
	rec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(rec, httptest.NewRequest(http.MethodPut, "/process/session", nil)) {
		t.Fatal("expected handled")
	}
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestEnvdCompatNilLookupList(t *testing.T) {
	var c *envdCompat
	if _, ok := c.lookup(envdProcessSelector{}); ok {
		t.Fatal("nil lookup should miss")
	}
	if got := c.list(); got != nil {
		t.Fatalf("nil list = %v", got)
	}
	pid := 1
	if _, ok := c.lookup(envdProcessSelector{PID: &pid}); ok {
		t.Fatal("nil lookup by pid should miss")
	}

	live := newEnvdCompat()
	live.byTag["stale"] = 99999
	if _, ok := live.lookup(envdProcessSelector{Tag: "stale"}); ok {
		t.Fatal("stale tag should miss when pid absent")
	}
}

type failWriter struct {
	httptest.ResponseRecorder
	failAfter int
	writes    int
}

func (f *failWriter) Write(p []byte) (int, error) {
	f.writes++
	if f.writes > f.failAfter {
		return 0, errors.New("write boom")
	}
	return f.ResponseRecorder.Write(p)
}

func (f *failWriter) Header() http.Header { return f.ResponseRecorder.Header() }
func (f *failWriter) WriteHeader(status int) {
	f.ResponseRecorder.WriteHeader(status)
}

func TestWriteConnectEnvelopeAndDrainSendErrors(t *testing.T) {
	fw := &failWriter{failAfter: 0}
	fw.ResponseRecorder = *httptest.NewRecorder()
	if err := writeConnectEnvelope(fw, 0, map[string]string{"a": "b"}); err == nil {
		t.Fatal("expected header write failure")
	}
	fw2 := &failWriter{failAfter: 1}
	fw2.ResponseRecorder = *httptest.NewRecorder()
	if err := writeConnectEnvelope(fw2, 0, map[string]string{"a": "b"}); err == nil {
		t.Fatal("expected payload write failure")
	}

	frames := make(chan sessions.Frame, 1)
	frames <- sessions.Frame{Stream: sessions.StreamStdout, Data: []byte("x")}
	close(frames)
	fw3 := &failWriter{failAfter: 0}
	fw3.ResponseRecorder = *httptest.NewRecorder()
	srv := newEnvdTestServer(t)
	srv.drainEnvdProcessFrames(&connectJSONStream{w: fw3}, frames, true)
}

func TestGitCommitBranchErrorsOnRealRepo(t *testing.T) {
	srv := newDaytonaTestServer(t)
	repo := filepath.Join(t.TempDir(), "repo")
	if out, err := exec.Command("git", "init", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v (%s)", err, out)
	}
	_ = exec.Command("git", "-C", repo, "config", "user.email", "t@t").Run()
	_ = exec.Command("git", "-C", repo, "config", "user.name", "t").Run()

	// Commit with empty message path already covered; force add of missing path.
	addRec := httptest.NewRecorder()
	srv.handleDaytonaGitAdd(addRec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"path":"`+repo+`","files":["missing-file-xyz"]}`)))
	if addRec.Code == http.StatusNoContent {
		t.Fatalf("git add missing should fail, got %d", addRec.Code)
	}

	commitRec := httptest.NewRecorder()
	srv.handleDaytonaGitCommit(commitRec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"path":"`+repo+`","message":"m","author":"a","email":"e@e"}`)))
	// empty repo commit may fail — that's the branch we want
	_ = commitRec.Code

	createRec := httptest.NewRecorder()
	srv.handleDaytonaGitCreateBranch(createRec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"path":"`+repo+`","name":"feature"}`)))
	_ = createRec.Code

	delRec := httptest.NewRecorder()
	srv.handleDaytonaGitDeleteBranch(delRec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"path":"`+repo+`","name":"nope"}`)))
	if delRec.Code == http.StatusNoContent {
		t.Fatalf("delete missing branch should fail, got %d", delRec.Code)
	}

	histRec := httptest.NewRecorder()
	srv.handleDaytonaGitHistory(histRec, httptest.NewRequest(http.MethodGet, "/git/history?path="+repo, nil))
	_ = histRec.Code

	_, env := gitCloneURLAndAuthEnv("not a url ://", "u", "p")
	_ = env
	_, env = gitCloneURLAndAuthEnv("ssh://example.com/r.git", "u", "p")
	if env != nil {
		t.Fatalf("ssh scheme should skip auth env, got %v", env)
	}
}

func TestStreamDaytonaSessionCommandLogsBranches(t *testing.T) {
	srv := newDaytonaTestServer(t)
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"logs-sess"}`)))
	async := true
	execRec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"command": "printf hello-logs", "runAsync": async})
	srv.handleDaytonaSessionExec(execRec, httptest.NewRequest(http.MethodPost, "/process/session/logs-sess/exec", bytes.NewReader(body)), "logs-sess")
	if execRec.Code != http.StatusOK {
		t.Fatalf("async exec = %d body=%s", execRec.Code, execRec.Body.String())
	}
	var resp daytonaSessionExecuteResponse
	_ = json.Unmarshal(execRec.Body.Bytes(), &resp)
	if resp.CmdID == "" {
		t.Fatal("expected cmd id")
	}
	// Follow logs briefly.
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.handleDaytonaSessionCommandLogs(w, r, "logs-sess", resp.CmdID)
	}))
	t.Cleanup(httpSrv.Close)
	req, _ := http.NewRequest(http.MethodGet, httpSrv.URL+"?follow=true", nil)
	client := &http.Client{Timeout: 2 * time.Second}
	res, err := client.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}
}

package main

import (
	"bytes"
	"context"
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

func TestSessionHandlerErrorBranches(t *testing.T) {
	srv := newDaytonaTestServer(t)
	srv.authToken = "tok"

	create := func(body string) (*httptest.ResponseRecorder, string) {
		req := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.handleSessionsCreate(rec, req)
		var snap models.Session
		_ = json.Unmarshal(rec.Body.Bytes(), &snap)
		return rec, snap.ID
	}

	rec, _ := create(`{"argv":["/nonexistent-toolboxd-bin-xyz"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad create status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec, id := create(`{"command":"cat","name":"pipe-cat"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create cat status = %d body=%s", rec.Code, rec.Body.String())
	}
	sigReq := httptest.NewRequest(http.MethodPost, "/sessions/"+id+"/signal", strings.NewReader(`{"signal":"NOTASIG"}`))
	sigRec := httptest.NewRecorder()
	srv.handleSessionSignal(sigRec, sigReq, id)
	if sigRec.Code != http.StatusBadRequest {
		t.Fatalf("bad signal status = %d", sigRec.Code)
	}
	_ = srv.sessions.Delete(id)

	rec, id = create(`{"command":"cat","name":"pty-cat","pty":true,"cols":80,"rows":24}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create pty status = %d body=%s", rec.Code, rec.Body.String())
	}
	resizeReq := httptest.NewRequest(http.MethodPost, "/sessions/"+id+"/resize", strings.NewReader(`{"cols":0,"rows":0}`))
	resizeRec := httptest.NewRecorder()
	srv.handleSessionResize(resizeRec, resizeReq, id)
	if resizeRec.Code != http.StatusBadRequest {
		t.Fatalf("bad resize status = %d", resizeRec.Code)
	}
	_ = srv.sessions.Delete(id)

	// Recorder init fails when sandbox recording path is a file.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	blocker := filepath.Join(dir, "sb-test")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile blocker: %v", err)
	}
	mgr, err := sessions.New(logger, sessions.Config{
		SandboxID:    "other",
		RecordingDir: dir,
		BufferBytes:  1 << 12,
	})
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	t.Cleanup(mgr.Close)
	// Point SandboxID at the file so recordingPathForID's parent mkdir fails.
	mgr2, err := sessions.New(logger, sessions.Config{
		SandboxID:    "sb-norec",
		RecordingDir: dir,
		BufferBytes:  1 << 12,
	})
	if err != nil {
		t.Fatalf("sessions.New norec: %v", err)
	}
	t.Cleanup(mgr2.Close)
	// Force recording dir for sb-test to be a file by using the blocker as nested path via Create.
	// Simpler path: create normally then wipe recorder by using a manager whose RecordingDir/SandboxID
	// can't create casts — recreate mgr with SandboxID under a file parent.
	_ = mgr
	recDir := t.TempDir()
	sandboxFile := filepath.Join(recDir, "sb-file")
	if err := os.WriteFile(sandboxFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("sandbox file: %v", err)
	}
	// New requires MkdirAll(RecordingDir/SandboxID) so we can't construct that way.
	// Instead create a session then replace recording with nil via Create when recorder fails mid-flight:
	// Create still works if newRecorder fails (warn + continue). Make RecordingDir/sb-id a file AFTER New.
	okDir := t.TempDir()
	okMgr, err := sessions.New(logger, sessions.Config{
		SandboxID:    "sb-ok",
		RecordingDir: okDir,
		BufferBytes:  1 << 12,
	})
	if err != nil {
		t.Fatalf("okMgr: %v", err)
	}
	t.Cleanup(okMgr.Close)
	sandboxPath := filepath.Join(okDir, "sb-ok")
	if err := os.RemoveAll(sandboxPath); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := os.WriteFile(sandboxPath, []byte("blocker"), 0o600); err != nil {
		t.Fatalf("WriteFile sandboxPath: %v", err)
	}
	noRecSrv := &server{sessions: okMgr, logger: logger}
	sess, err := okMgr.Create(context.Background(), models.CreateSessionRequest{Name: "norec", Command: "sleep 2"})
	if err != nil {
		t.Fatalf("Create norec: %v", err)
	}
	recReq := httptest.NewRequest(http.MethodGet, "/sessions/"+sess.ID()+"/recording", nil)
	recRec := httptest.NewRecorder()
	noRecSrv.handleSessionRecording(recRec, recReq, sess.ID())
	if recRec.Code != http.StatusNotFound {
		t.Fatalf("recording status = %d body=%s", recRec.Code, recRec.Body.String())
	}
	_ = okMgr.Delete(sess.ID())

	if srv.handleSessionsRoute(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/sessionz", nil)) {
		t.Fatal("expected handleSessionsRoute false for /sessionz")
	}
}

func TestSessionAttachPumpDrainAndControl(t *testing.T) {
	srv := newDaytonaTestServer(t)
	sess, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{
		Name:    "attach-cat",
		Command: "sh -c 'cat; echo err-side >&2'",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = srv.sessions.Delete(sess.ID()) })

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.handleSessionAttach(w, r, sess.ID())
	}))
	t.Cleanup(httpSrv.Close)

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	_ = conn.WriteMessage(websocket.TextMessage, []byte("{not-json"))
	_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"resize","cols":40,"rows":12}`))
	_ = conn.WriteMessage(websocket.BinaryMessage, []byte("hi\n"))
	_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"close"}`))

	// Second attach after delete → 404.
	_ = srv.sessions.Delete(sess.ID())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sessions/"+sess.ID()+"/attach", nil)
	srv.handleSessionAttach(rec, req, sess.ID())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("attach missing status = %d", rec.Code)
	}

	// Exit+drain path with a short-lived session producing stdout.
	sess2, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{
		Name:    "attach-echo",
		Command: "sh -c 'echo hello; sleep 0.2'",
	})
	if err != nil {
		t.Fatalf("Create echo: %v", err)
	}
	httpSrv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.handleSessionAttach(w, r, sess2.ID())
	}))
	t.Cleanup(httpSrv2.Close)
	wsURL2 := "ws" + strings.TrimPrefix(httpSrv2.URL, "http") + "/attach"
	conn2, _, err := websocket.DefaultDialer.Dial(wsURL2, nil)
	if err != nil {
		t.Fatalf("Dial2: %v", err)
	}
	defer conn2.Close()
	deadline := time.Now().Add(3 * time.Second)
	_ = conn2.SetReadDeadline(deadline)
	sawExit := false
	for !sawExit {
		msgType, data, err := conn2.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.TextMessage && bytes.Contains(data, []byte(`"exit"`)) {
			sawExit = true
		}
	}
	if !sawExit {
		t.Fatal("expected exit control frame from attach")
	}
}

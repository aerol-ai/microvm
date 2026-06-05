package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
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

func TestSessionHandlerSuccessAndAttachBranches(t *testing.T) {
	srv := newDaytonaTestServer(t)

	createReq := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(`{"name":"session-handler","command":"cat","pty":true,"cols":80,"rows":24}`))
	createRec := httptest.NewRecorder()
	srv.handleSessionsCreate(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createRec.Code, createRec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	t.Run("get_log_resize_signal_recording", func(t *testing.T) {
		rr := httptest.NewRecorder()
		srv.handleSessionGet(rr, httptest.NewRequest(http.MethodGet, "/sessions/"+created.ID, nil), created.ID)
		if rr.Code != http.StatusOK {
			t.Fatalf("get status = %d", rr.Code)
		}

		rr = httptest.NewRecorder()
		srv.handleSessionResize(rr, httptest.NewRequest(http.MethodPost, "/sessions/"+created.ID+"/resize", strings.NewReader(`{"cols":100,"rows":40}`)), created.ID)
		if rr.Code != http.StatusOK {
			t.Fatalf("resize status = %d body=%s", rr.Code, rr.Body.String())
		}

		rr = httptest.NewRecorder()
		srv.handleSessionSignal(rr, httptest.NewRequest(http.MethodPost, "/sessions/"+created.ID+"/signal", strings.NewReader(`{"signal":"TERM"}`)), created.ID)
		if rr.Code != http.StatusOK {
			t.Fatalf("signal status = %d body=%s", rr.Code, rr.Body.String())
		}

		time.Sleep(150 * time.Millisecond)

		rr = httptest.NewRecorder()
		srv.handleSessionLog(rr, httptest.NewRequest(http.MethodGet, "/sessions/"+created.ID+"/log", nil), created.ID)
		if rr.Code != http.StatusOK {
			t.Fatalf("log status = %d", rr.Code)
		}

		rr = httptest.NewRecorder()
		srv.handleSessionRecording(rr, httptest.NewRequest(http.MethodGet, "/sessions/"+created.ID+"/recording", nil), created.ID)
		if rr.Code != http.StatusOK {
			t.Fatalf("recording status = %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("attach_upgrade_failure", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/sessions/"+created.ID+"/attach", nil)
		srv.handleSessionAttach(rr, req, created.ID)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("attach non-ws status = %d", rr.Code)
		}
	})

	t.Run("delete_success", func(t *testing.T) {
		rr := httptest.NewRecorder()
		srv.handleSessionDelete(rr, httptest.NewRequest(http.MethodDelete, "/sessions/"+created.ID, nil), created.ID)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("delete status = %d", rr.Code)
		}
	})
}

func TestEnvdHelperBranchesAndProcessListCleanup(t *testing.T) {
	srv := newEnvdTestServer(t)

	stdout := buildEnvdProcessDataEvent(sessions.Frame{Stream: sessions.StreamStdout, Data: []byte("out")}, false)
	if stdout.Stdout == "" || stdout.Stderr != "" || stdout.PTY != "" {
		t.Fatalf("stdout event = %+v", stdout)
	}
	stderr := buildEnvdProcessDataEvent(sessions.Frame{Stream: sessions.StreamStderr, Data: []byte("err")}, false)
	if stderr.Stderr == "" || stderr.Stdout != "" || stderr.PTY != "" {
		t.Fatalf("stderr event = %+v", stderr)
	}
	pty := buildEnvdProcessDataEvent(sessions.Frame{Stream: sessions.StreamStdout, Data: []byte("pty")}, true)
	if pty.PTY == "" || pty.Stdout != "" || pty.Stderr != "" {
		t.Fatalf("pty event = %+v", pty)
	}

	rr := httptest.NewRecorder()
	stream := startConnectJSONStream(rr)
	frames := make(chan sessions.Frame, 2)
	frames <- sessions.Frame{Stream: sessions.StreamStdout, Data: []byte("drain-out")}
	frames <- sessions.Frame{Stream: sessions.StreamStderr, Data: []byte("drain-err")}
	close(frames)
	srv.drainEnvdProcessFrames(stream, frames, false)
	if rr.Body.Len() == 0 {
		t.Fatal("expected drained envelopes")
	}

	// Missing-session cleanup branch.
	srv.envd.byPID[1234] = &envdProcessState{PID: 1234, SessionID: "missing-session", Tag: "missing-proc"}
	srv.envd.byTag["missing-proc"] = 1234

	// Exited-session cleanup branch.
	sess, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{
		Name:    "exited-process-list",
		Command: "printf done",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	state, err := srv.envd.registerSession(sess, "exited-proc", envdProcessConfig{Cmd: "printf", Args: []string{"done"}}, false, false)
	if err != nil {
		t.Fatalf("registerSession: %v", err)
	}
	select {
	case <-sess.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session did not exit")
	}

	rr = httptest.NewRecorder()
	srv.handleEnvdProcessList(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/List", strings.NewReader(`{}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("process list status = %d", rr.Code)
	}
	if _, ok := srv.envd.byTag["missing-proc"]; ok {
		t.Fatal("missing process entry was not cleaned up")
	}
	if _, ok := srv.envd.byPID[state.PID]; ok {
		t.Fatal("exited process entry was not cleaned up")
	}
}

func TestHandleExecAndUploadAdditionalBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &server{logger: logger, allowedPorts: map[int]struct{}{}}

	t.Run("exec_nonzero_and_bad_workdir", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/process/execute", strings.NewReader(`{"command":"echo boom 1>&2; exit 7"}`))
		srv.handleExec(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("exec nonzero status = %d body=%s", rr.Code, rr.Body.String())
		}
		var res models.ExecResult
		if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode exec response: %v", err)
		}
		if res.ExitCode != 7 || !strings.Contains(res.Stderr, "boom") {
			t.Fatalf("unexpected exec response: %+v", res)
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/process/execute", strings.NewReader(`{"command":"echo hi","workdir":"/definitely/missing/workdir"}`))
		srv.handleExec(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("exec bad workdir status = %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("upload_query_path_success", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "query.txt")
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fw, err := mw.CreateFormFile("file", "query.txt")
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		_, _ = fw.Write([]byte("query-path"))
		_ = mw.Close()

		req := httptest.NewRequest(http.MethodPost, "/files/upload?path="+target, &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rr := httptest.NewRecorder()
		srv.handleUpload(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("upload status = %d body=%s", rr.Code, rr.Body.String())
		}
		data, err := os.ReadFile(target)
		if err != nil || string(data) != "query-path" {
			t.Fatalf("uploaded query-path got=%q err=%v", string(data), err)
		}
	})
}

func TestDaytonaSessionStateAndLookupBranches(t *testing.T) {
	state := &daytonaSessionState{}
	state.addCommand(&daytonaCommandState{id: "b", command: "second", createdAt: time.Now().Add(time.Second)})
	state.addCommand(&daytonaCommandState{id: "a", command: "first", createdAt: time.Now()})
	snapshot := state.commandsSnapshot()
	if len(snapshot) != 2 || snapshot[0].id != "a" || snapshot[1].id != "b" {
		t.Fatalf("commandsSnapshot ordering = %+v", snapshot)
	}

	srv := newDaytonaTestServer(t)
	srv.daytona.ensureSession("stale")
	if _, state, ok := srv.lookupDaytonaSession("stale"); ok || state != nil {
		t.Fatal("lookupDaytonaSession should fail for stale daytona-only state")
	}
	if _, ok := srv.daytona.session("stale"); ok {
		t.Fatal("stale daytona session was not cleaned up")
	}
}

func TestSessionAttachRoundTripBinaryFrames(t *testing.T) {
	srv := newDaytonaTestServer(t)
	createReq := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(`{"name":"attach-rt","command":"cat","pty":true,"cols":80,"rows":24}`))
	createRec := httptest.NewRecorder()
	srv.handleSessionsCreate(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d", createRec.Code)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(createRec.Body.Bytes(), &created)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !srv.handleSessionsRoute(w, r) {
			http.NotFound(w, r)
		}
	}))
	defer httpSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/sessions/" + created.ID + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("frame-test\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}

	seenStdout := false
	for i := 0; i < 4; i++ {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.BinaryMessage && len(payload) > 1 && payload[0] == streamFramePrefixStdoutSession && strings.Contains(string(payload[1:]), "frame-test") {
			seenStdout = true
			break
		}
	}
	if !seenStdout {
		t.Fatal("did not observe attach stdout frame")
	}
}

func TestRoutesDispatchSmoke(t *testing.T) {
	srv := newEnvdTestServer(t)
	srv.authToken = "route-token"
	h := srv.routes()

	type reqSpec struct {
		method string
		path   string
		body   string
	}
	reqs := []reqSpec{
		{http.MethodGet, "/envd/health", ""},
		{http.MethodPost, "/process/code-run", "{bad"},
		{http.MethodGet, "/process/session", ""},
		{http.MethodGet, "/files", ""},
		{http.MethodGet, "/files/info", ""},
		{http.MethodPost, "/files/move", ""},
		{http.MethodGet, "/files/search", ""},
		{http.MethodGet, "/files/find", ""},
		{http.MethodGet, "/git/status", ""},
		{http.MethodGet, "/sessions", ""},
	}
	for _, tc := range reqs {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer route-token")
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusNotFound {
			t.Fatalf("%s %s dispatched incorrectly: status=%d body=%s", tc.method, tc.path, rr.Code, rr.Body.String())
		}
	}
}

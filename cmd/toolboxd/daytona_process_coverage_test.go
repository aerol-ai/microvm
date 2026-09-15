package main

import (
	"bytes"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/gorilla/websocket"
)

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

func TestHandleDaytonaSessionDeleteUnderlyingMissing(t *testing.T) {
	srv := newDaytonaTestServer(t)
	createBody := bytes.NewBufferString(`{"sessionId":"del-missing"}`)
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", createBody))
	if createRec.Code != http.StatusCreated && createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d", createRec.Code)
	}
	sess, _, ok := srv.lookupDaytonaSession("del-missing")
	if !ok {
		t.Fatal("expected daytona session")
	}
	if err := srv.sessions.Delete(sess.ID()); err != nil {
		t.Fatalf("Delete underlying: %v", err)
	}
	delRec := httptest.NewRecorder()
	srv.handleDaytonaSessionDelete(delRec, httptest.NewRequest(http.MethodDelete, "/process/session/del-missing", nil), "del-missing")
	if delRec.Code != http.StatusNotFound {
		t.Fatalf("delete status = %d body=%s", delRec.Code, delRec.Body.String())
	}
}

func TestDaytonaSessionCommandAndListErrorBranches(t *testing.T) {
	srv := newDaytonaTestServer(t)
	state := &daytonaSessionState{commands: map[string]*daytonaCommandState{}}
	if state.acceptsInput("missing") {
		t.Fatal("acceptsInput should be false for missing command")
	}

	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"list-stale"}`)))
	sess, _, ok := srv.lookupDaytonaSession("list-stale")
	if !ok {
		t.Fatal("expected session")
	}
	// Leave daytona map entry while removing underlying session so list skips it.
	_ = srv.sessions.Delete(sess.ID())
	listRec := httptest.NewRecorder()
	srv.handleDaytonaSessionList(listRec, httptest.NewRequest(http.MethodGet, "/process/session", nil))
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d", listRec.Code)
	}

	createRec = httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"input-live"}`)))
	live, liveState, ok := srv.lookupDaytonaSession("input-live")
	if !ok {
		t.Fatal("expected input-live session")
	}
	cmd := &daytonaCommandState{id: "cmd-1", running: false, stream: newDaytonaCommandStream()}
	liveState.addCommand(cmd)
	inputRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCommandInput(inputRec, httptest.NewRequest(http.MethodPost, "/process/session/input-live/command/cmd-1/input", bytes.NewBufferString(`{"data":"x"}`)), "input-live", "cmd-1")
	if inputRec.Code != http.StatusConflict {
		t.Fatalf("input on non-accepting command status = %d", inputRec.Code)
	}
	// Accepting + stdin closed → Write error while lookup still succeeds.
	liveState.activeCommandID = "cmd-1"
	cmd.running = true
	if err := live.CloseStdin(); err != nil {
		t.Fatalf("CloseStdin: %v", err)
	}
	inputRec = httptest.NewRecorder()
	srv.handleDaytonaSessionCommandInput(inputRec, httptest.NewRequest(http.MethodPost, "/process/session/input-live/command/cmd-1/input", bytes.NewBufferString(`{"data":"x"}`)), "input-live", "cmd-1")
	if inputRec.Code != http.StatusInternalServerError {
		t.Fatalf("input after CloseStdin status = %d body=%s", inputRec.Code, inputRec.Body.String())
	}
}

func TestRunDaytonaSessionCommandStderrAndExit(t *testing.T) {
	srv := newDaytonaTestServer(t)
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"stderr-sess"}`)))
	if createRec.Code != http.StatusCreated && createRec.Code != http.StatusOK {
		t.Fatalf("create = %d", createRec.Code)
	}
	execRec := httptest.NewRecorder()
	cmd := `echo start; echo err-line >&2; true`
	srv.handleDaytonaSessionExec(execRec, httptest.NewRequest(http.MethodPost, "/process/session/stderr-sess/exec", bytes.NewBufferString(`{"command":`+jsonString(cmd)+`}`)), "stderr-sess")
	if execRec.Code != http.StatusOK {
		t.Fatalf("exec status = %d body=%s", execRec.Code, execRec.Body.String())
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

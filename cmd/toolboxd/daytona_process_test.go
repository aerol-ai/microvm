package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/gorilla/websocket"
)

func newDaytonaTestServer(t *testing.T) *server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := sessions.New(logger, sessions.Config{
		SandboxID:    "sb-test",
		RecordingDir: filepath.Join(t.TempDir(), "recordings"),
		BufferBytes:  1 << 14,
	})
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	t.Cleanup(mgr.Close)
	return &server{sessions: mgr, daytona: newDaytonaCompat(), logger: logger}
}

func TestHandleDaytonaProcessRouteSessionLifecycle(t *testing.T) {
	srv := newDaytonaTestServer(t)

	createBody := bytes.NewBufferString(`{"sessionId":"sdk-session"}`)
	createReq := httptest.NewRequest(http.MethodPost, "/process/session", createBody)
	createRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(createRec, createReq) {
		t.Fatal("expected create route to be handled")
	}
	if createRec.Code != http.StatusCreated && createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d", createRec.Code)
	}

	execBody := bytes.NewBufferString(`{"command":"printf hello-daytona"}`)
	execReq := httptest.NewRequest(http.MethodPost, "/process/session/sdk-session/exec", execBody)
	execRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(execRec, execReq) {
		t.Fatal("expected exec route to be handled")
	}
	if execRec.Code != http.StatusOK {
		t.Fatalf("exec status = %d body=%s", execRec.Code, execRec.Body.String())
	}

	var execResp daytonaSessionExecuteResponse
	if err := json.Unmarshal(execRec.Body.Bytes(), &execResp); err != nil {
		t.Fatalf("decode exec response: %v", err)
	}
	if execResp.CmdID == "" {
		t.Fatal("expected cmdId in exec response")
	}
	if execResp.ExitCode == nil || *execResp.ExitCode != 0 {
		t.Fatalf("exitCode = %+v, want 0", execResp.ExitCode)
	}
	if execResp.Stdout == nil || *execResp.Stdout != "hello-daytona" {
		t.Fatalf("stdout = %+v, want hello-daytona", execResp.Stdout)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/process/session/sdk-session", nil)
	getRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(getRec, getReq) {
		t.Fatal("expected get route to be handled")
	}
	if getRec.Code != http.StatusOK {
		t.Fatalf("get status = %d", getRec.Code)
	}
	var sessionResp daytonaSessionResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &sessionResp); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	if sessionResp.SessionID != "sdk-session" {
		t.Fatalf("sessionId = %q, want sdk-session", sessionResp.SessionID)
	}
	if len(sessionResp.Commands) != 1 || sessionResp.Commands[0].ID != execResp.CmdID {
		t.Fatalf("unexpected commands: %+v", sessionResp.Commands)
	}

	logsReq := httptest.NewRequest(http.MethodGet, "/process/session/sdk-session/command/"+execResp.CmdID+"/logs", nil)
	logsRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(logsRec, logsReq) {
		t.Fatal("expected logs route to be handled")
	}
	if logsRec.Code != http.StatusOK {
		t.Fatalf("logs status = %d", logsRec.Code)
	}
	var logsResp daytonaSessionLogsResponse
	if err := json.Unmarshal(logsRec.Body.Bytes(), &logsResp); err != nil {
		t.Fatalf("decode logs response: %v", err)
	}
	if logsResp.Stdout != "hello-daytona" {
		t.Fatalf("stdout logs = %q, want hello-daytona", logsResp.Stdout)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/process/session/sdk-session", nil)
	deleteRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(deleteRec, deleteReq) {
		t.Fatal("expected delete route to be handled")
	}
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", deleteRec.Code)
	}
}

func TestHandleDaytonaSessionCommandInputDeliversStdin(t *testing.T) {
	srv := newDaytonaTestServer(t)

	createReq := httptest.NewRequest(http.MethodPost, "/process/session",
		bytes.NewBufferString(`{"sessionId":"input-session"}`))
	createRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(createRec, createReq) {
		t.Fatal("expected create route to be handled")
	}

	// Run an async interactive command that blocks on `read` until we send input.
	execBody := `{"command":"read name && printf 'Hello, %s' \"$name\"","runAsync":true}`
	execReq := httptest.NewRequest(http.MethodPost, "/process/session/input-session/exec",
		bytes.NewBufferString(execBody))
	execRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(execRec, execReq) {
		t.Fatal("expected exec route to be handled")
	}
	if execRec.Code != http.StatusOK {
		t.Fatalf("async exec status = %d body=%s", execRec.Code, execRec.Body.String())
	}
	var execResp daytonaSessionExecuteResponse
	if err := json.Unmarshal(execRec.Body.Bytes(), &execResp); err != nil {
		t.Fatalf("decode exec response: %v", err)
	}
	if execResp.CmdID == "" {
		t.Fatal("expected cmdId in async exec response")
	}

	// Wait for the goroutine to mark the command active before sending input.
	if !waitForActiveCommand(t, srv, "input-session", execResp.CmdID, 2*time.Second) {
		t.Fatal("command never reached the active state")
	}

	inputReq := httptest.NewRequest(http.MethodPost,
		"/process/session/input-session/command/"+execResp.CmdID+"/input",
		bytes.NewBufferString(`{"data":"Alice\n"}`))
	inputRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(inputRec, inputReq) {
		t.Fatal("expected input route to be handled")
	}
	if inputRec.Code != http.StatusOK {
		t.Fatalf("input status = %d body=%s", inputRec.Code, inputRec.Body.String())
	}

	// Once the command receives the line, the wrapper script prints the end
	// marker and finishCommand records stdout. Poll until that happens.
	if !waitForCommandStdoutContains(t, srv, "input-session", execResp.CmdID, "Hello, Alice", 3*time.Second) {
		t.Fatal("never saw expected stdout from interactive command")
	}
}

// TestHandleDaytonaSessionCommandInputAutoTerminates pins the auto-newline
// accommodation: bash's `read` blocks until EOL, and the Daytona SDK's
// sendSessionCommandInput helper ships examples that omit the trailing \n.
// The server appends one when missing so the "send a line of input" intent
// works without forcing callers to know the bash detail.
func TestHandleDaytonaSessionCommandInputAutoTerminates(t *testing.T) {
	srv := newDaytonaTestServer(t)

	createReq := httptest.NewRequest(http.MethodPost, "/process/session",
		bytes.NewBufferString(`{"sessionId":"auto-newline-session"}`))
	createRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(createRec, createReq) {
		t.Fatal("expected create route to be handled")
	}

	execBody := `{"command":"read name && printf 'Hello, %s' \"$name\"","runAsync":true}`
	execReq := httptest.NewRequest(http.MethodPost, "/process/session/auto-newline-session/exec",
		bytes.NewBufferString(execBody))
	execRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(execRec, execReq) {
		t.Fatal("expected exec route to be handled")
	}
	var execResp daytonaSessionExecuteResponse
	if err := json.Unmarshal(execRec.Body.Bytes(), &execResp); err != nil {
		t.Fatalf("decode exec response: %v", err)
	}

	if !waitForActiveCommand(t, srv, "auto-newline-session", execResp.CmdID, 2*time.Second) {
		t.Fatal("command never reached the active state")
	}

	// Send the input without a trailing newline, matching what the
	// Daytona SDK does for `sendSessionCommandInput(sid, cid, 'Alice')`.
	inputReq := httptest.NewRequest(http.MethodPost,
		"/process/session/auto-newline-session/command/"+execResp.CmdID+"/input",
		bytes.NewBufferString(`{"data":"Alice"}`))
	inputRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(inputRec, inputReq) {
		t.Fatal("expected input route to be handled")
	}
	if inputRec.Code != http.StatusOK {
		t.Fatalf("input status = %d body=%s", inputRec.Code, inputRec.Body.String())
	}

	// The command should still complete, proving that the server
	// supplied the missing newline for `read`.
	if !waitForCommandStdoutContains(t, srv, "auto-newline-session", execResp.CmdID, "Hello, Alice", 3*time.Second) {
		t.Fatal("command never received the input (no auto-newline?)")
	}
}

func TestHandleDaytonaSessionCommandInputRejectsInactive(t *testing.T) {
	srv := newDaytonaTestServer(t)

	createReq := httptest.NewRequest(http.MethodPost, "/process/session",
		bytes.NewBufferString(`{"sessionId":"input-session-2"}`))
	createRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(createRec, createReq) {
		t.Fatal("expected create route to be handled")
	}

	// Sync exec — the command is finished before the response returns.
	execReq := httptest.NewRequest(http.MethodPost, "/process/session/input-session-2/exec",
		bytes.NewBufferString(`{"command":"printf done"}`))
	execRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(execRec, execReq) {
		t.Fatal("expected exec route to be handled")
	}
	if execRec.Code != http.StatusOK {
		t.Fatalf("sync exec status = %d", execRec.Code)
	}
	var execResp daytonaSessionExecuteResponse
	if err := json.Unmarshal(execRec.Body.Bytes(), &execResp); err != nil {
		t.Fatalf("decode exec response: %v", err)
	}

	inputReq := httptest.NewRequest(http.MethodPost,
		"/process/session/input-session-2/command/"+execResp.CmdID+"/input",
		bytes.NewBufferString(`{"data":"hi\n"}`))
	inputRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(inputRec, inputReq) {
		t.Fatal("expected input route to be handled")
	}
	if inputRec.Code != http.StatusConflict {
		t.Fatalf("input status = %d, want %d, body=%s",
			inputRec.Code, http.StatusConflict, inputRec.Body.String())
	}
}

func TestHandleDaytonaSessionListAndCommandGet(t *testing.T) {
	srv := newDaytonaTestServer(t)

	createReq := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"list-session"}`))
	createRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(createRec, createReq) {
		t.Fatal("expected create route to be handled")
	}
	if createRec.Code != http.StatusCreated && createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d", createRec.Code)
	}

	execReq := httptest.NewRequest(http.MethodPost, "/process/session/list-session/exec", bytes.NewBufferString(`{"command":"printf listed"}`))
	execRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(execRec, execReq) {
		t.Fatal("expected exec route to be handled")
	}
	if execRec.Code != http.StatusOK {
		t.Fatalf("exec status = %d body=%s", execRec.Code, execRec.Body.String())
	}
	var execResp daytonaSessionExecuteResponse
	if err := json.Unmarshal(execRec.Body.Bytes(), &execResp); err != nil {
		t.Fatalf("decode exec response: %v", err)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/process/session", nil)
	listRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(listRec, listReq) {
		t.Fatal("expected list route to be handled")
	}
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", listRec.Code, listRec.Body.String())
	}
	var listed []daytonaSessionResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listed) == 0 {
		t.Fatalf("expected at least one session in list response")
	}

	cmdGetReq := httptest.NewRequest(http.MethodGet, "/process/session/list-session/command/"+execResp.CmdID, nil)
	cmdGetRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(cmdGetRec, cmdGetReq) {
		t.Fatal("expected command get route to be handled")
	}
	if cmdGetRec.Code != http.StatusOK {
		t.Fatalf("command get status = %d body=%s", cmdGetRec.Code, cmdGetRec.Body.String())
	}

	notFoundReq := httptest.NewRequest(http.MethodGet, "/process/session/list-session/command/missing-cmd", nil)
	notFoundRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(notFoundRec, notFoundReq) {
		t.Fatal("expected command get route to be handled")
	}
	if notFoundRec.Code != http.StatusNotFound {
		t.Fatalf("missing command get status = %d, want 404", notFoundRec.Code)
	}
}

func TestHandleDaytonaSessionCreateValidationErrors(t *testing.T) {
	srv := newDaytonaTestServer(t)

	badJSONReq := httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader("{bad"))
	badJSONRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(badJSONRec, badJSONReq) {
		t.Fatal("expected create route to be handled")
	}
	if badJSONRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON status = %d, want 400", badJSONRec.Code)
	}

	emptyReq := httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":""}`))
	emptyRec := httptest.NewRecorder()
	if !srv.handleDaytonaProcessRoute(emptyRec, emptyReq) {
		t.Fatal("expected create route to be handled")
	}
	if emptyRec.Code != http.StatusBadRequest {
		t.Fatalf("empty sessionId status = %d, want 400", emptyRec.Code)
	}
}

func waitForActiveCommand(t *testing.T, srv *server, sessionID, commandID string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, state, ok := srv.lookupDaytonaSession(sessionID); ok && state.acceptsInput(commandID) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func waitForCommandStdoutContains(t *testing.T, srv *server, sessionID, commandID, want string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, state, ok := srv.lookupDaytonaSession(sessionID); ok {
			if cmd, found := state.command(commandID); found && strings.Contains(cmd.stdout, want) {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestLongestEndMarkerPrefixSuffix pins the rolling-match behavior that
// decides how many trailing bytes the streaming runner must withhold
// from /logs?follow=true subscribers. Getting this wrong stalls
// interactive commands (short output, blocked on stdin) because the
// fixed hold-back kept everything inside the buffer.
func TestLongestEndMarkerPrefixSuffix(t *testing.T) {
	pattern := "__SB_DAYTONA_END_abcd__:"
	tests := []struct {
		name     string
		captured string
		want     int
	}{
		{"no overlap — flush all", "Enter your name: \n", 0},
		{"trailing newline — flush all", "Hello, Alice\n", 0},
		{"buffer ends with marker prefix", "some output __SB_", 5},
		{"buffer ends with longer prefix", "x__SB_DAYTONA", 12},
		{"trailing single underscore — partial start", "blah_", 1},
		{"empty buffer", "", 0},
		{"buffer shorter than any prefix", "ab", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := longestEndMarkerPrefixSuffix(tc.captured, pattern)
			if got != tc.want {
				t.Fatalf("longestEndMarkerPrefixSuffix(%q, ...) = %d, want %d",
					tc.captured, got, tc.want)
			}
		})
	}
}

// TestHandleDaytonaSessionCommandLogsFollowStreamsShortOutput pins the
// regression case behind the hold-back fix: a command that prints a
// short prompt and then blocks on stdin must still surface that prompt
// over the WebSocket promptly, well before the command itself finishes.
func TestHandleDaytonaSessionCommandLogsFollowStreamsShortOutput(t *testing.T) {
	srv := newDaytonaTestServer(t)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !srv.handleDaytonaProcessRoute(w, r) {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(httpSrv.Close)

	createResp, err := http.Post(httpSrv.URL+"/process/session", "application/json",
		bytes.NewBufferString(`{"sessionId":"short-output-session"}`))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = createResp.Body.Close()

	// printf then read — read blocks forever (no input sent), so the
	// command never reaches its end marker. The prompt MUST still
	// appear on the WS before we time out the test.
	execBody := `{"command":"printf 'Enter your name: ' ; read name","runAsync":true}`
	execResp, err := http.Post(httpSrv.URL+"/process/session/short-output-session/exec",
		"application/json", bytes.NewBufferString(execBody))
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	defer execResp.Body.Close()
	var execPayload daytonaSessionExecuteResponse
	if err := json.NewDecoder(execResp.Body).Decode(&execPayload); err != nil {
		t.Fatalf("decode exec: %v", err)
	}

	wsURL := strings.Replace(httpSrv.URL, "http://", "ws://", 1) +
		"/process/session/short-output-session/command/" + execPayload.CmdID + "/logs?follow=true"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var collected []byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, payload, err := conn.ReadMessage()
		if err != nil {
			break
		}
		collected = append(collected, payload...)
		demuxed := bytes.ReplaceAll(collected, daytonaStdoutPrefix, nil)
		demuxed = bytes.ReplaceAll(demuxed, daytonaStderrPrefix, nil)
		if bytes.Contains(demuxed, []byte("Enter your name:")) {
			return
		}
	}
	demuxed := bytes.ReplaceAll(collected, daytonaStdoutPrefix, nil)
	demuxed = bytes.ReplaceAll(demuxed, daytonaStderrPrefix, nil)
	t.Fatalf("never saw the prompt on the WS within 2s; got %q", demuxed)
}

// TestHandleDaytonaSessionCommandLogsFollowStreamsWebSocket pins the
// /process/session/{sid}/command/{cid}/logs?follow=true contract: the
// handler must accept a WebSocket upgrade and emit stdout/stderr chunks
// framed with the Daytona-SDK demux markers (0x01x3 / 0x02x3). Without
// this path, @daytona/sdk's getSessionCommandLogs(..., onStdout, onStderr)
// receives HTTP 200 and aborts with `Unexpected server response: 200`.
func TestHandleDaytonaSessionCommandLogsFollowStreamsWebSocket(t *testing.T) {
	srv := newDaytonaTestServer(t)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !srv.handleDaytonaProcessRoute(w, r) {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(httpSrv.Close)

	createReq, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/process/session",
		bytes.NewBufferString(`{"sessionId":"follow-session"}`))
	createResp, err := http.DefaultClient.Do(createReq)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated && createResp.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d", createResp.StatusCode)
	}

	// Long-running async command: print, sleep, print. With async=true the
	// exec endpoint returns immediately, so the WebSocket subscriber joins
	// while output is still being produced.
	execBody := `{"command":"printf first ; sleep 0.2 ; printf second","runAsync":true}`
	execResp, err := http.Post(httpSrv.URL+"/process/session/follow-session/exec",
		"application/json", bytes.NewBufferString(execBody))
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	defer execResp.Body.Close()
	if execResp.StatusCode != http.StatusOK {
		t.Fatalf("exec status = %d", execResp.StatusCode)
	}
	var execPayload daytonaSessionExecuteResponse
	if err := json.NewDecoder(execResp.Body).Decode(&execPayload); err != nil {
		t.Fatalf("decode exec: %v", err)
	}
	if execPayload.CmdID == "" {
		t.Fatal("expected cmdId")
	}

	wsURL := strings.Replace(httpSrv.URL, "http://", "ws://", 1) +
		"/process/session/follow-session/command/" + execPayload.CmdID + "/logs?follow=true"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS dial: %v (resp status %d)", err, resp.StatusCode)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var collected []byte
	for {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			// EOF when the runner closes the subscriber channel after the
			// command finishes — expected.
			break
		}
		if msgType != websocket.BinaryMessage {
			t.Fatalf("frame type = %d, want binary", msgType)
		}
		collected = append(collected, payload...)
		if bytes.Contains(collected, []byte("first")) && bytes.Contains(collected, []byte("second")) {
			break
		}
	}

	// Every byte we received should be inside a stdout-prefixed region —
	// the SDK's stdDemuxStream slices on these markers to assign streams.
	if !bytes.HasPrefix(collected, daytonaStdoutPrefix) {
		t.Fatalf("first bytes = % x, want stdout marker prefix", collected[:min(len(collected), 6)])
	}
	// Strip the marker(s) and compare payload bytes. There may be a
	// single replay frame or multiple live frames concatenated; either
	// way the marker bytes themselves are not part of the user payload.
	payload := bytes.ReplaceAll(collected, daytonaStdoutPrefix, nil)
	payload = bytes.ReplaceAll(payload, daytonaStderrPrefix, nil)
	if !bytes.Contains(payload, []byte("first")) || !bytes.Contains(payload, []byte("second")) {
		t.Fatalf("payload after demux = %q, want both 'first' and 'second'", payload)
	}
}

// TestHandleDaytonaSessionCommandLogsFollowReplaysFinishedCommand covers
// the cold-cache case: by the time the subscriber connects, the command
// has already finished. The handler must still replay the buffered
// stdout/stderr from a single frame and then close cleanly.
func TestHandleDaytonaSessionCommandLogsFollowReplaysFinishedCommand(t *testing.T) {
	srv := newDaytonaTestServer(t)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !srv.handleDaytonaProcessRoute(w, r) {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(httpSrv.Close)

	createResp, err := http.Post(httpSrv.URL+"/process/session", "application/json",
		bytes.NewBufferString(`{"sessionId":"replay-session"}`))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = createResp.Body.Close()

	// Synchronous exec — by the time we get the response, the command has
	// finished and stream.finish() has already been called.
	execResp, err := http.Post(httpSrv.URL+"/process/session/replay-session/exec",
		"application/json", bytes.NewBufferString(`{"command":"printf replay-payload"}`))
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	defer execResp.Body.Close()
	var execPayload daytonaSessionExecuteResponse
	if err := json.NewDecoder(execResp.Body).Decode(&execPayload); err != nil {
		t.Fatalf("decode exec: %v", err)
	}

	wsURL := strings.Replace(httpSrv.URL, "http://", "ws://", 1) +
		"/process/session/replay-session/command/" + execPayload.CmdID + "/logs?follow=true"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var collected []byte
	for {
		_, payload, err := conn.ReadMessage()
		if err != nil {
			break
		}
		collected = append(collected, payload...)
	}
	payload := bytes.ReplaceAll(collected, daytonaStdoutPrefix, nil)
	payload = bytes.ReplaceAll(payload, daytonaStderrPrefix, nil)
	if !bytes.Contains(payload, []byte("replay-payload")) {
		t.Fatalf("replay payload = %q, want to contain 'replay-payload'", payload)
	}
}

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
)

func newDaytonaTestServer(t *testing.T) *server {
	t.Helper()
	mgr, err := sessions.New(slog.New(slog.NewTextHandler(io.Discard, nil)), sessions.Config{
		SandboxID:    "sb-test",
		RecordingDir: filepath.Join(t.TempDir(), "recordings"),
		BufferBytes:  1 << 14,
	})
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	t.Cleanup(mgr.Close)
	return &server{sessions: mgr, daytona: newDaytonaCompat()}
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

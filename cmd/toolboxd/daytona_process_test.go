package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

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

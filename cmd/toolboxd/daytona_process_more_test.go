package main

import (
	crand "crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type failingDaytonaReader struct{}

func (failingDaytonaReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

func TestNewDaytonaCommandIDErrorBranch(t *testing.T) {
	oldReader := crand.Reader
	crand.Reader = failingDaytonaReader{}
	t.Cleanup(func() { crand.Reader = oldReader })

	if _, err := newDaytonaCommandID(); err == nil {
		t.Fatal("expected newDaytonaCommandID to fail when entropy source fails")
	}
}

func TestDaytonaProcessNotFoundAndConflictBranches(t *testing.T) {
	srv := newDaytonaTestServer(t)

	cases := []struct {
		name string
		req  *http.Request
		fn   func(http.ResponseWriter, *http.Request)
		want int
	}{
		{
			name: "delete_missing",
			req:  httptest.NewRequest(http.MethodDelete, "/process/session/missing", nil),
			fn:   func(w http.ResponseWriter, r *http.Request) { srv.handleDaytonaSessionDelete(w, r, "missing") },
			want: http.StatusNotFound,
		},
		{
			name: "exec_missing",
			req:  httptest.NewRequest(http.MethodPost, "/process/session/missing/exec", strings.NewReader(`{"command":"echo hi"}`)),
			fn:   func(w http.ResponseWriter, r *http.Request) { srv.handleDaytonaSessionExec(w, r, "missing") },
			want: http.StatusNotFound,
		},
		{
			name: "command_get_missing",
			req:  httptest.NewRequest(http.MethodGet, "/process/session/missing/command/cmd", nil),
			fn: func(w http.ResponseWriter, r *http.Request) {
				srv.handleDaytonaSessionCommandGet(w, r, "missing", "cmd")
			},
			want: http.StatusNotFound,
		},
		{
			name: "command_logs_missing",
			req:  httptest.NewRequest(http.MethodGet, "/process/session/missing/command/cmd/logs", nil),
			fn: func(w http.ResponseWriter, r *http.Request) {
				srv.handleDaytonaSessionCommandLogs(w, r, "missing", "cmd")
			},
			want: http.StatusNotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			tc.fn(rr, tc.req)
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d", rr.Code, tc.want)
			}
		})
	}

	createReq := httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":"conflict-session"}`))
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, createReq)
	if createRec.Code != http.StatusCreated && createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d body=%s", createRec.Code, createRec.Body.String())
	}
	t.Cleanup(func() { _ = srv.sessions.Delete("conflict-session") })

	state := srv.daytona.ensureSession("conflict-session")
	state.addCommand(&daytonaCommandState{
		id:        "cmd-1",
		command:   "echo",
		createdAt: time.Now().UTC(),
		stream:    newDaytonaCommandStream(),
	})
	inputReq := httptest.NewRequest(http.MethodPost, "/process/session/conflict-session/command/cmd-1/input", strings.NewReader(`{"data":"hello"}`))
	inputRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCommandInput(inputRec, inputReq, "conflict-session", "cmd-1")
	if inputRec.Code != http.StatusConflict {
		t.Fatalf("input conflict status = %d, want 409", inputRec.Code)
	}
}

func TestDaytonaProcessCreateAndExecValidationBranches(t *testing.T) {
	srv := newDaytonaTestServer(t)

	createBadJSON := httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader("{bad"))
	createBadJSONRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createBadJSONRec, createBadJSON)
	if createBadJSONRec.Code != http.StatusBadRequest {
		t.Fatalf("create invalid json status = %d, want 400", createBadJSONRec.Code)
	}

	createEmptyReq := httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":""}`))
	createEmptyRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createEmptyRec, createEmptyReq)
	if createEmptyRec.Code != http.StatusBadRequest {
		t.Fatalf("create empty sessionId status = %d, want 400", createEmptyRec.Code)
	}

	okReq := httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":"validation-session"}`))
	okRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(okRec, okReq)
	if okRec.Code != http.StatusCreated && okRec.Code != http.StatusOK {
		t.Fatalf("create validation session status = %d body=%s", okRec.Code, okRec.Body.String())
	}
	t.Cleanup(func() { _ = srv.sessions.Delete("validation-session") })

	execBadJSON := httptest.NewRequest(http.MethodPost, "/process/session/validation-session/exec", strings.NewReader("{bad"))
	execBadJSONRec := httptest.NewRecorder()
	srv.handleDaytonaSessionExec(execBadJSONRec, execBadJSON, "validation-session")
	if execBadJSONRec.Code != http.StatusBadRequest {
		t.Fatalf("exec invalid json status = %d, want 400", execBadJSONRec.Code)
	}

	execEmptyReq := httptest.NewRequest(http.MethodPost, "/process/session/validation-session/exec", strings.NewReader(`{"command":"   "}`))
	execEmptyRec := httptest.NewRecorder()
	srv.handleDaytonaSessionExec(execEmptyRec, execEmptyReq, "validation-session")
	if execEmptyRec.Code != http.StatusBadRequest {
		t.Fatalf("exec empty command status = %d, want 400", execEmptyRec.Code)
	}
}

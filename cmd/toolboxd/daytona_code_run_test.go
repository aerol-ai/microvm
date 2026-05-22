package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

func TestHandleDaytonaCodeRunShell(t *testing.T) {
	srv := newDaytonaTestServer(t)

	body := bytes.NewBufferString(`{"code":"printf hello-daytona-code-run","language":"sh"}`)
	req := httptest.NewRequest(http.MethodPost, "/process/code-run", body)
	rec := httptest.NewRecorder()
	srv.handleDaytonaCodeRun(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp daytonaCodeRunResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ExitCode != 0 {
		t.Fatalf("exitCode = %d want 0; result=%q", resp.ExitCode, resp.Result)
	}
	if resp.Result != "hello-daytona-code-run" {
		t.Fatalf("result = %q want %q", resp.Result, "hello-daytona-code-run")
	}
}

func TestHandleDaytonaCodeRunPropagatesNonZeroExit(t *testing.T) {
	srv := newDaytonaTestServer(t)

	// `exit 7` returns 7. stdout is empty, so handleDaytonaCodeRun's fallback
	// path picks up stderr (also empty here) — what matters is exitCode is
	// surfaced so the SDK's `codeResult.exitCode !== 0` branch works.
	body := bytes.NewBufferString(`{"code":"exit 7","language":"sh"}`)
	req := httptest.NewRequest(http.MethodPost, "/process/code-run", body)
	rec := httptest.NewRecorder()
	srv.handleDaytonaCodeRun(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp daytonaCodeRunResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ExitCode != 7 {
		t.Fatalf("exitCode = %d want 7", resp.ExitCode)
	}
}

func TestHandleDaytonaCodeRunRejectsUnknownLanguage(t *testing.T) {
	srv := newDaytonaTestServer(t)

	body := bytes.NewBufferString(`{"code":"print(1)","language":"cobol"}`)
	req := httptest.NewRequest(http.MethodPost, "/process/code-run", body)
	rec := httptest.NewRecorder()
	srv.handleDaytonaCodeRun(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not supported") {
		t.Fatalf("body = %s, want 'not supported'", rec.Body.String())
	}
}

func TestHandleDaytonaCodeRunMissingInterpreterReturns400(t *testing.T) {
	// We can only assert the missing-interpreter path when the interpreter
	// genuinely is missing on the test host. Skip when it happens to be
	// installed (CI doesn't ship ts-node by default).
	if _, err := exec.LookPath("ts-node"); err == nil {
		t.Skip("ts-node is on PATH on this host; skipping")
	}
	srv := newDaytonaTestServer(t)

	body := bytes.NewBufferString(`{"code":"console.log('hi')","language":"typescript"}`)
	req := httptest.NewRequest(http.MethodPost, "/process/code-run", body)
	rec := httptest.NewRecorder()
	srv.handleDaytonaCodeRun(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "interpreter not installed") {
		t.Fatalf("body = %s, want 'interpreter not installed'", rec.Body.String())
	}
}

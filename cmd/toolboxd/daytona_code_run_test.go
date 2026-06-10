package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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

func TestHandleDaytonaCodeRunRejectsInvalidPayloads(t *testing.T) {
	srv := newDaytonaTestServer(t)

	badJSON := httptest.NewRequest(http.MethodPost, "/process/code-run", bytes.NewBufferString("{bad"))
	badJSONRec := httptest.NewRecorder()
	srv.handleDaytonaCodeRun(badJSONRec, badJSON)
	if badJSONRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON status = %d, want 400", badJSONRec.Code)
	}

	emptyCode := httptest.NewRequest(http.MethodPost, "/process/code-run",
		bytes.NewBufferString(`{"code":"","language":"sh"}`))
	emptyCodeRec := httptest.NewRecorder()
	srv.handleDaytonaCodeRun(emptyCodeRec, emptyCode)
	if emptyCodeRec.Code != http.StatusBadRequest {
		t.Fatalf("empty code status = %d, want 400", emptyCodeRec.Code)
	}
}

func TestHandleDaytonaCodeRunUsesStderrFallbackAndWriteScriptCleanup(t *testing.T) {
	srv := newDaytonaTestServer(t)

	body := bytes.NewBufferString(`{"code":"printf failed >&2; exit 7","language":"sh"}`)
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
	if resp.ExitCode != 7 || resp.Result != "failed" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	scriptPath, cleanup, err := writeCodeRunScript("printf hi", ".sh")
	if err != nil {
		t.Fatalf("writeCodeRunScript: %v", err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("script path missing: %v", err)
	}
	cleanup()
	if _, err := os.Stat(filepath.Dir(scriptPath)); !os.IsNotExist(err) {
		t.Fatalf("cleanup did not remove temp dir: %v", err)
	}
}

func TestWriteCodeRunScriptErrorBranches(t *testing.T) {
	invalidTmp := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(invalidTmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile invalidTmp: %v", err)
	}
	t.Setenv("TMPDIR", invalidTmp)
	if _, _, err := writeCodeRunScript("printf hi", ".sh"); err == nil {
		t.Fatal("expected MkdirTemp failure when TMPDIR is a file")
	}

	if _, _, err := writeCodeRunScript("printf hi", "/child"); err == nil {
		t.Fatal("expected WriteFile failure for nested suffix path")
	}
}

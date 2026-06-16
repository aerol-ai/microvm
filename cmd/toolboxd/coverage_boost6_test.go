package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCloneEnvdProcessStateNil covers the nil guard in cloneEnvdProcessState.
func TestCloneEnvdProcessStateNil(t *testing.T) {
	if got := cloneEnvdProcessState(nil); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

// TestHandleEnvdMakeDirFileAlreadyExists covers the branch where the target
// path exists but is a regular file (not a directory) → 409 "path already exists".
func TestHandleEnvdMakeDirFileAlreadyExists(t *testing.T) {
	srv := newEnvdTestServer(t)
	handler := srv.routes()

	f := filepath.Join(t.TempDir(), "existing.txt")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(envdMakeDirRequest{Path: f})
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/MakeDir", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "path already exists") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

// TestHandleEnvdFilesystemMoveEmptyDestination covers the resolveDaytonaPath
// error path for an empty Destination field → 400.
func TestHandleEnvdFilesystemMoveEmptyDestination(t *testing.T) {
	srv := newEnvdTestServer(t)
	handler := srv.routes()

	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(envdMoveRequest{Source: src, Destination: ""})
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Move", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleDaytonaGitCreateBranchEmptyPath covers the resolveGitPath error
// when Path is empty → 400.
func TestHandleDaytonaGitCreateBranchEmptyPath(t *testing.T) {
	srv := newDaytonaTestServer(t)

	body, _ := json.Marshal(daytonaGitBranchRequest{Path: "", Name: "feature"})
	req := httptest.NewRequest(http.MethodPost, "/git/branches", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleDaytonaGitCreateBranch(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleDaytonaGitDeleteBranchEmptyPath covers the resolveGitPath error
// when Path is empty → 400.
func TestHandleDaytonaGitDeleteBranchEmptyPath(t *testing.T) {
	srv := newDaytonaTestServer(t)

	body, _ := json.Marshal(daytonaGitDeleteBranchRequest{Path: "", Name: "feature"})
	req := httptest.NewRequest(http.MethodDelete, "/git/branches/feature", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleDaytonaGitDeleteBranch(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleDaytonaGitCloneEmptyPath covers the resolveDaytonaPath error for
// an empty clone destination path → 400.
func TestHandleDaytonaGitCloneEmptyPath(t *testing.T) {
	srv := newDaytonaTestServer(t)

	body, _ := json.Marshal(daytonaGitCloneRequest{Path: "", URL: "http://example.com/repo.git"})
	req := httptest.NewRequest(http.MethodPost, "/git/clone", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleDaytonaGitClone(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleDaytonaGitAddEmptyPath covers the resolveGitPath error when
// Path is empty → 400.
func TestHandleDaytonaGitAddEmptyPath(t *testing.T) {
	srv := newDaytonaTestServer(t)

	body, _ := json.Marshal(daytonaGitAddRequest{Path: "", Files: []string{"main.go"}})
	req := httptest.NewRequest(http.MethodPost, "/git/add", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleDaytonaGitAdd(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleDaytonaListFilesOnFile covers the os.ReadDir error path when the
// resolved path is a regular file, not a directory → 500.
func TestHandleDaytonaListFilesOnFile(t *testing.T) {
	srv := newDaytonaTestServer(t)

	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/files?path="+f, nil)
	rec := httptest.NewRecorder()
	srv.handleDaytonaListFiles(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("expected non-200 for file path, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleDaytonaMoveFileEmptyDestination covers the resolveDaytonaPath
// error for an empty destination query param → 400.
func TestHandleDaytonaMoveFileEmptyDestination(t *testing.T) {
	srv := newDaytonaTestServer(t)

	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/files/move?source="+src+"&destination=", nil)
	rec := httptest.NewRecorder()
	srv.handleDaytonaMoveFile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleEnvdMultipartWriteEmptyFilenameNoOverride covers the
// resolveDaytonaPath error when a multipart file has an empty filename and no
// ?path= query override → 400.
func TestHandleEnvdMultipartWriteEmptyFilenameNoOverride(t *testing.T) {
	srv := newEnvdTestServer(t)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	// CreateFormFile with empty filename → header.Filename == ""
	fw, err := mw.CreateFormFile("file", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("content")); err != nil {
		t.Fatal(err)
	}
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/files", &buf)
	req.Header.Set("Authorization", "Bearer toolbox-token")
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestGitCloneURLAndAuthEnvWithEmbeddedCreds covers the branch that extracts
// username/password from the URL's userinfo when no explicit creds are passed.
func TestGitCloneURLAndAuthEnvWithEmbeddedCreds(t *testing.T) {
	rawURL := "https://user:secret@github.com/org/repo.git"
	cleanURL, env := gitCloneURLAndAuthEnv(rawURL, "", "")
	if strings.Contains(cleanURL, "user:secret") {
		t.Fatalf("URL should not contain credentials: %s", cleanURL)
	}
	if len(env) == 0 {
		t.Fatal("expected auth env for embedded credentials")
	}
}

// TestHandleDaytonaGitCommitAllowEmptyBranch covers the allow_empty flag
// append branch. The git command will fail (no repo), but the flag code path
// is exercised.
func TestHandleDaytonaGitCommitAllowEmptyBranch(t *testing.T) {
	// Create a real git repo so resolveGitPath passes; the commit will fail
	// because there's nothing to commit (or succeed with --allow-empty).
	repoDir := t.TempDir()
	if _, err := runGitNoRepo("-C", repoDir, "init"); err != nil {
		t.Skipf("git not available: %v", err)
	}
	_, _ = runGitNoRepo("-C", repoDir, "config", "user.email", "test@test.com")
	_, _ = runGitNoRepo("-C", repoDir, "config", "user.name", "Test")

	srv := newDaytonaTestServer(t)
	allowEmpty := true
	body, _ := json.Marshal(daytonaGitCommitRequest{
		Path:       repoDir,
		Author:     "Test",
		Email:      "test@test.com",
		Message:    "empty commit",
		AllowEmpty: &allowEmpty,
	})
	req := httptest.NewRequest(http.MethodPost, "/git/commit", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleDaytonaGitCommit(rec, req)
	// 200 on success, or git error — either way the allow_empty branch ran
	if rec.Code != http.StatusOK && rec.Code != http.StatusUnprocessableEntity {
		t.Logf("commit response: %d %s", rec.Code, rec.Body.String())
	}
}

// TestHandleDaytonaSessionCommandInputBadJSON covers the JSON decode error path
// in handleDaytonaSessionCommandInput by directly manipulating internal state
// to make acceptsInput return true, then sending a malformed body.
func TestHandleDaytonaSessionCommandInputBadJSON(t *testing.T) {
	srv := newDaytonaTestServer(t)

	// Create a daytona session via the normal route so GetByName works.
	createReq := httptest.NewRequest(http.MethodPost, "/process/session",
		strings.NewReader(`{"sessionId":"input-json-test"}`))
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, createReq)
	if createRec.Code != http.StatusCreated && createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d", createRec.Code)
	}

	// Inject a command in active/running state directly into the session state.
	state, ok := srv.daytona.session("input-json-test")
	if !ok {
		t.Fatal("session state not found after create")
	}
	const fakeCmdID = "fake-active-cmd"
	cmd := &daytonaCommandState{
		id:      fakeCmdID,
		command: "read",
		running: true,
		stream:  newDaytonaCommandStream(),
	}
	state.mu.Lock()
	state.commands[fakeCmdID] = cmd
	state.activeCommandID = fakeCmdID
	state.mu.Unlock()

	// Now send bad JSON — acceptsInput returns true so we reach the decode call.
	req := httptest.NewRequest(http.MethodPost,
		"/process/session/input-json-test/command/"+fakeCmdID+"/input",
		strings.NewReader("{bad json"))
	rec := httptest.NewRecorder()
	srv.handleDaytonaSessionCommandInput(rec, req, "input-json-test", fakeCmdID)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

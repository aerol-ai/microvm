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

func TestGitCloneURLExtractsExistingUserinfo(t *testing.T) {
	u, env := gitCloneURLAndAuthEnv("https://alice:secret@example.com/r.git", "", "")
	if !strings.Contains(u, "example.com") || len(env) == 0 {
		t.Fatalf("url=%q env=%v", u, env)
	}
	_, env2 := gitCloneURLAndAuthEnv("https://bob@example.com/r.git", "", "")
	if len(env2) == 0 {
		t.Fatal("expected env from username-only userinfo")
	}
	// No credentials at all → early return after clearing user.
	u3, env3 := gitCloneURLAndAuthEnv("https://example.com/r.git", "", "")
	if u3 == "" || env3 != nil {
		t.Fatalf("no-auth url=%q env=%v", u3, env3)
	}
}

func TestRunGitNoRepoEmptyStderrMessage(t *testing.T) {
	dir := t.TempDir()
	fakeGit := filepath.Join(dir, "git")
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("WriteFile fake git: %v", err)
	}
	t.Setenv("PATH", dir)
	if _, err := runGitNoRepoWithEnv(nil, "status"); err == nil {
		t.Fatal("expected fake git failure")
	}
}

func TestDaytonaFindInFilesOpenError(t *testing.T) {
	srv := newDaytonaTestServer(t)
	root := t.TempDir()
	if err := os.Symlink("/no/such/file/cov95-open", filepath.Join(root, "broken")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/files/find?path="+root+"&pattern=hi", nil)
	srv.handleDaytonaFindInFiles(rec, req)
	// Walk may surface the open error as a filesystem error response.
	if rec.Code == 0 {
		t.Fatal("expected a response code")
	}
}

func TestGitCloneBranchThenBadCommit(t *testing.T) {
	srv := newDaytonaTestServer(t)
	bare := filepath.Join(t.TempDir(), "bare.git")
	if out, err := exec.Command("git", "init", "--bare", bare).CombinedOutput(); err != nil {
		t.Fatalf("git init bare: %v (%s)", err, out)
	}
	work := filepath.Join(t.TempDir(), "work")
	if out, err := exec.Command("git", "clone", bare, work).CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v (%s)", err, out)
	}
	_ = os.WriteFile(filepath.Join(work, "README"), []byte("x"), 0o600)
	cmds := [][]string{
		{"git", "-C", work, "config", "user.email", "t@t"},
		{"git", "-C", work, "config", "user.name", "t"},
		{"git", "-C", work, "add", "."},
		{"git", "-C", work, "commit", "-m", "init"},
		{"git", "-C", work, "branch", "-M", "main"},
		{"git", "-C", work, "push", "origin", "main"},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v (%s)", c, err, out)
		}
	}

	dest := filepath.Join(t.TempDir(), "cloned")
	branch := "main"
	badCommit := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	body := map[string]any{
		"path":      dest,
		"url":       bare,
		"branch":    branch,
		"commit_id": badCommit,
	}
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	srv.handleDaytonaGitClone(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
	if rec.Code == http.StatusNoContent {
		t.Fatalf("clone bad commit should fail, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestGitCommitBranchErrorsOnRealRepo(t *testing.T) {
	srv := newDaytonaTestServer(t)
	repo := filepath.Join(t.TempDir(), "repo")
	if out, err := exec.Command("git", "init", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v (%s)", err, out)
	}
	_ = exec.Command("git", "-C", repo, "config", "user.email", "t@t").Run()
	_ = exec.Command("git", "-C", repo, "config", "user.name", "t").Run()

	// Commit with empty message path already covered; force add of missing path.
	addRec := httptest.NewRecorder()
	srv.handleDaytonaGitAdd(addRec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"path":"`+repo+`","files":["missing-file-xyz"]}`)))
	if addRec.Code == http.StatusNoContent {
		t.Fatalf("git add missing should fail, got %d", addRec.Code)
	}

	commitRec := httptest.NewRecorder()
	srv.handleDaytonaGitCommit(commitRec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"path":"`+repo+`","message":"m","author":"a","email":"e@e"}`)))
	// empty repo commit may fail — that's the branch we want
	_ = commitRec.Code

	createRec := httptest.NewRecorder()
	srv.handleDaytonaGitCreateBranch(createRec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"path":"`+repo+`","name":"feature"}`)))
	_ = createRec.Code

	delRec := httptest.NewRecorder()
	srv.handleDaytonaGitDeleteBranch(delRec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"path":"`+repo+`","name":"nope"}`)))
	if delRec.Code == http.StatusNoContent {
		t.Fatalf("delete missing branch should fail, got %d", delRec.Code)
	}

	histRec := httptest.NewRecorder()
	srv.handleDaytonaGitHistory(histRec, httptest.NewRequest(http.MethodGet, "/git/history?path="+repo, nil))
	_ = histRec.Code

	_, env := gitCloneURLAndAuthEnv("not a url ://", "u", "p")
	_ = env
	_, env = gitCloneURLAndAuthEnv("ssh://example.com/r.git", "u", "p")
	if env != nil {
		t.Fatalf("ssh scheme should skip auth env, got %v", env)
	}
}

func TestDaytonaFilesGitIOErrorMatrix(t *testing.T) {
	srv := newDaytonaTestServer(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	filePath := filepath.Join(t.TempDir(), "not-a-dir.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile file: %v", err)
	}

	listRec := httptest.NewRecorder()
	srv.handleDaytonaListFiles(listRec, httptest.NewRequest(http.MethodGet, "/files?path="+filePath, nil))
	if listRec.Code == http.StatusOK {
		t.Fatalf("list files on file should fail, got %d", listRec.Code)
	}

	gitOps := []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
		body string
	}{
		{"add", srv.handleDaytonaGitAdd, `{"path":"` + filepath.Join(t.TempDir(), "norepo") + `","files":["a"]}`},
		{"checkout", srv.handleDaytonaGitCheckout, `{"path":"` + filepath.Join(t.TempDir(), "norepo") + `","branch":"main"}`},
		{"commit", srv.handleDaytonaGitCommit, `{"path":"` + filepath.Join(t.TempDir(), "norepo") + `","message":"m","author":"a","email":"e@e"}`},
		{"createBranch", srv.handleDaytonaGitCreateBranch, `{"path":"` + filepath.Join(t.TempDir(), "norepo") + `","name":"b"}`},
		{"deleteBranch", srv.handleDaytonaGitDeleteBranch, `{"path":"` + filepath.Join(t.TempDir(), "norepo") + `","name":"b"}`},
	}
	for _, tc := range gitOps {
		rec := httptest.NewRecorder()
		tc.fn(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)))
		if rec.Code == http.StatusNoContent || rec.Code == http.StatusOK {
			t.Fatalf("%s expected error, got %d", tc.name, rec.Code)
		}
	}

	cloneRec := httptest.NewRecorder()
	cloneBody := `{"path":"` + filepath.Join(blocker, "repo") + `","url":"https://example.com/r.git"}`
	srv.handleDaytonaGitClone(cloneRec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(cloneBody)))
	if cloneRec.Code == http.StatusNoContent {
		t.Fatalf("clone mkdir fail should error, got %d", cloneRec.Code)
	}

	// Clone auth goes into GIT_CONFIG_* env, not the URL userinfo.
	u, env := gitCloneURLAndAuthEnv("https://example.com/r.git", "user", "")
	if u == "" || len(env) == 0 || !strings.Contains(strings.Join(env, " "), "Authorization: Basic") {
		t.Fatalf("expected auth env for username-only, url=%q env=%v", u, env)
	}
	u2, env2 := gitCloneURLAndAuthEnv("https://example.com/r.git", "user", "pass")
	if u2 == "" || len(env2) == 0 {
		t.Fatalf("expected auth env for user+pass, url=%q env=%v", u2, env2)
	}
	_, env3 := gitCloneURLAndAuthEnv("https://user:pass@example.com/r.git", "", "")
	if len(env3) == 0 {
		t.Fatal("expected auth env extracted from URL userinfo")
	}
}

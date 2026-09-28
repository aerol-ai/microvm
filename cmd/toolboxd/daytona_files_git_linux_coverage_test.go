//go:build linux

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxGitCommitRevParseFailure(t *testing.T) {
	dir := t.TempDir()
	fakeGit := filepath.Join(dir, "git")
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	script := "#!/bin/sh\nif echo \"$*\" | grep -q rev-parse; then echo boom >&2; exit 1; fi\nexec " + realGit + " \"$@\"\n"
	if err := os.WriteFile(fakeGit, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	repo := filepath.Join(t.TempDir(), "repo")
	if out, err := exec.Command(realGit, "init", repo).CombinedOutput(); err != nil {
		t.Fatalf("init: %v (%s)", err, out)
	}
	_ = exec.Command(realGit, "-C", repo, "config", "user.email", "t@t").Run()
	_ = exec.Command(realGit, "-C", repo, "config", "user.name", "t").Run()
	_ = os.WriteFile(filepath.Join(repo, "f"), []byte("x"), 0o600)
	_ = exec.Command(realGit, "-C", repo, "add", "f").Run()

	srv := newDaytonaTestServer(t)
	body := `{"path":"` + repo + `","message":"m","author":"a","email":"e@e"}`
	rec := httptest.NewRecorder()
	srv.handleDaytonaGitCommit(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	if rec.Code == http.StatusOK {
		t.Fatalf("expected rev-parse failure, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestLinuxGitHistoryParseEdges(t *testing.T) {
	dir := t.TempDir()
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	fake := filepath.Join(dir, "git")
	script := "#!/bin/sh\nif echo \"$*\" | grep -q -- '--pretty'; then\n  printf 'badline\\n\\nok\\x00a\\x00b\\x00c\\x00d\\n'\n  exit 0\nfi\nexec " + realGit + " \"$@\"\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	repo := filepath.Join(t.TempDir(), "repo")
	if out, err := exec.Command(realGit, "init", repo).CombinedOutput(); err != nil {
		t.Fatalf("init: %v (%s)", err, out)
	}
	srv := newDaytonaTestServer(t)
	rec := httptest.NewRecorder()
	srv.handleDaytonaGitHistory(rec, httptest.NewRequest(http.MethodGet, "/git/history?path="+repo, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("history status = %d body=%s", rec.Code, rec.Body.String())
	}
}

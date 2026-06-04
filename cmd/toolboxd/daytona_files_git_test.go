package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGitCloneURLAndAuthEnvUsesSanitizedURL(t *testing.T) {
	cloneURL, env := gitCloneURLAndAuthEnv("https://example.com/org/repo.git", "user", "pass")
	if cloneURL != "https://example.com/org/repo.git" {
		t.Fatalf("cloneURL = %q", cloneURL)
	}
	if len(env) != 3 {
		t.Fatalf("env length = %d, want 3", len(env))
	}
	if env[0] != "GIT_CONFIG_COUNT=1" || env[1] != "GIT_CONFIG_KEY_0=http.extraHeader" {
		t.Fatalf("unexpected git config env: %+v", env)
	}
	if env[2] != "GIT_CONFIG_VALUE_0=Authorization: Basic dXNlcjpwYXNz" {
		t.Fatalf("unexpected auth header env: %q", env[2])
	}
}

func TestGitCloneURLAndAuthEnvExtractsEmbeddedCredentials(t *testing.T) {
	cloneURL, env := gitCloneURLAndAuthEnv("https://user:pass@example.com/org/repo.git", "", "")
	if cloneURL != "https://example.com/org/repo.git" {
		t.Fatalf("cloneURL = %q", cloneURL)
	}
	if len(env) != 3 || env[2] != "GIT_CONFIG_VALUE_0=Authorization: Basic dXNlcjpwYXNz" {
		t.Fatalf("unexpected env: %+v", env)
	}
}

func TestGitCloneURLAndAuthEnvLeavesSSHURLAlone(t *testing.T) {
	rawURL := "git@github.com:aerol-ai/microvm.git"
	cloneURL, env := gitCloneURLAndAuthEnv(rawURL, "user", "pass")
	if cloneURL != rawURL {
		t.Fatalf("cloneURL = %q, want %q", cloneURL, rawURL)
	}
	if len(env) != 0 {
		t.Fatalf("env = %+v, want empty", env)
	}
}

func TestResolveDaytonaPath(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}

	t.Run("empty_and_required", func(t *testing.T) {
		if _, err := resolveDaytonaPath("   ", false); err == nil {
			t.Fatal("expected required path error")
		}
	})

	t.Run("empty_defaults_to_workdir", func(t *testing.T) {
		got, err := resolveDaytonaPath("", true)
		if err != nil {
			t.Fatalf("resolveDaytonaPath: %v", err)
		}
		if got != wd {
			t.Fatalf("got %q, want %q", got, wd)
		}
	})

	t.Run("absolute_cleaned", func(t *testing.T) {
		got, err := resolveDaytonaPath(" /tmp/../tmp/a//b ", false)
		if err != nil {
			t.Fatalf("resolveDaytonaPath: %v", err)
		}
		if got != "/tmp/a/b" {
			t.Fatalf("got %q, want /tmp/a/b", got)
		}
	})

	t.Run("relative_joins_workdir", func(t *testing.T) {
		got, err := resolveDaytonaPath("foo/../bar", false)
		if err != nil {
			t.Fatalf("resolveDaytonaPath: %v", err)
		}
		want := filepath.Join(wd, "bar")
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
}

func TestResolveGitPath(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "repo")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := resolveGitPath(file)
	if err != nil {
		t.Fatalf("resolveGitPath: %v", err)
	}
	if got != file {
		t.Fatalf("got %q, want %q", got, file)
	}

	if _, err := resolveGitPath(filepath.Join(root, "missing")); err == nil {
		t.Fatal("expected missing path error")
	}
}

func TestMatchesPattern(t *testing.T) {
	root := "/tmp/repo"
	if !matchesPattern(root, "/tmp/repo/src/main.go", "main.go", "*.go") {
		t.Fatal("expected filename match")
	}
	if !matchesPattern(root, "/tmp/repo/src/main.go", "main.go", "src/*.go") {
		t.Fatal("expected relative path match")
	}
	if matchesPattern(root, "/tmp/repo/src/main.go", "main.go", "*.txt") {
		t.Fatal("did not expect match")
	}
}

func TestClampInt32(t *testing.T) {
	if got := clampInt32(-5); got != 0 {
		t.Fatalf("clampInt32(-5) = %d, want 0", got)
	}
	if got := clampInt32(123); got != 123 {
		t.Fatalf("clampInt32(123) = %d, want 123", got)
	}
	max := int64(^uint32(0) >> 1)
	if got := clampInt32(max + 99); int64(got) != max {
		t.Fatalf("clampInt32(max+99) = %d, want %d", got, max)
	}
}

func TestValueOrEmptyStringAndBoolPtr(t *testing.T) {
	if got := valueOrEmptyString(nil); got != "" {
		t.Fatalf("valueOrEmptyString(nil) = %q, want empty", got)
	}
	v := "abc"
	if got := valueOrEmptyString(&v); got != "abc" {
		t.Fatalf("valueOrEmptyString(&v) = %q, want abc", got)
	}
	b := boolPtr(true)
	if b == nil || !*b {
		t.Fatalf("boolPtr(true) = %v", b)
	}
}

func TestParseGitStatus(t *testing.T) {
	out := strings.Join([]string{
		"## feature...origin/feature [ahead 2, behind 1]",
		"M  staged.go",
		" D removed.go",
		"R  old.go -> new.go",
		"UU conflict.go",
		"?? untracked.txt",
	}, "\n")

	res := parseGitStatus(out)
	if res.CurrentBranch != "feature" {
		t.Fatalf("CurrentBranch = %q, want feature", res.CurrentBranch)
	}
	if res.BranchPublished == nil || !*res.BranchPublished {
		t.Fatalf("BranchPublished = %v, want true", res.BranchPublished)
	}
	if res.Ahead == nil || *res.Ahead != 2 || res.Behind == nil || *res.Behind != 1 {
		t.Fatalf("ahead/behind mismatch: ahead=%v behind=%v", res.Ahead, res.Behind)
	}
	if len(res.FileStatus) != 5 {
		t.Fatalf("len(FileStatus) = %d, want 5", len(res.FileStatus))
	}
	if res.FileStatus[2].Extra != "old.go" || res.FileStatus[2].Name != "new.go" {
		t.Fatalf("rename parse mismatch: %+v", res.FileStatus[2])
	}
	if res.FileStatus[3].Staging != "Updated but unmerged" || res.FileStatus[3].Worktree != "Updated but unmerged" {
		t.Fatalf("conflict parse mismatch: %+v", res.FileStatus[3])
	}
}

func TestParseGitBranchHeader_GoneAndDetached(t *testing.T) {
	res := daytonaGitStatusResponse{}
	parseGitBranchHeader("main...origin/main [gone]", &res)
	if res.BranchPublished == nil || *res.BranchPublished {
		t.Fatalf("BranchPublished = %v, want false", res.BranchPublished)
	}
	if res.CurrentBranch != "main" {
		t.Fatalf("CurrentBranch = %q, want main", res.CurrentBranch)
	}

	res = daytonaGitStatusResponse{}
	parseGitBranchHeader("HEAD", &res)
	if res.BranchPublished == nil || *res.BranchPublished {
		t.Fatalf("detached BranchPublished = %v, want false", res.BranchPublished)
	}
	if res.CurrentBranch != "HEAD" {
		t.Fatalf("detached CurrentBranch = %q, want HEAD", res.CurrentBranch)
	}
}

func TestMapGitStatus(t *testing.T) {
	tests := []struct {
		value byte
		code  string
		want  string
	}{
		{value: ' ', code: " M", want: "Unmodified"},
		{value: '?', code: "??", want: "Untracked"},
		{value: 'M', code: "M ", want: "Modified"},
		{value: 'A', code: "A ", want: "Added"},
		{value: 'D', code: "D ", want: "Deleted"},
		{value: 'R', code: "R ", want: "Renamed"},
		{value: 'C', code: "C ", want: "Copied"},
		{value: 'X', code: "UU", want: "Updated but unmerged"},
		{value: 'X', code: "XZ", want: "Modified"},
	}
	for _, tc := range tests {
		if got := mapGitStatus(tc.value, tc.code); got != tc.want {
			t.Fatalf("mapGitStatus(%q,%q) = %q, want %q", tc.value, tc.code, got, tc.want)
		}
	}
}

func TestBuildDaytonaFileInfo(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	res := buildDaytonaFileInfo(path, info)
	if res.Name != "file.txt" || res.Size != 5 {
		t.Fatalf("unexpected file info: %+v", res)
	}
	if res.Permissions == "" || len(res.Permissions) != 4 {
		t.Fatalf("unexpected permissions: %q", res.Permissions)
	}
	if _, err := time.Parse(time.RFC3339, res.ModTime); err != nil {
		t.Fatalf("ModTime is not RFC3339: %q", res.ModTime)
	}
}

func TestRunGitNoRepoWithEnvAndErrors(t *testing.T) {
	out, err := runGitNoRepoWithEnv([]string{"GIT_CONFIG_COUNT=0"}, "--version")
	if err != nil {
		t.Fatalf("runGitNoRepoWithEnv --version: %v", err)
	}
	if !strings.Contains(out, "git version") {
		t.Fatalf("unexpected output: %q", out)
	}

	if _, err := runGitNoRepo("definitely-not-a-real-git-subcommand"); err == nil {
		t.Fatal("expected git command error")
	} else {
		var ge *gitCommandError
		if !errors.As(err, &ge) {
			t.Fatalf("expected gitCommandError, got %T", err)
		}
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDaytonaFileRoutes(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()
	root := t.TempDir()

	src := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(src, []byte("hello\nneedle\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(src): %v", err)
	}
	dst := filepath.Join(root, "moved.txt")

	t.Run("file_info", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/files/info?path="+src, nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var info daytonaFileInfoResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &info); err != nil {
			t.Fatalf("decode info: %v", err)
		}
		if info.Name != "notes.txt" || info.IsDir {
			t.Fatalf("unexpected info: %+v", info)
		}
	})

	t.Run("list_files", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/files?path="+root, nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var items []daytonaFileInfoResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &items); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		if len(items) != 1 || items[0].Name != "notes.txt" {
			t.Fatalf("unexpected list result: %+v", items)
		}
	})

	t.Run("move_file", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/files/move?source="+src+"&destination="+dst, nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204; body=%s", rr.Code, rr.Body.String())
		}
		if _, err := os.Stat(dst); err != nil {
			t.Fatalf("expected destination file: %v", err)
		}
	})

	t.Run("search_files", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/files/search?path="+root+"&pattern=*.txt", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var resp daytonaSearchFilesResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode search: %v", err)
		}
		if len(resp.Files) != 1 || resp.Files[0] != dst {
			t.Fatalf("unexpected search result: %+v", resp)
		}
	})

	t.Run("find_in_files", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/files/find?path="+root+"&pattern=needle", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var matches []daytonaMatchResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &matches); err != nil {
			t.Fatalf("decode matches: %v", err)
		}
		if len(matches) != 1 || matches[0].File != dst || !strings.Contains(matches[0].Content, "needle") {
			t.Fatalf("unexpected find result: %+v", matches)
		}
	})
}

func TestDaytonaGitRoutes(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	repo := initGitRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "first.txt"), []byte("v1\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(first): %v", err)
	}
	requireGitOK(t, repo, "add", "first.txt")
	requireGitOK(t, repo, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "initial")

	t.Run("git_add_and_commit", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(repo, "new.txt"), []byte("new\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(new): %v", err)
		}

		addBody := `{"path":"` + repo + `","files":["new.txt"]}`
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/git/add", strings.NewReader(addBody))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("add status = %d, want 204; body=%s", rr.Code, rr.Body.String())
		}

		commitBody := `{"path":"` + repo + `","author":"Test User","email":"test@example.com","message":"second"}`
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/git/commit", strings.NewReader(commitBody))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("commit status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var commit daytonaGitCommitResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &commit); err != nil {
			t.Fatalf("decode commit: %v", err)
		}
		if commit.Hash == "" {
			t.Fatal("expected commit hash")
		}
	})

	t.Run("git_status_and_history", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/git/status?path="+repo, nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var st daytonaGitStatusResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
			t.Fatalf("decode status: %v", err)
		}
		if st.CurrentBranch == "" {
			t.Fatalf("unexpected git status: %+v", st)
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/git/history?path="+repo, nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("history status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var commits []daytonaGitCommitInfo
		if err := json.Unmarshal(rr.Body.Bytes(), &commits); err != nil {
			t.Fatalf("decode history: %v", err)
		}
		if len(commits) == 0 {
			t.Fatal("expected non-empty commit history")
		}
	})

	t.Run("git_branch_routes", func(t *testing.T) {
		createBody := `{"path":"` + repo + `","name":"feature/test"}`
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/git/branches", strings.NewReader(createBody))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("create branch status = %d, want 204; body=%s", rr.Code, rr.Body.String())
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/git/branches?path="+repo, nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("list branches status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var branches daytonaListBranchesResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &branches); err != nil {
			t.Fatalf("decode branches: %v", err)
		}
		if !containsString(branches.Branches, "feature/test") {
			t.Fatalf("branches missing feature/test: %+v", branches.Branches)
		}

		checkoutBody := `{"path":"` + repo + `","branch":"feature/test"}`
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/git/checkout", strings.NewReader(checkoutBody))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("checkout status = %d, want 204; body=%s", rr.Code, rr.Body.String())
		}

		requireGitOK(t, repo, "checkout", "-")

		deleteBody := `{"path":"` + repo + `","name":"feature/test"}`
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodDelete, "/git/branches", strings.NewReader(deleteBody))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("delete branch status = %d, want 204; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("git_clone_and_not_implemented", func(t *testing.T) {
		source := initGitRepo(t)
		if err := os.WriteFile(filepath.Join(source, "README.md"), []byte("clone-me\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(source): %v", err)
		}
		requireGitOK(t, source, "add", "README.md")
		requireGitOK(t, source, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "seed")

		destination := filepath.Join(t.TempDir(), "clone")
		cloneReq := map[string]any{"path": destination, "url": source}
		cloneBody, _ := json.Marshal(cloneReq)

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/git/clone", bytes.NewReader(cloneBody))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("clone status = %d, want 204; body=%s", rr.Code, rr.Body.String())
		}
		if _, err := os.Stat(filepath.Join(destination, ".git")); err != nil {
			t.Fatalf("cloned repo missing .git: %v", err)
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/git/pull", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotImplemented {
			t.Fatalf("pull status = %d, want 501; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("git_route_not_found", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/git/unknown", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestDaytonaFileAndGitRouteErrors(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	t.Run("files_info_missing_path", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/files/info", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("files_info_not_found", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/files/info?path=/definitely/missing/file", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("files_search_errors", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/files/search?path=/tmp", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("missing pattern status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/files/search?path=/tmp&pattern=[", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid pattern status = %d, want 400", rr.Code)
		}
	})

	t.Run("files_move_errors", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/files/move?destination=/tmp/x", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("missing source status = %d, want 400", rr.Code)
		}
	})

	repo := initGitRepo(t)
	t.Run("git_body_and_validation_errors", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/git/add", strings.NewReader(`{"path":"`+repo+`"}`))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("git add missing files status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/git/commit", strings.NewReader(`{"path":"`+repo+`"}`))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("git commit missing fields status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/git/status", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("git status missing path status = %d, want 400", rr.Code)
		}
	})

	t.Run("git_error_mapping_from_command_failure", func(t *testing.T) {
		rr := httptest.NewRecorder()
		badCheckout := `{"path":"` + repo + `","branch":"definitely-not-a-branch"}`
		req := httptest.NewRequest(http.MethodPost, "/git/checkout", strings.NewReader(badCheckout))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("git checkout invalid branch status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
	})
}

func initGitRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	if _, err := runGitNoRepo("init", repo); err != nil {
		t.Fatalf("git init: %v", err)
	}
	return repo
}

func requireGitOK(t *testing.T, repo string, args ...string) {
	t.Helper()
	if _, err := runGit(repo, args...); err != nil {
		t.Fatalf("git -C %s %v failed: %v", repo, args, err)
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

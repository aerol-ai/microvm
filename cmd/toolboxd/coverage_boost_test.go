package main

// coverage_boost_test.go – additional tests that cover paths left uncovered
// by the existing test suite. Goal: push the overall toolboxd package
// statement-coverage past 90 %.
//
// Tests are grouped by the source file they primarily cover.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ─────────────────────────────────────────────────────────────────────────────
// main.go helpers
// ─────────────────────────────────────────────────────────────────────────────

func TestIsKnownToolboxPath(t *testing.T) {
	trueCases := []string{
		"/",
		"/health",
		"/version",
		"/process/execute",
		"/process/session",
		"/files",
		"/files/info",
		"/files/upload",
		"/git/status",
		"/proxy/3000",
		"/envd/health",
		"/sessions",
		"/sessions/abc",
	}
	for _, p := range trueCases {
		if !isKnownToolboxPath(p) {
			t.Errorf("isKnownToolboxPath(%q) = false, want true", p)
		}
	}
	falseCases := []string{
		"/unknown",
		"/admin",
		"/metrics",
	}
	for _, p := range falseCases {
		if isKnownToolboxPath(p) {
			t.Errorf("isKnownToolboxPath(%q) = true, want false", p)
		}
	}
}

func TestNormalizeSandboxPath_ExtendedCases(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		sandboxID string
		want      string
	}{
		{"empty_path_becomes_root", "", "", "/"},
		{"envd_prefix_kept", "/envd/health", "sb", "/envd/health"},
		{"envd_prefix_sub_kept", "/envd/process.Process/Start", "sb", "/envd/process.Process/Start"},
		{"sandbox_prefix_slash_only", "/sb/", "sb", "/"},
		// First segment is not a known toolbox path → no strip; path returned as-is.
		{"unknown_first_segment_no_match", "/randomseg/unknown", "", "/randomseg/unknown"},
		// First segment is sandbox, rest is known → strip sandbox prefix.
		{"first_known_path_strip_heuristic", "/sandboxid/health", "", "/health"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeSandboxPath(tc.path, tc.sandboxID)
			if got != tc.want {
				t.Fatalf("normalizeSandboxPath(%q, %q) = %q, want %q", tc.path, tc.sandboxID, got, tc.want)
			}
		})
	}
}

func TestRequireAuth_WithAndWithoutToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// No token configured → always allowed.
	sNoToken := &server{logger: logger, allowedPorts: map[int]struct{}{}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	if !sNoToken.requireAuth(rr, req) {
		t.Fatal("requireAuth with no token should always return true")
	}

	// Token configured, no header → 401.
	sWithToken := &server{logger: logger, authToken: "secret", allowedPorts: map[int]struct{}{}}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	if sWithToken.requireAuth(rr, req) {
		t.Fatal("requireAuth without header should return false")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}

	// Token configured, wrong token → 401.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Authorization", "Bearer wrongtoken")
	if sWithToken.requireAuth(rr, req) {
		t.Fatal("requireAuth with wrong token should return false")
	}

	// Token configured, correct token → allowed.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Authorization", "Bearer secret")
	if !sWithToken.requireAuth(rr, req) {
		t.Fatal("requireAuth with correct token should return true")
	}
}

func TestRoutesRootVersionHealth(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, sandboxID: "testbox", allowedPorts: map[int]struct{}{}}
	h := s.routes()

	for _, tc := range []struct {
		path string
		key  string
	}{
		{"/", "sandbox_id"},
		{"/health", "status"},
		{"/version", "version"},
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", tc.path, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), tc.key) {
			t.Fatalf("GET %s body missing %q: %s", tc.path, tc.key, rr.Body.String())
		}
	}
}

func TestRoutesDefaultNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, sandboxID: "sb-known", allowedPorts: map[int]struct{}{}}
	h := s.routes()

	// /sb-known/definitely/not/a/known/path doesn't strip to a known prefix.
	// The router's default branch returns 404.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sb-known/definitely/not/a/known/path", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestRoutesCodeInterpreterNotImplemented(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, authToken: "", allowedPorts: map[int]struct{}{}}
	h := s.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/interpreter/anything", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rr.Code)
	}
}

func TestNewSessionFlusher_NilManager(t *testing.T) {
	if f := newSessionFlusher(nil); f != nil {
		t.Fatalf("newSessionFlusher(nil) = %v, want nil", f)
	}
}

func TestEnvHelpers_MissingKeys(t *testing.T) {
	if got := envInt("TB_NONEXISTENT_INT_KEY", 99); got != 99 {
		t.Fatalf("envInt missing = %d, want 99", got)
	}
	if got := envInt64("TB_NONEXISTENT_INT64_KEY", 42); got != 42 {
		t.Fatalf("envInt64 missing = %d, want 42", got)
	}
	if got := envString("TB_NONEXISTENT_STRING_KEY", "def"); got != "def" {
		t.Fatalf("envString missing = %q, want def", got)
	}
	if got := envDuration("TB_NONEXISTENT_DUR_KEY", time.Minute); got != time.Minute {
		t.Fatalf("envDuration missing = %s, want 1m", got)
	}
}

func TestHandleDownload_InternalServerError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, allowedPorts: map[int]struct{}{}}
	dir := t.TempDir()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/files/download?path="+dir, nil)
	s.handleDownload(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("expected error status for directory, got 200")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// envd.go helpers
// ─────────────────────────────────────────────────────────────────────────────

func TestCloneEnvdStringMap(t *testing.T) {
	got := cloneEnvdStringMap(nil)
	if len(got) != 0 {
		t.Fatalf("cloneEnvdStringMap(nil) len = %d, want 0", len(got))
	}
	src := map[string]string{"A": "1", "B": "2"}
	clone := cloneEnvdStringMap(src)
	if clone["A"] != "1" || clone["B"] != "2" {
		t.Fatalf("clone content mismatch: %+v", clone)
	}
	src["A"] = "changed"
	if clone["A"] == "changed" {
		t.Fatal("clone should be independent of original")
	}
}

func TestEnvdProcessInputDecode(t *testing.T) {
	// PTY input.
	encoded := base64.StdEncoding.EncodeToString([]byte("pty-data"))
	in := envdProcessInput{PTY: encoded}
	payload, isPTY, err := in.decode()
	if err != nil || !isPTY || string(payload) != "pty-data" {
		t.Fatalf("pty decode: payload=%q isPTY=%v err=%v", payload, isPTY, err)
	}

	// Invalid PTY base64.
	in = envdProcessInput{PTY: "!!!not-base64!!!"}
	_, _, err = in.decode()
	if err == nil || !strings.Contains(err.Error(), "pty") {
		t.Fatalf("expected pty encoding error, got %v", err)
	}

	// Stdin input.
	encodedStdin := base64.StdEncoding.EncodeToString([]byte("stdin-data"))
	in = envdProcessInput{Stdin: encodedStdin}
	payload, isPTY, err = in.decode()
	if err != nil || isPTY || string(payload) != "stdin-data" {
		t.Fatalf("stdin decode: payload=%q isPTY=%v err=%v", payload, isPTY, err)
	}

	// Invalid stdin base64.
	in = envdProcessInput{Stdin: "!!!not-base64!!!"}
	_, _, err = in.decode()
	if err == nil || !strings.Contains(err.Error(), "stdin") {
		t.Fatalf("expected stdin encoding error, got %v", err)
	}

	// Both empty → error.
	in = envdProcessInput{}
	_, _, err = in.decode()
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestMapEnvdSignal(t *testing.T) {
	tests := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{"SIGNAL_SIGTERM", "TERM", false},
		{"15", "TERM", false},
		{"SIGTERM", "TERM", false},
		{"TERM", "TERM", false},
		{"SIGNAL_SIGKILL", "KILL", false},
		{"9", "KILL", false},
		{"SIGKILL", "KILL", false},
		{"KILL", "KILL", false},
		{"SIGNAL_UNSPECIFIED", "TERM", false},
		{"0", "TERM", false},
		{"", "TERM", false},
		{"SIGUSR1", "", true},
		{"bogus", "", true},
	}
	for _, tc := range tests {
		got, err := mapEnvdSignal(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("mapEnvdSignal(%q) = %q, nil err; want error", tc.raw, got)
			}
		} else {
			if err != nil || got != tc.want {
				t.Errorf("mapEnvdSignal(%q) = %q, %v; want %q, nil", tc.raw, got, err, tc.want)
			}
		}
	}
}

func TestIsSupportedEnvdUser(t *testing.T) {
	if !isSupportedEnvdUser("") {
		t.Fatal("isSupportedEnvdUser(\"\") should be true")
	}
	if !isSupportedEnvdUser("   ") {
		t.Fatal("isSupportedEnvdUser(spaces) should be true")
	}
	if os.Geteuid() != 0 {
		if isSupportedEnvdUser("root") {
			t.Fatal("non-root process: isSupportedEnvdUser(root) should be false")
		}
	}
	if isSupportedEnvdUser("some-definitely-nonexistent-user-xyz") {
		t.Fatal("isSupportedEnvdUser(nonexistent) should be false")
	}
}

func TestParseEnvdBasicUsername(t *testing.T) {
	encoded := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	got, err := parseEnvdBasicUsername(encoded)
	if err != nil || got != "alice" {
		t.Fatalf("got %q, %v; want alice, nil", got, err)
	}

	_, err = parseEnvdBasicUsername("Token xyz")
	if err == nil {
		t.Fatal("expected error for non-Basic header")
	}

	_, err = parseEnvdBasicUsername("Basic !!!not-base64!!!")
	if err == nil {
		t.Fatal("expected error for bad base64")
	}

	encoded = "Basic " + base64.StdEncoding.EncodeToString([]byte("nodivider"))
	_, err = parseEnvdBasicUsername(encoded)
	if err == nil {
		t.Fatal("expected error for no colon")
	}
}

func TestRequestedEnvdUsername_ConflictingUsers(t *testing.T) {
	alice := base64.StdEncoding.EncodeToString([]byte("alice:"))
	req := httptest.NewRequest(http.MethodGet, "/envd/files?username=bob", nil)
	req.Header.Set("X-E2B-User-Authorization", "Basic "+alice)
	_, err := requestedEnvdUsername(req)
	if err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("expected conflicting envd users error, got %v", err)
	}
}

func TestRequestedEnvdUsername_HeaderOnly(t *testing.T) {
	alice := base64.StdEncoding.EncodeToString([]byte("alice:"))
	req := httptest.NewRequest(http.MethodGet, "/envd/files", nil)
	req.Header.Set("X-E2B-User-Authorization", "Basic "+alice)
	got, err := requestedEnvdUsername(req)
	if err != nil || got != "alice" {
		t.Fatalf("got %q, %v; want alice, nil", got, err)
	}
}

func TestRequestedEnvdUsername_InvalidHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/envd/files", nil)
	req.Header.Set("X-E2B-User-Authorization", "Basic !!!bad!!!")
	_, err := requestedEnvdUsername(req)
	if err == nil {
		t.Fatal("expected error for bad auth header")
	}
}

func TestEnvdFilesystemMakeDir_ConflictAndErrors(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()
	root := t.TempDir()

	// Create a directory that already exists → 409.
	mkdirBody := `{"path":"` + root + `"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/MakeDir", strings.NewReader(mkdirBody))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("mkdir existing dir status = %d, want 409; body=%s", rr.Code, rr.Body.String())
	}

	// Create a path where a file already exists (not dir) → 409.
	existingFile := filepath.Join(root, "file.txt")
	if err := os.WriteFile(existingFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	mkdirBody = `{"path":"` + existingFile + `"}`
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/MakeDir", strings.NewReader(mkdirBody))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("mkdir existing file status = %d, want 409; body=%s", rr.Code, rr.Body.String())
	}

	// Invalid JSON body → 400.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/MakeDir", strings.NewReader("{bad"))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json mkdir status = %d, want 400", rr.Code)
	}
}

func TestEnvdFilesystemMove_Errors(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	// Invalid JSON body → 400.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Move", strings.NewReader("{bad"))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json move status = %d, want 400", rr.Code)
	}

	// Source doesn't exist → 404.
	moveBody := `{"source":"/definitely/missing","destination":"/tmp/dest"}`
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Move", strings.NewReader(moveBody))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("move missing source status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestEnvdFilesystemListDir_Errors(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	// Invalid JSON.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/ListDir", strings.NewReader("{bad"))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json listdir status = %d, want 400", rr.Code)
	}

	// Missing path.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/ListDir", strings.NewReader(`{"path":""}`))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty path listdir status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestEnvdFilesystemRemove_InvalidJSON(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Remove", strings.NewReader("{bad"))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json remove status = %d, want 400", rr.Code)
	}
}

func TestEnvdFilesystemStat_InvalidJSON(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Stat", strings.NewReader("{bad"))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json stat status = %d, want 400", rr.Code)
	}
}

func TestEnvdRouteWatcherNotImplemented(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	for _, path := range []string{
		envdPrefix + "/filesystem.Filesystem/WatchDir",
		envdPrefix + "/filesystem.Filesystem/CreateWatcher",
		envdPrefix + "/filesystem.Filesystem/GetWatcherEvents",
		envdPrefix + "/filesystem.Filesystem/RemoveWatcher",
		envdPrefix + "/process.Process/StreamInput",
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotImplemented {
			t.Errorf("POST %s status = %d, want 501; body=%s", path, rr.Code, rr.Body.String())
		}
	}
}

func TestEnvdOctetStreamWrite_MissingPath(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/files", strings.NewReader("data"))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	req.Header.Set("Content-Type", "application/octet-stream")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("octet stream missing path status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestEnvdMultipartWrite_MissingFile(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("other", "value"); err != nil {
		t.Fatalf("WriteField: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/files", &body)
	req.Header.Set("Authorization", "Bearer toolbox-token")
	req.Header.Set("Content-Type", mw.FormDataContentType())
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("multipart no file status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestEnvdFileRead_MissingPath(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, envdPrefix+"/files", nil)
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("file read missing path status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestEnvdFileRead_NotFound(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, envdPrefix+"/files?path=/definitely/missing/file", nil)
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("file read not found status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestEnvdProcessUpdate_InvalidJSON(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Update", strings.NewReader("{bad"))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("process update bad json status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestEnvdProcessSendSignal_InvalidJSON(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendSignal", strings.NewReader("{bad"))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("process signal bad json status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestEnvdProcessCloseStdin_InvalidJSON(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/CloseStdin", strings.NewReader("{bad"))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("process close stdin bad json status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestEnvdProcessList_NoSessions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &server{logger: logger, authToken: "", allowedPorts: map[int]struct{}{}, envd: newEnvdCompat()}
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/List", strings.NewReader("{}"))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("list no sessions status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
}

func TestEnvdProcessStart_NoSessions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &server{logger: logger, authToken: "", allowedPorts: map[int]struct{}{}, envd: newEnvdCompat()}
	h := srv.routes()

	payload := []byte(`{"process":{"cmd":"/bin/sh"}}`)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(encodeConnectEnvelopeForTest(payload)))
	req.Header.Set("Content-Type", "application/connect+json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("start no sessions status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
}

func TestEnvdProcessStart_MissingCmd(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	payload := []byte(`{"process":{"cmd":""}}`)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(encodeConnectEnvelopeForTest(payload)))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	req.Header.Set("Content-Type", "application/connect+json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("start missing cmd status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// daytona_process.go – additional route coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleDaytonaProcessRoute_NoSessionsManager(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &server{logger: logger, daytona: newDaytonaCompat()}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":"x"}`))
	if !srv.handleDaytonaProcessRoute(rr, req) {
		t.Fatal("expected route to be handled")
	}
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rr.Code)
	}
}

func TestHandleDaytonaProcessRoute_MethodNotAllowed(t *testing.T) {
	srv := newDaytonaTestServer(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/process/session", nil)
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT /process/session status = %d, want 405", rr.Code)
	}
}

func TestHandleDaytonaProcessRoute_EntrypointNotImplemented(t *testing.T) {
	srv := newDaytonaTestServer(t)

	for _, path := range []string{"/process/session/entrypoint", "/process/session/entrypoint/logs"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if !srv.handleDaytonaProcessRoute(rr, req) {
			t.Fatalf("expected %s to be handled", path)
		}
		if rr.Code != http.StatusNotImplemented {
			t.Fatalf("%s status = %d, want 501; body=%s", path, rr.Code, rr.Body.String())
		}
	}
}

func TestHandleDaytonaProcessRoute_EmptySessionID(t *testing.T) {
	srv := newDaytonaTestServer(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/session/", nil)
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty session id status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaSessionCommandRoute_MethodErrors(t *testing.T) {
	srv := newDaytonaTestServer(t)

	// Create a session and run a sync command.
	srv.handleDaytonaProcessRoute(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":"cmd-route-test"}`)))

	execRec := httptest.NewRecorder()
	srv.handleDaytonaProcessRoute(execRec,
		httptest.NewRequest(http.MethodPost, "/process/session/cmd-route-test/exec",
			strings.NewReader(`{"command":"printf cmdtest"}`)))
	var execResp daytonaSessionExecuteResponse
	_ = json.Unmarshal(execRec.Body.Bytes(), &execResp)

	cmdBase := "/process/session/cmd-route-test/command/" + execResp.CmdID

	// GET command → 200.
	rr := httptest.NewRecorder()
	srv.handleDaytonaProcessRoute(rr, httptest.NewRequest(http.MethodGet, cmdBase, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET command status = %d, want 200", rr.Code)
	}

	// PUT command → 405.
	rr = httptest.NewRecorder()
	srv.handleDaytonaProcessRoute(rr, httptest.NewRequest(http.MethodPut, cmdBase, nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT command status = %d, want 405", rr.Code)
	}

	// PUT command/logs → 405.
	rr = httptest.NewRecorder()
	srv.handleDaytonaProcessRoute(rr, httptest.NewRequest(http.MethodPut, cmdBase+"/logs", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT command/logs status = %d, want 405", rr.Code)
	}

	// GET command/input → 405.
	rr = httptest.NewRecorder()
	srv.handleDaytonaProcessRoute(rr, httptest.NewRequest(http.MethodGet, cmdBase+"/input", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET command/input status = %d, want 405", rr.Code)
	}

	// GET command/unknown → 404.
	rr = httptest.NewRecorder()
	srv.handleDaytonaProcessRoute(rr, httptest.NewRequest(http.MethodGet, cmdBase+"/unknown", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown action status = %d, want 404", rr.Code)
	}

	// Empty command id.
	rr = httptest.NewRecorder()
	srv.handleDaytonaProcessRoute(rr,
		httptest.NewRequest(http.MethodGet, "/process/session/cmd-route-test/command/", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty command id status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaSessionDelete_NotFound(t *testing.T) {
	srv := newDaytonaTestServer(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/process/session/nonexistent", nil)
	if !srv.handleDaytonaProcessRoute(rr, req) {
		t.Fatal("expected route to be handled")
	}
	if rr.Code != http.StatusNotFound {
		t.Fatalf("delete nonexistent status = %d, want 404", rr.Code)
	}
}

func TestHandleDaytonaSessionGet_NotFound(t *testing.T) {
	srv := newDaytonaTestServer(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/session/nonexistent", nil)
	if !srv.handleDaytonaProcessRoute(rr, req) {
		t.Fatal("expected route to be handled")
	}
	if rr.Code != http.StatusNotFound {
		t.Fatalf("get nonexistent status = %d, want 404", rr.Code)
	}
}

func TestHandleDaytonaSessionExec_MethodNotAllowed(t *testing.T) {
	srv := newDaytonaTestServer(t)

	srv.handleDaytonaProcessRoute(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":"ma-test"}`)))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/session/ma-test/exec", nil)
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET exec status = %d, want 405", rr.Code)
	}
}

func TestHandleDaytonaProcessRoute_UnknownAction(t *testing.T) {
	srv := newDaytonaTestServer(t)

	srv.handleDaytonaProcessRoute(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":"unknown-action"}`)))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/session/unknown-action/bogus", nil)
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown action status = %d, want 404", rr.Code)
	}
}

func TestHandleDaytonaSessionExec_InvalidJSON(t *testing.T) {
	srv := newDaytonaTestServer(t)

	srv.handleDaytonaProcessRoute(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":"exec-json-test"}`)))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session/exec-json-test/exec", strings.NewReader("{bad"))
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("exec bad json status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaSessionExec_EmptyCommand(t *testing.T) {
	srv := newDaytonaTestServer(t)

	srv.handleDaytonaProcessRoute(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":"exec-empty-test"}`)))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session/exec-empty-test/exec",
		strings.NewReader(`{"command":""}`))
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("exec empty command status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaSessionCommandInput_NotFound(t *testing.T) {
	srv := newDaytonaTestServer(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session/nosession/command/nocmd/input",
		strings.NewReader(`{"data":"hi"}`))
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("input no session status = %d, want 404", rr.Code)
	}
}

func TestHandleDaytonaSessionCommandInput_CommandNotFound(t *testing.T) {
	srv := newDaytonaTestServer(t)

	srv.handleDaytonaProcessRoute(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":"input-notfound"}`)))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session/input-notfound/command/badid/input",
		strings.NewReader(`{"data":"hi"}`))
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("input bad command status = %d, want 404", rr.Code)
	}
}

func TestHandleDaytonaSessionCommandLogs_CommandNotFound(t *testing.T) {
	srv := newDaytonaTestServer(t)

	srv.handleDaytonaProcessRoute(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":"logs-notfound"}`)))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/session/logs-notfound/command/badid/logs", nil)
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("logs bad command status = %d, want 404", rr.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// sessions_handler.go – WebSocket attach test
// ─────────────────────────────────────────────────────────────────────────────

func TestSessionAttach_ReplayAndExit(t *testing.T) {
	srv := newDaytonaTestServer(t)

	createReq := httptest.NewRequest(http.MethodPost, "/sessions",
		strings.NewReader(`{"name":"attach-test","command":"printf attach-output"}`))
	createRec := httptest.NewRecorder()
	if !srv.handleSessionsRoute(createRec, createReq) {
		t.Fatal("expected create to be handled")
	}
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body=%s", createRec.Code, createRec.Body.String())
	}
	var created struct{ ID string }
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !srv.handleSessionsRoute(w, r) {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(httpSrv.Close)

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/sessions/" + created.ID + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	seenStdout := false
	seenExit := false
	for i := 0; i < 12 && !seenExit; i++ {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			break
		}
		switch msgType {
		case websocket.BinaryMessage:
			if len(payload) > 1 && payload[0] == streamFramePrefixStdoutSession &&
				strings.Contains(string(payload[1:]), "attach-output") {
				seenStdout = true
			}
		case websocket.TextMessage:
			var ctrl sessionAttachControlOut
			if err := json.Unmarshal(payload, &ctrl); err == nil && ctrl.Type == "exit" {
				seenExit = true
			}
		}
	}
	if !seenStdout {
		t.Fatal("did not observe stdout frame on attach WS")
	}
	if !seenExit {
		t.Fatal("did not observe exit control on attach WS")
	}
}

func TestSessionAttach_SessionsDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &server{logger: logger, allowedPorts: map[int]struct{}{}}
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sessions/abc/attach", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("attach disabled sessions status = %d, want 404", rr.Code)
	}
}

func TestSessionsRoute_SessionDeleteNotFound(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/sessions/nonexistent-id", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("delete nonexistent status = %d, want 404", rr.Code)
	}
}

func TestSessionsRoute_MethodNotAllowedOnSessionID(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	createReq := httptest.NewRequest(http.MethodPost, "/sessions",
		strings.NewReader(`{"name":"mna-test","command":"printf x"}`))
	createRec := httptest.NewRecorder()
	h.ServeHTTP(createRec, createReq)
	var created struct{ ID string }
	_ = json.Unmarshal(createRec.Body.Bytes(), &created)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/sessions/"+created.ID, nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT /sessions/{id} status = %d, want 405", rr.Code)
	}
}

func TestSessionsRoute_MethodNotAllowedOnActions(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	createReq := httptest.NewRequest(http.MethodPost, "/sessions",
		strings.NewReader(`{"name":"mna-action","command":"printf x"}`))
	createRec := httptest.NewRecorder()
	h.ServeHTTP(createRec, createReq)
	var created struct{ ID string }
	_ = json.Unmarshal(createRec.Body.Bytes(), &created)

	base := "/sessions/" + created.ID

	actionMethodCombos := []struct {
		method string
		action string
	}{
		{http.MethodGet, "/signal"},
		{http.MethodGet, "/resize"},
		{http.MethodPost, "/log"},
		{http.MethodPost, "/recording"},
		{http.MethodPost, "/attach"},
	}
	for _, tc := range actionMethodCombos {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, base+tc.action, nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s%s status = %d, want 405", tc.method, base, tc.action, rr.Code)
		}
	}
}

func TestSessionsRoute_SessionIDRequired(t *testing.T) {
	srv := newDaytonaTestServer(t)
	// Call handleSessionsRoute directly to test the empty-id branch without
	// going through the prefix-stripping router (which alters /sessions/).
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sessions/", nil)
	if !srv.handleSessionsRoute(rr, req) {
		t.Fatal("expected route to be handled")
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty session id status = %d, want 400", rr.Code)
	}
}

func TestSessionsRoute_SignalMissingSession(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sessions/nope/signal",
		strings.NewReader(`{"signal":"TERM"}`))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("signal missing session status = %d, want 404", rr.Code)
	}
}

func TestSessionsRoute_ResizeMissingSession(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sessions/nope/resize",
		strings.NewReader(`{"cols":80,"rows":24}`))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("resize missing session status = %d, want 404", rr.Code)
	}
}

func TestSessionsRoute_LogMissingSession(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sessions/nope/log", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("log missing session status = %d, want 404", rr.Code)
	}
}

func TestSessionsRoute_RecordingMissingSession(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sessions/nope/recording", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("recording missing session status = %d, want 404", rr.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// daytona_code_run.go
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleDaytonaCodeRun_InvalidJSON(t *testing.T) {
	srv := newDaytonaTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/process/code-run", strings.NewReader("{bad"))
	rr := httptest.NewRecorder()
	srv.handleDaytonaCodeRun(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaCodeRun_EmptyCode(t *testing.T) {
	srv := newDaytonaTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/process/code-run",
		strings.NewReader(`{"code":"","language":"sh"}`))
	rr := httptest.NewRecorder()
	srv.handleDaytonaCodeRun(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaCodeRun_StderrFallback(t *testing.T) {
	srv := newDaytonaTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/process/code-run",
		strings.NewReader(`{"code":"printf stderr-only 1>&2; exit 1","language":"sh"}`))
	rr := httptest.NewRecorder()
	srv.handleDaytonaCodeRun(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp daytonaCodeRunResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ExitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", resp.ExitCode)
	}
	if !strings.Contains(resp.Result, "stderr-only") {
		t.Fatalf("result = %q, want 'stderr-only'", resp.Result)
	}
}

func TestHandleDaytonaCodeRun_WithTimeout(t *testing.T) {
	srv := newDaytonaTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/process/code-run",
		strings.NewReader(`{"code":"printf quick","language":"sh","timeout":1}`))
	rr := httptest.NewRecorder()
	srv.handleDaytonaCodeRun(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp daytonaCodeRunResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Result != "quick" {
		t.Fatalf("result = %q, want quick", resp.Result)
	}
}

func TestWriteCodeRunScript_Success(t *testing.T) {
	path, cleanup, err := writeCodeRunScript("print('hello')", ".py")
	if err != nil {
		t.Fatalf("writeCodeRunScript error: %v", err)
	}

	if !strings.HasSuffix(path, ".py") {
		cleanup()
		t.Fatalf("script path %q missing .py suffix", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		cleanup()
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "print('hello')" {
		cleanup()
		t.Fatalf("content = %q, want print('hello')", string(data))
	}

	dir := filepath.Dir(path)
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("expected dir to be removed, stat err=%v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// daytona_files_git.go – handler error branches
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleDaytonaListFiles_NotFoundPath(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/files?path=/definitely/missing/dir", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("list files missing dir status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleDaytonaMoveFile_MissingSource(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/files/move?source=/missing/src&destination=/tmp/dest", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("move missing source status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleDaytonaGitAdd_InvalidJSON(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/git/add", strings.NewReader("{bad"))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git add bad json status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaGitCheckout_InvalidJSON(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/git/checkout", strings.NewReader("{bad"))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git checkout bad json status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaGitCheckout_EmptyBranch(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()
	repo := initGitRepo(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/git/checkout",
		strings.NewReader(`{"path":"`+repo+`","branch":""}`))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git checkout empty branch status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaGitClone_InvalidJSON(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/git/clone", strings.NewReader("{bad"))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git clone bad json status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaGitClone_EmptyURL(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/git/clone",
		strings.NewReader(`{"path":"/tmp/dest","url":""}`))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git clone empty url status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaGitCommit_InvalidJSON(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/git/commit", strings.NewReader("{bad"))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git commit bad json status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaGitCreateBranch_InvalidJSON(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/git/branches", strings.NewReader("{bad"))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git create branch bad json status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaGitCreateBranch_EmptyName(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()
	repo := initGitRepo(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/git/branches",
		strings.NewReader(`{"path":"`+repo+`","name":""}`))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git create branch empty name status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaGitDeleteBranch_EmptyName(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()
	repo := initGitRepo(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/git/branches",
		strings.NewReader(`{"path":"`+repo+`","name":""}`))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git delete branch empty name status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaGitDeleteBranch_InvalidJSON(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/git/branches", strings.NewReader("{bad"))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git delete branch bad json status = %d, want 400", rr.Code)
	}
}

func TestHandleDaytonaGitHistory_InvalidPath(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/git/history", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git history missing path status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleDaytonaGitListBranches_InvalidPath(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/git/branches", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("git list branches missing path status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleDaytonaFindInFiles_MissingPattern(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/files/find?path=/tmp", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("find in files missing pattern status = %d, want 400", rr.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// daytona_process.go – stream / command helpers
// ─────────────────────────────────────────────────────────────────────────────

func TestDaytonaCommandStream_FinishIdempotent(t *testing.T) {
	s := newDaytonaCommandStream()
	s.finish()
	s.finish() // must not panic
}

func TestDaytonaCommandStream_BroadcastNilAndEmpty(t *testing.T) {
	var s *daytonaCommandStream
	s.broadcast(0, nil)
	s.broadcast(0, []byte{})

	s2 := newDaytonaCommandStream()
	s2.broadcast(0, nil)
}

func TestDaytonaCommandStream_SubscribeFinished(t *testing.T) {
	s := newDaytonaCommandStream()
	s.finish()
	_, ch, finished := s.subscribe()
	if !finished {
		t.Fatal("subscribe after finish should return finished=true")
	}
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel from finished stream should be closed")
		}
	default:
		t.Fatal("channel should not block")
	}
}

func TestDaytonaCommandStream_SubscribeNil(t *testing.T) {
	var s *daytonaCommandStream
	initial, ch, finished := s.subscribe()
	if initial != nil || !finished {
		t.Fatalf("nil stream subscribe: initial=%v finished=%v, want nil,true", initial, finished)
	}
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("nil-stream channel should be closed")
		}
	default:
		t.Fatal("nil-stream channel should not block")
	}
}

func TestShellSingleQuote(t *testing.T) {
	if got := shellSingleQuote("hello"); got != "'hello'" {
		t.Fatalf("shellSingleQuote(hello) = %q, want 'hello'", got)
	}
	if got := shellSingleQuote("it's"); got != "'it'\\''s'" {
		t.Fatalf("shellSingleQuote(it's) = %q, want 'it'\\''s'", got)
	}
}

func TestInt32PtrAndCloneInt32Ptr(t *testing.T) {
	p := int32Ptr(42)
	if *p != 42 {
		t.Fatalf("int32Ptr(42) = %d, want 42", *p)
	}
	c := cloneInt32Ptr(p)
	if c == p || *c != 42 {
		t.Fatalf("cloneInt32Ptr should produce independent copy")
	}
	if got := cloneInt32Ptr(nil); got != nil {
		t.Fatalf("cloneInt32Ptr(nil) = %v, want nil", got)
	}
}

func TestStringOrNil(t *testing.T) {
	if got := stringOrNil(""); got != nil {
		t.Fatalf("stringOrNil(\"\") = %v, want nil", got)
	}
	got := stringOrNil("value")
	if got == nil || *got != "value" {
		t.Fatalf("stringOrNil(value) = %v, want &value", got)
	}
}

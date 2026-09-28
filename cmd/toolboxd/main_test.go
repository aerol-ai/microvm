package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/clonegen"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestNormalizeSandboxIDCases(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     string
	}{
		{name: "uses_trimmed_hostname", hostname: " 7f3c2a1b9d4e ", want: "7f3c2a1b9d4e"},
		{name: "blank_returns_empty", hostname: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeSandboxID(tc.hostname); got != tc.want {
				t.Fatalf("normalizeSandboxID(%q) = %q, want %q", tc.hostname, got, tc.want)
			}
		})
	}
}

func TestNormalizeSandboxPathCases(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		sandboxID string
		want      string
	}{
		{name: "exact_prefix_root", path: "/7f3c2a1b9d4e", sandboxID: "7f3c2a1b9d4e", want: "/"},
		{name: "exact_prefix_subpath", path: "/7f3c2a1b9d4e/process/execute", sandboxID: "7f3c2a1b9d4e", want: "/process/execute"},
		{name: "heuristic_root_strip", path: "/7f3c2a1b9d4e/", sandboxID: "", want: "/"},
		{name: "heuristic_proxy_strip", path: "/7f3c2a1b9d4e/proxy/3000", sandboxID: "", want: "/proxy/3000"},
		{name: "heuristic_files_strip", path: "/7f3c2a1b9d4e/files", sandboxID: "", want: "/files"},
		{name: "heuristic_git_strip", path: "/7f3c2a1b9d4e/git/status", sandboxID: "", want: "/git/status"},
		{name: "direct_toolbox_path_kept", path: "/process/execute", sandboxID: "", want: "/process/execute"},
		{name: "direct_proxy_path_kept", path: "/proxy/3000", sandboxID: "", want: "/proxy/3000"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeSandboxPath(tc.path, tc.sandboxID); got != tc.want {
				t.Fatalf("normalizeSandboxPath(%q, %q) = %q, want %q", tc.path, tc.sandboxID, got, tc.want)
			}
		})
	}
}

func TestServerAllowedPorts(t *testing.T) {
	s := &server{allowedPorts: map[int]struct{}{}}
	s.setAllowedPorts([]int{80, -1, 0, 65536, 8080, 8080})
	if !s.portAllowed(80) || !s.portAllowed(8080) {
		t.Fatalf("expected allowed ports to include 80 and 8080")
	}
	if s.portAllowed(0) || s.portAllowed(65536) || s.portAllowed(-1) {
		t.Fatalf("unexpected invalid port in allowlist")
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("TB_INT", "42")
	t.Setenv("TB_INT_BAD", "not-a-number")
	t.Setenv("TB_INT64", "9001")
	t.Setenv("TB_STRING", "  value  ")
	t.Setenv("TB_DUR", "3s")
	t.Setenv("TB_DUR_BAD", "x")

	if got := envInt("TB_INT", 1); got != 42 {
		t.Fatalf("envInt = %d, want 42", got)
	}
	if got := envInt("TB_INT_BAD", 7); got != 7 {
		t.Fatalf("envInt bad = %d, want fallback 7", got)
	}
	if got := envInt64("TB_INT64", 1); got != 9001 {
		t.Fatalf("envInt64 = %d, want 9001", got)
	}
	if got := envString("TB_STRING", "fallback"); got != "value" {
		t.Fatalf("envString = %q, want value", got)
	}
	if got := envDuration("TB_DUR", time.Second); got != 3*time.Second {
		t.Fatalf("envDuration = %s, want 3s", got)
	}
	if got := envDuration("TB_DUR_BAD", 5*time.Second); got != 5*time.Second {
		t.Fatalf("envDuration bad = %s, want fallback 5s", got)
	}
}

func TestUtilityHelpers(t *testing.T) {
	t.Run("env_map_to_slice", func(t *testing.T) {
		if got := envMapToSlice(nil); got != nil {
			t.Fatalf("envMapToSlice(nil) = %v, want nil", got)
		}
		got := envMapToSlice(map[string]string{"A": "1", "B": "2"})
		joined := strings.Join(got, ",")
		if !strings.Contains(joined, "A=1") || !strings.Contains(joined, "B=2") {
			t.Fatalf("envMapToSlice output = %v", got)
		}
	})

	t.Run("detect_shell", func(t *testing.T) {
		shell, err := detectShell()
		if err != nil {
			t.Fatalf("detectShell error = %v", err)
		}
		if shell == "" {
			t.Fatalf("detectShell returned empty path")
		}
	})

	t.Run("write_multipart_file", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "out.txt")

		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		partWriter, err := mw.CreateFormFile("file", "in.txt")
		if err != nil {
			t.Fatalf("CreateFormFile error = %v", err)
		}
		_, _ = partWriter.Write([]byte("hello-world"))
		_ = mw.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		if err := req.ParseMultipartForm(1 << 20); err != nil {
			t.Fatalf("ParseMultipartForm error = %v", err)
		}
		file, _, err := req.FormFile("file")
		if err != nil {
			t.Fatalf("FormFile error = %v", err)
		}
		defer file.Close()

		if err := writeMultipartFile(target, file); err != nil {
			t.Fatalf("writeMultipartFile error = %v", err)
		}
		data, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("ReadFile error = %v", err)
		}
		if string(data) != "hello-world" {
			t.Fatalf("written content = %q", string(data))
		}
	})
}

func TestMainRouteHandlerBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{
		logger:       logger,
		sandboxID:    "sb-test",
		authToken:    "token-123",
		allowedPorts: map[int]struct{}{},
	}
	h := s.routes()

	t.Run("auth_required", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/process/execute", strings.NewReader(`{"command":"echo hi"}`))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})

	authed := func(method, path string, body io.Reader) *http.Request {
		req := httptest.NewRequest(method, path, body)
		req.Header.Set("Authorization", "Bearer token-123")
		return req
	}

	t.Run("exec_invalid_and_missing_command", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, authed(http.MethodPost, "/process/execute", strings.NewReader("{bad")))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid json status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		h.ServeHTTP(rr, authed(http.MethodPost, "/process/execute", strings.NewReader(`{"command":"   "}`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("missing command status = %d, want 400", rr.Code)
		}
	})

	t.Run("upload_branches", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, authed(http.MethodPost, "/files/upload", strings.NewReader("not-multipart")))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid multipart status = %d, want 400", rr.Code)
		}

		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		part, _ := mw.CreateFormFile("file", "a.txt")
		_, _ = part.Write([]byte("x"))
		_ = mw.Close()
		req := authed(http.MethodPost, "/files/upload", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rr = httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("missing path status = %d, want 400", rr.Code)
		}
	})

	t.Run("download_branches", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, authed(http.MethodGet, "/files/download", nil))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("missing path status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		h.ServeHTTP(rr, authed(http.MethodGet, "/files/download?path=/definitely/missing", nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("missing file status = %d, want 404", rr.Code)
		}
	})

	t.Run("set_allowed_ports_and_proxy_errors", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, authed(http.MethodPost, "/admin/allowed-ports", strings.NewReader("{bad")))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid allow body status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		allowBody, _ := json.Marshal(map[string]any{"ports": []int{8080}})
		h.ServeHTTP(rr, authed(http.MethodPost, "/admin/allowed-ports", bytes.NewReader(allowBody)))
		if rr.Code != http.StatusOK {
			t.Fatalf("allow ports status = %d, want 200", rr.Code)
		}

		rr = httptest.NewRecorder()
		req := authed(http.MethodGet, "/proxy/", nil)
		s.handleProxy(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("proxy missing port status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		req = authed(http.MethodGet, "/proxy/not-a-port", nil)
		s.handleProxy(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("proxy invalid port status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		req = authed(http.MethodGet, "/proxy/9999", nil)
		s.handleProxy(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("proxy not allowed status = %d, want 403", rr.Code)
		}
	})
}

func TestMainHandlers_SuccessPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, allowedPorts: map[int]struct{}{}}

	t.Run("exec_success", func(t *testing.T) {
		workDir := t.TempDir()
		body := strings.NewReader(`{"command":"printf $XVAR && pwd","env":{"XVAR":"ok-"},"workdir":"` + workDir + `"}`)
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/process/execute", body)
		s.handleExec(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("exec status = %d body=%s", rr.Code, rr.Body.String())
		}
		var res models.ExecResult
		if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode exec response: %v", err)
		}
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "ok-") || !strings.Contains(res.Stdout, workDir) {
			t.Fatalf("unexpected exec response: %+v", res)
		}
	})

	t.Run("upload_and_download_success", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "nested", "file.txt")

		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		_ = mw.WriteField("path", target)
		fw, err := mw.CreateFormFile("file", "file.txt")
		if err != nil {
			t.Fatalf("CreateFormFile error: %v", err)
		}
		_, _ = fw.Write([]byte("payload-123"))
		_ = mw.Close()

		uploadReq := httptest.NewRequest(http.MethodPost, "/files/upload", &body)
		uploadReq.Header.Set("Content-Type", mw.FormDataContentType())
		uploadRec := httptest.NewRecorder()
		s.handleUpload(uploadRec, uploadReq)
		if uploadRec.Code != http.StatusCreated {
			t.Fatalf("upload status = %d body=%s", uploadRec.Code, uploadRec.Body.String())
		}

		data, err := os.ReadFile(target)
		if err != nil || string(data) != "payload-123" {
			t.Fatalf("uploaded file read got=%q err=%v", string(data), err)
		}

		downloadReq := httptest.NewRequest(http.MethodGet, "/files/download?path="+target, nil)
		downloadRec := httptest.NewRecorder()
		s.handleDownload(downloadRec, downloadReq)
		if downloadRec.Code != http.StatusOK {
			t.Fatalf("download status = %d body=%s", downloadRec.Code, downloadRec.Body.String())
		}
		if downloadRec.Body.String() != "payload-123" {
			t.Fatalf("download body = %q", downloadRec.Body.String())
		}
	})

	t.Run("proxy_success", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/hello" {
				t.Fatalf("forwarded path = %q, want /hello", r.URL.Path)
			}
			_, _ = w.Write([]byte("proxied-ok"))
		}))
		defer backend.Close()

		parts := strings.Split(strings.TrimPrefix(backend.URL, "http://"), ":")
		port, err := strconv.Atoi(parts[len(parts)-1])
		if err != nil {
			t.Fatalf("parse backend port: %v", err)
		}
		s.setAllowedPorts([]int{port})

		req := httptest.NewRequest(http.MethodGet, "/proxy/"+strconv.Itoa(port)+"/hello", nil)
		rr := httptest.NewRecorder()
		s.handleProxy(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("proxy status = %d body=%s", rr.Code, rr.Body.String())
		}
		if rr.Body.String() != "proxied-ok" {
			t.Fatalf("proxy body = %q", rr.Body.String())
		}
	})
}

func TestMainVersionBranchAndSessionFlusher(t *testing.T) {
	oldArgs := os.Args
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() {
		os.Stdout = oldStdout
		os.Args = oldArgs
		_ = r.Close()
		_ = w.Close()
	})

	os.Stdout = w
	os.Args = []string{"toolboxd", "--version"}
	main()
	_ = w.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != version.Version {
		t.Fatalf("version output = %q, want %q", got, version.Version)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := sessions.New(logger, sessions.Config{
		SandboxID:    "sb-test",
		RecordingDir: t.TempDir(),
		BufferBytes:  1 << 12,
	})
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	if got := newSessionFlusher(nil); got != nil {
		t.Fatalf("newSessionFlusher(nil) = %T, want nil", got)
	}

	flusher, ok := newSessionFlusher(mgr).(*sessionFlusherAdapter)
	if !ok {
		t.Fatalf("newSessionFlusher returned %T, want *sessionFlusherAdapter", newSessionFlusher(mgr))
	}
	if ids := flusher.ListIDs(); len(ids) != 0 {
		t.Fatalf("ListIDs() = %v, want empty", ids)
	}

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Name:    "flush-me",
		Command: "printf tool-box",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ids := flusher.ListIDs(); len(ids) != 1 || ids[0] != sess.ID() {
		t.Fatalf("ListIDs() = %v, want [%s]", ids, sess.ID())
	}
	if err := flusher.FlushRecording(sess.ID()); err != nil {
		t.Fatalf("FlushRecording(active) = %v", err)
	}
	if err := flusher.FlushRecording("missing"); err != nil {
		t.Fatalf("FlushRecording(missing) = %v, want nil", err)
	}
}

func TestMainUtilityErrorBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("start_user_command_error", func(t *testing.T) {
		pidBefore := userCommandPID.Load()
		t.Cleanup(func() { userCommandPID.Store(pidBefore) })

		startUserCommand(logger, []string{filepath.Join(t.TempDir(), "does-not-exist")})
		if userCommandPID.Load() != pidBefore {
			t.Fatalf("userCommandPID changed to %d after failed start", userCommandPID.Load())
		}
	})

	t.Run("forward_shutdown_signals", func(t *testing.T) {
		pidBefore := userCommandPID.Load()
		t.Cleanup(func() { userCommandPID.Store(pidBefore) })
		userCommandPID.Store(999999)

		srv := &http.Server{}
		done := make(chan struct{})
		go func() {
			forwardShutdownSignals(logger, srv)
			close(done)
		}()

		time.Sleep(50 * time.Millisecond)
		proc, err := os.FindProcess(os.Getpid())
		if err != nil {
			t.Fatalf("FindProcess: %v", err)
		}
		if err := proc.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("Signal: %v", err)
		}

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("forwardShutdownSignals did not return")
		}
	})

	t.Run("write_multipart_file_error", func(t *testing.T) {
		src, err := os.CreateTemp(t.TempDir(), "input-*")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		defer src.Close()
		if _, err := src.WriteString("payload"); err != nil {
			t.Fatalf("WriteString: %v", err)
		}
		if _, err := src.Seek(0, 0); err != nil {
			t.Fatalf("Seek: %v", err)
		}
		if err := writeMultipartFile(t.TempDir(), src); err == nil {
			t.Fatal("expected writeMultipartFile to fail for directory target")
		}
	})
}

func TestRoutesDispatchCoverage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := sessions.New(logger, sessions.Config{
		SandboxID:    "sb-test",
		RecordingDir: t.TempDir(),
		BufferBytes:  1 << 12,
	})
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	srv := &server{
		logger:       logger,
		sandboxID:    "sb-test",
		allowedPorts: map[int]struct{}{},
		sessions:     mgr,
		daytona:      newDaytonaCompat(),
		envd:         newEnvdCompat(),
		cloneGen:     clonegen.New(clonegen.DefaultPath, logger),
	}
	h := srv.routes()

	cases := []struct {
		name string
		req  *http.Request
	}{
		{name: "root", req: httptest.NewRequest(http.MethodGet, "/sb-test/", nil)},
		{name: "health", req: httptest.NewRequest(http.MethodGet, "/sb-test/health", nil)},
		{name: "version", req: httptest.NewRequest(http.MethodGet, "/sb-test/version", nil)},
		{name: "clone_generation", req: httptest.NewRequest(http.MethodGet, "/sb-test/clone-generation", nil)},
		{name: "proxy", req: httptest.NewRequest(http.MethodGet, "/sb-test/proxy/abc", nil)},
		{name: "envd_health", req: httptest.NewRequest(http.MethodGet, "/sb-test/envd/health", nil)},
		{name: "process_execute", req: httptest.NewRequest(http.MethodPost, "/sb-test/process/execute", strings.NewReader("{bad"))},
		{name: "process_code_run", req: httptest.NewRequest(http.MethodPost, "/sb-test/process/code-run", strings.NewReader("{bad"))},
		{name: "process_interpreter", req: httptest.NewRequest(http.MethodGet, "/sb-test/process/interpreter/python", nil)},
		{name: "process_session_list", req: httptest.NewRequest(http.MethodGet, "/sb-test/process/session", nil)},
		{name: "process_session_create", req: httptest.NewRequest(http.MethodPost, "/sb-test/process/session", strings.NewReader("{bad"))},
		{name: "files_upload", req: httptest.NewRequest(http.MethodPost, "/sb-test/files/upload", strings.NewReader("not multipart"))},
		{name: "files_download", req: httptest.NewRequest(http.MethodGet, "/sb-test/files/download?path="+filepath.Join(t.TempDir(), "missing"), nil)},
		{name: "files", req: httptest.NewRequest(http.MethodGet, "/sb-test/files?path="+t.TempDir(), nil)},
		{name: "files_info", req: httptest.NewRequest(http.MethodGet, "/sb-test/files/info?path="+t.TempDir(), nil)},
		{name: "files_move", req: httptest.NewRequest(http.MethodPost, "/sb-test/files/move?source=/missing&destination=/tmp/dest", nil)},
		{name: "files_search", req: httptest.NewRequest(http.MethodGet, "/sb-test/files/search?path="+t.TempDir()+"&pattern=*", nil)},
		{name: "files_find", req: httptest.NewRequest(http.MethodGet, "/sb-test/files/find?path="+t.TempDir()+"&pattern=x", nil)},
		{name: "git_status", req: httptest.NewRequest(http.MethodGet, "/sb-test/git/status?path="+t.TempDir(), nil)},
		{name: "allowed_ports", req: httptest.NewRequest(http.MethodPost, "/sb-test/admin/allowed-ports", strings.NewReader("{bad"))},
		{name: "exec_stream", req: httptest.NewRequest(http.MethodGet, "/sb-test/process/exec/stream", nil)},
		{name: "sessions", req: httptest.NewRequest(http.MethodGet, "/sb-test/sessions", nil)},
		{name: "sessions_unknown", req: httptest.NewRequest(http.MethodGet, "/sb-test/sessions/missing", nil)},
		{name: "not_found", req: httptest.NewRequest(http.MethodGet, "/sb-test/does-not-exist", nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, tc.req)
		})
	}
}

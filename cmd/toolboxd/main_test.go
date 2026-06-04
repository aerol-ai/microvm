package main

import (
	"bytes"
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
	"testing"
	"time"

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

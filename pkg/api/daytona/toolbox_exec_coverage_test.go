package daytona

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// newToolboxExecEnv wires a fake toolbox daemon that answers the
// execute/download endpoints so the JSON-RPC-style helpers (runToolboxCommand,
// runToolboxString, sendToolboxJSON) and the bulk-download multipart path get
// real coverage. Mirrors newToolboxProxyTestEnv but with exec-oriented routes.
func newToolboxExecEnv(t *testing.T) (facadeURL, sandboxID string) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/process/execute", func(w http.ResponseWriter, r *http.Request) {
		// Echo a deterministic result. userHomeDir/workDir run shell strings
		// through here too, so just return a fixed stdout.
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"stdout":"/root\n","stderr":"","exit_code":0,"duration_ms":1}`)
	})
	mux.HandleFunc("/files/download", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		if path == "/missing.txt" {
			http.Error(w, `{"error":"no such file"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, "contents-of-"+filepath.Base(path))
	})
	mux.HandleFunc("/files/upload", func(w http.ResponseWriter, r *http.Request) {
		// Drain the uploaded multipart body and ack.
		_ = r.ParseMultipartForm(1 << 20)
		w.WriteHeader(http.StatusNoContent)
	})

	toolboxServer := httptest.NewServer(mux)
	t.Cleanup(toolboxServer.Close)

	host, portText, err := net.SplitHostPort(mustParseURL(t, toolboxServer.URL).Host)
	if err != nil {
		t.Fatalf("split toolbox host: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse toolbox port: %v", err)
	}

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mountManager, err := mounts.New(logger, mounts.Config{
		RootDir:     filepath.Join(dir, "mounts"),
		CredDir:     filepath.Join(dir, "cred"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mountManager.Close)

	cfg := config.Config{
		DBPath:            filepath.Join(dir, "state.db"),
		PublicHost:        "sandbox.test",
		ToolboxPort:       port,
		Runtime:           models.RuntimeDocker,
		EnableCaddy:       false,
		HTTPClientTimeout: 5 * time.Second,
	}
	svc := service.New(cfg, logger, st, fakeToolboxRouteRuntime{}, nil, nil, nil, mountManager, nil)

	sandboxID = "sb-exec"
	now := time.Now().UTC().Round(time.Second)
	if err := st.Upsert(context.Background(), &models.Sandbox{
		ID:             sandboxID,
		Name:           sandboxID,
		Image:          "ubuntu:22.04",
		Status:         models.SandboxStatusStarted,
		ContainerID:    "ctr-" + sandboxID,
		ContainerIP:    host,
		ToolboxEnabled: true,
		ToolboxToken:   "tok-exec",
		Runtime:        models.RuntimeDocker,
		CreatedAt:      now,
		UpdatedAt:      now,
		LastActiveAt:   now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	mux2 := http.NewServeMux()
	RegisterRoutes(mux2, Deps{
		Service: svc,
		Logger:  logger,
		Auth:    func(next http.Handler) http.Handler { return next },
	})
	facadeServer := httptest.NewServer(mux2)
	t.Cleanup(facadeServer.Close)
	return facadeServer.URL, sandboxID
}

func TestToolboxExecuteCommand(t *testing.T) {
	facadeURL, id := newToolboxExecEnv(t)

	resp, err := http.Post(
		facadeURL+ToolboxPrefix+"/"+id+"/process/execute",
		"application/json",
		strings.NewReader(`{"command":"echo hi"}`),
	)
	if err != nil {
		t.Fatalf("POST process/execute: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "/root") {
		t.Fatalf("execute response = %s", body)
	}
}

func TestToolboxExecuteCommand_BadJSON(t *testing.T) {
	facadeURL, id := newToolboxExecEnv(t)
	resp, err := http.Post(
		facadeURL+ToolboxPrefix+"/"+id+"/process/execute",
		"application/json",
		strings.NewReader(`{bad`),
	)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestToolboxUserHomeDirAndWorkDir(t *testing.T) {
	facadeURL, id := newToolboxExecEnv(t)

	for _, path := range []string{"user-home-dir", "work-dir"} {
		resp, err := http.Get(facadeURL + ToolboxPrefix + "/" + id + "/" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d, body=%s", path, resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "/root") {
			t.Fatalf("%s body = %s", path, body)
		}
	}
}

func TestToolboxBulkDownload(t *testing.T) {
	facadeURL, id := newToolboxExecEnv(t)

	resp, err := http.Post(
		facadeURL+ToolboxPrefix+"/"+id+"/files/bulk-download",
		"application/json",
		strings.NewReader(`{"paths":["/a.txt","/missing.txt"]}`),
	)
	if err != nil {
		t.Fatalf("POST bulk-download: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("Content-Type = %q (%v)", resp.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(resp.Body, params["boundary"])
	var fileParts, errorParts int
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		if part.FormName() == "error" {
			errorParts++
		} else {
			fileParts++
		}
		_, _ = io.Copy(io.Discard, part)
	}
	// One good file + one error part (the missing path).
	if fileParts != 1 || errorParts != 1 {
		t.Fatalf("parts: file=%d error=%d, want 1/1", fileParts, errorParts)
	}
}

func TestToolboxBulkDownload_BadRequests(t *testing.T) {
	facadeURL, id := newToolboxExecEnv(t)

	// Bad JSON.
	resp, _ := http.Post(facadeURL+ToolboxPrefix+"/"+id+"/files/bulk-download",
		"application/json", strings.NewReader(`{bad`))
	if resp != nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("bad json status = %d, want 400", resp.StatusCode)
		}
	}

	// Empty paths.
	resp2, _ := http.Post(facadeURL+ToolboxPrefix+"/"+id+"/files/bulk-download",
		"application/json", strings.NewReader(`{"paths":[]}`))
	if resp2 != nil {
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusBadRequest {
			t.Fatalf("empty paths status = %d, want 400", resp2.StatusCode)
		}
	}
}

func TestToolboxBulkUpload(t *testing.T) {
	facadeURL, id := newToolboxExecEnv(t)

	var buf strings.Builder
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("files[0].path", "/dest/a.txt")
	part, err := mw.CreateFormFile("files[0].file", "a.txt")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	_, _ = io.WriteString(part, "hello")
	_ = mw.Close()

	req, _ := http.NewRequest(http.MethodPost,
		facadeURL+ToolboxPrefix+"/"+id+"/files/bulk-upload", strings.NewReader(buf.String()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("bulk-upload: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
}

func TestToolboxBulkUpload_NoFiles(t *testing.T) {
	facadeURL, id := newToolboxExecEnv(t)
	var buf strings.Builder
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("unrelated", "x")
	_ = mw.Close()

	req, _ := http.NewRequest(http.MethodPost,
		facadeURL+ToolboxPrefix+"/"+id+"/files/bulk-upload", strings.NewReader(buf.String()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("bulk-upload: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestParseListFilters(t *testing.T) {
	mk := func(rawQuery string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/daytona/sandbox?"+rawQuery, nil)
	}

	f, err := parseListFilters(mk(`id=abc&name=foo&labels=%7B%22team%22%3A%22a%22%7D&states=started&states=stopped`))
	if err != nil {
		t.Fatalf("parseListFilters: %v", err)
	}
	if f.ID != "abc" || f.Name != "foo" {
		t.Fatalf("filters = %+v", f)
	}
	if f.Labels["team"] != "a" {
		t.Fatalf("labels = %+v", f.Labels)
	}
	if _, ok := f.States["started"]; !ok {
		t.Fatalf("states = %+v", f.States)
	}

	// Malformed labels JSON → error.
	if _, err := parseListFilters(mk(`labels=notjson`)); err == nil {
		t.Fatal("expected error for malformed labels")
	}
}

func TestToolbox_SandboxNotFound(t *testing.T) {
	facadeURL, _ := newToolboxExecEnv(t)
	resp, err := http.Get(facadeURL + ToolboxPrefix + "/sb-does-not-exist/user-home-dir")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestToolboxErrorHelpers(t *testing.T) {
	// toolboxHTTPError.Error
	var nilErr *toolboxHTTPError
	if nilErr.Error() != "" {
		t.Fatalf("nil error string = %q", nilErr.Error())
	}
	if (&toolboxHTTPError{StatusCode: 404, Message: "nope"}).Error() != "nope" {
		t.Fatal("message error string")
	}
	if got := (&toolboxHTTPError{StatusCode: http.StatusTeapot}).Error(); got != http.StatusText(http.StatusTeapot) {
		t.Fatalf("status-only error = %q", got)
	}

	// errorPayload
	if got := string(errorPayload(&toolboxHTTPError{StatusCode: 502, Message: "boom"})); !strings.Contains(got, "boom") {
		t.Fatalf("errorPayload(httpErr) = %s", got)
	}
	if got := string(errorPayload(nil)); !strings.Contains(got, "toolbox unavailable") {
		t.Fatalf("errorPayload(nil) = %s", got)
	}

	// responseErrorPayload — extracts error field from JSON body.
	if got := string(responseErrorPayload(500, []byte(`{"error":"upstream"}`))); !strings.Contains(got, "upstream") {
		t.Fatalf("responseErrorPayload(json) = %s", got)
	}
	if got := string(responseErrorPayload(500, nil)); !strings.Contains(got, http.StatusText(500)) {
		t.Fatalf("responseErrorPayload(empty) = %s", got)
	}

	// readToolboxHTTPError
	if err := readToolboxHTTPError(nil); err == nil {
		t.Fatal("readToolboxHTTPError(nil) should return error")
	}
	resp := &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(`{"error":"down"}`))}
	terr := readToolboxHTTPError(resp)
	var he *toolboxHTTPError
	if !errors.As(terr, &he) || he.Message != "down" {
		t.Fatalf("readToolboxHTTPError = %v", terr)
	}
}

func TestWriteToolboxError(t *testing.T) {
	h := newHandlers(Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})

	// Typed toolbox error maps to its own status.
	rr := httptest.NewRecorder()
	h.writeToolboxError(rr, &toolboxHTTPError{StatusCode: http.StatusNotFound, Message: "missing"})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("typed err status = %d, want 404", rr.Code)
	}

	// Generic error maps to 502 bad gateway.
	rr2 := httptest.NewRecorder()
	h.writeToolboxError(rr2, io.EOF)
	if rr2.Code != http.StatusBadGateway {
		t.Fatalf("generic err status = %d, want 502", rr2.Code)
	}
}

func TestToolboxExtraCoverage(t *testing.T) {
	facadeURL, id := newToolboxExecEnv(t)

	t.Run("routing_switches", func(t *testing.T) {
		endpoints := []struct {
			method string
			path   string
		}{
			{http.MethodGet, ""},
			{http.MethodGet, "health"},
			{http.MethodGet, "version"},
			{http.MethodGet, "files"},
			{http.MethodDelete, "files"},
			{http.MethodPost, "files/folder"},
			{http.MethodPost, "files/replace"},
			{http.MethodPost, "files/permissions"},
			{http.MethodGet, "files/info"},
			{http.MethodPost, "files/upload"},
			{http.MethodGet, "files/download"},
			{http.MethodPost, "files/move"},
			{http.MethodGet, "files/search"},
			{http.MethodGet, "files/find"},
			{http.MethodGet, "git/status"},
			{http.MethodGet, "lsp/initialize"},
			{http.MethodPost, "process/code-run"},
			{http.MethodGet, "process/session/123"},
			{http.MethodGet, "process/interpreter/execute"},
			{http.MethodGet, "process/pty/123"},
		}

		for _, ep := range endpoints {
			req, err := http.NewRequest(ep.method, facadeURL+ToolboxPrefix+"/"+id+"/"+ep.path, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do %s %s: %v", ep.method, ep.path, err)
			}
			resp.Body.Close()
		}
	})

	t.Run("unsupported_route", func(t *testing.T) {
		resp, err := http.Get(facadeURL + ToolboxPrefix + "/" + id + "/unsupported-endpoint")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", resp.StatusCode)
		}
	})

	t.Run("sendToolboxJSON_marshal_error", func(t *testing.T) {
		h := newHandlers(Deps{})
		_, err := h.sendToolboxJSON(context.Background(), "sb-1", "POST", "/test", nil, make(chan int), nil)
		if err == nil {
			t.Fatal("expected json marshal error")
		}
	})

	t.Run("copyResponseHeaders_exclusions", func(t *testing.T) {
		src := http.Header{
			"Connection":      []string{"keep-alive"},
			"Upgrade":         []string{"websocket"},
			"X-Custom-Header": []string{"custom-value"},
		}
		dst := http.Header{}
		copyResponseHeaders(dst, src)
		if dst.Get("Connection") != "" || dst.Get("Upgrade") != "" {
			t.Fatalf("excluded headers were copied: %+v", dst)
		}
		if dst.Get("X-Custom-Header") != "custom-value" {
			t.Fatalf("custom header not copied: %+v", dst)
		}
	})

	t.Run("error_env_calls", func(t *testing.T) {
		errFacadeURL, errId := newToolboxErrorEnv(t)

		// execute command failure
		resp, _ := http.Post(errFacadeURL+ToolboxPrefix+"/"+errId+"/process/execute", "application/json", strings.NewReader(`{"command":"echo"}`))
		if resp != nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %d", resp.StatusCode)
			}
		}

		// user home dir failure
		resp2, _ := http.Get(errFacadeURL + ToolboxPrefix + "/" + errId + "/user-home-dir")
		if resp2 != nil {
			resp2.Body.Close()
			if resp2.StatusCode != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %d", resp2.StatusCode)
			}
		}

		// work dir failure
		resp3, _ := http.Get(errFacadeURL + ToolboxPrefix + "/" + errId + "/work-dir")
		if resp3 != nil {
			resp3.Body.Close()
			if resp3.StatusCode != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %d", resp3.StatusCode)
			}
		}

		// bulk download failure (should generate error parts)
		resp4, err := http.Post(errFacadeURL+ToolboxPrefix+"/"+errId+"/files/bulk-download", "application/json", strings.NewReader(`{"paths":["/a.txt"]}`))
		if err != nil {
			t.Fatalf("POST bulk-download: %v", err)
		}
		defer resp4.Body.Close()
		if resp4.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp4.StatusCode)
		}
		mediaType, params, err := mime.ParseMediaType(resp4.Header.Get("Content-Type"))
		if err == nil && strings.HasPrefix(mediaType, "multipart/") {
			mr := multipart.NewReader(resp4.Body, params["boundary"])
			part, err := mr.NextPart()
			if err == nil {
				if part.FormName() != "error" {
					t.Fatalf("expected error part, got %s", part.FormName())
				}
				body, _ := io.ReadAll(part)
				if !strings.Contains(string(body), "download failed") {
					t.Fatalf("expected download failed, got %s", body)
				}
			}
		}

		// bulk upload failure
		var buf strings.Builder
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("files[0].path", "/dest/a.txt")
		part, _ := mw.CreateFormFile("files[0].file", "a.txt")
		_, _ = io.WriteString(part, "hello")
		_ = mw.Close()

		req, _ := http.NewRequest(http.MethodPost, errFacadeURL+ToolboxPrefix+"/"+errId+"/files/bulk-upload", strings.NewReader(buf.String()))
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp5, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("bulk-upload error env: %v", err)
		}
		defer resp5.Body.Close()
		if resp5.StatusCode != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", resp5.StatusCode)
		}
	})
}

func newToolboxErrorEnv(t *testing.T) (facadeURL, sandboxID string) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/process/execute", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"command execution failed"}`, http.StatusInternalServerError)
	})
	mux.HandleFunc("/files/download", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"download failed"}`, http.StatusInternalServerError)
	})
	mux.HandleFunc("/files/upload", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"upload failed"}`, http.StatusInternalServerError)
	})

	toolboxServer := httptest.NewServer(mux)
	t.Cleanup(toolboxServer.Close)

	host, portText, err := net.SplitHostPort(mustParseURL(t, toolboxServer.URL).Host)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mountManager, err := mounts.New(logger, mounts.Config{
		RootDir:     filepath.Join(dir, "mounts"),
		CredDir:     filepath.Join(dir, "cred"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts: %v", err)
	}
	t.Cleanup(mountManager.Close)

	cfg := config.Config{
		DBPath:            filepath.Join(dir, "state.db"),
		PublicHost:        "sandbox.test",
		ToolboxPort:       port,
		Runtime:           models.RuntimeDocker,
		EnableCaddy:       false,
		HTTPClientTimeout: 5 * time.Second,
	}
	svc := service.New(cfg, logger, st, fakeToolboxRouteRuntime{}, nil, nil, nil, mountManager, nil)

	sandboxID = "sb-exec-err"
	now := time.Now().UTC()
	if err := st.Upsert(context.Background(), &models.Sandbox{
		ID:             sandboxID,
		Name:           sandboxID,
		Status:         models.SandboxStatusStarted,
		ContainerIP:    host,
		ToolboxEnabled: true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	mux2 := http.NewServeMux()
	RegisterRoutes(mux2, Deps{
		Service: svc,
		Logger:  logger,
		Auth:    func(next http.Handler) http.Handler { return next },
	})
	facadeServer := httptest.NewServer(mux2)
	t.Cleanup(facadeServer.Close)
	return facadeServer.URL, sandboxID
}

func TestToolboxDirectCoverage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(config.Config{}, logger, st, fakeToolboxRouteRuntime{}, nil, nil, nil, nil, nil)
	h := newHandlers(Deps{
		Service: svc,
		Logger:  logger,
	})

	t.Run("proxyToolbox_WakeAwareToolboxTarget_error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/process/session/123", nil)
		rr := httptest.NewRecorder()
		h.proxyToolbox(rr, req, "missing-sandbox", "/process/session/123")
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rr.Code)
		}
	})

	t.Run("proxyToolbox_invalid_target_url", func(t *testing.T) {
		now := time.Now().UTC()
		if err := st.Upsert(context.Background(), &models.Sandbox{
			ID:             "sb-bad-url",
			Name:           "sb-bad-url",
			Status:         models.SandboxStatusStarted,
			ContainerIP:    "127.0.0.1\x7f",
			ToolboxEnabled: true,
			CreatedAt:      now,
			UpdatedAt:      now,
		}); err != nil {
			t.Fatalf("upsert: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/process/session/123", nil)
		rr := httptest.NewRecorder()
		h.proxyToolbox(rr, req, "sb-bad-url", "/process/session/123")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("bulkUpload_parse_multipart_error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/files/bulk-upload", strings.NewReader("not-multipart"))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=invalid-boundary")
		rr := httptest.NewRecorder()
		h.bulkUpload(rr, req, "sb-1")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("bulkUpload_missing_file_or_path", func(t *testing.T) {
		// entry.file is nil
		var buf strings.Builder
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("files[0].path", "/dest/a.txt")
		_ = mw.Close()

		req := httptest.NewRequest(http.MethodPost, "/files/bulk-upload", strings.NewReader(buf.String()))
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rr := httptest.NewRecorder()
		h.bulkUpload(rr, req, "sb-1")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}

		// entry.path is empty
		var buf2 strings.Builder
		mw2 := multipart.NewWriter(&buf2)
		part, _ := mw2.CreateFormFile("files[0].file", "a.txt")
		_, _ = io.WriteString(part, "hello")
		_ = mw2.Close()

		req2 := httptest.NewRequest(http.MethodPost, "/files/bulk-upload", strings.NewReader(buf2.String()))
		req2.Header.Set("Content-Type", mw2.FormDataContentType())
		rr2 := httptest.NewRecorder()
		h.bulkUpload(rr2, req2, "sb-1")
		if rr2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr2.Code)
		}

		// entry == nil in File loop (path is empty but file is present - same as above but path is completely absent)
		var buf3 strings.Builder
		mw3 := multipart.NewWriter(&buf3)
		part3, _ := mw3.CreateFormFile("files[0].file", "a.txt")
		_, _ = io.WriteString(part3, "hello")
		_ = mw3.Close()

		req3 := httptest.NewRequest(http.MethodPost, "/files/bulk-upload", strings.NewReader(buf3.String()))
		req3.Header.Set("Content-Type", mw3.FormDataContentType())
		rr3 := httptest.NewRecorder()
		h.bulkUpload(rr3, req3, "sb-1")
		if rr3.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr3.Code)
		}
	})

	t.Run("writeMultipartErrorPart_empty_body", func(t *testing.T) {
		var buf strings.Builder
		mw := multipart.NewWriter(&buf)
		h.writeMultipartErrorPart(mw, nil)
		_ = mw.Close()
		if !strings.Contains(buf.String(), "Bad Gateway") {
			t.Fatalf("expected Bad Gateway, got %s", buf.String())
		}
	})
}

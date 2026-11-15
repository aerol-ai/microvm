package isolate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestAsToolboxHost(t *testing.T) {
	d := New(Config{}, nil)
	th, ok := AsToolboxHost(d)
	if !ok || th == nil {
		t.Fatal("Driver should implement ToolboxHost")
	}
	if _, ok := AsToolboxHost(struct{}{}); ok {
		t.Fatal("non-ToolboxHost should not match")
	}
}

func TestServeToolboxUnsupportedEndpoint(t *testing.T) {
	d := New(Config{}, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1/files/read", nil)
	d.ServeToolbox(context.Background(), "sb-1", "tok", rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

// An isolate has no filesystem to watch: a clear 501 naming the runtimes
// that can (plan F5, Q8).
func TestServeToolboxFileWatchUnsupported(t *testing.T) {
	d := New(Config{}, nil)
	for _, path := range []string{"/files/watch", "/v1/sandboxes/sb-1/toolbox/files/watch"} {
		rec := httptest.NewRecorder()
		d.ServeToolbox(context.Background(), "sb-1", "tok", rec, httptest.NewRequest(http.MethodGet, path+"?path=/", nil))
		if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), "gVisor or Firecracker") {
			t.Fatalf("%s = %d %q, want the file-watching 501", path, rec.Code, rec.Body.String())
		}
	}
}

// Terminals, sessions, the code interpreters, code-run and streaming exec
// answer 501 instead of falling through to the fetch-handler exec that
// every other "/process" path reaches: that exec answers 200 with the
// handler's output, which their clients would take for a working terminal
// or a program's output. The sandbox here has a handler that answers, so a
// route that reached it would show as a 200, and the handler would have run.
func TestServeToolboxTerminalsUnsupported(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}
	invoked := 0
	sup.hosts[0].invokeFn = func(context.Context, string, *http.Request) (*http.Response, error) {
		invoked++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("tenant output")), Header: make(http.Header)}, nil
	}
	const (
		terminals   = "no shell"
		interpreter = "code interpreter is not supported on V8 isolate sandboxes"
		codeRun     = "code-run needs a shell"
		stream      = "streaming exec needs a process"
	)
	for _, tc := range []struct {
		method, path, want string
		json               bool // answered in toolboxd's {"error": ...} shape
	}{
		{http.MethodPost, "/process/pty", terminals, false},
		{http.MethodGet, "/process/pty/t1/connect", terminals, false},
		{http.MethodPost, "/process/session", terminals, false},
		{http.MethodPost, "/process/session/s1/exec", terminals, false},
		{http.MethodPost, "/sessions", terminals, false},
		{http.MethodPost, "/sessions/s1/exec", terminals, false},
		// Daytona codeInterpreter.
		{http.MethodPost, "/process/interpreter/context", interpreter, true},
		{http.MethodGet, "/process/interpreter/context", interpreter, true},
		{http.MethodDelete, "/process/interpreter/context/ctx-1", interpreter, true},
		{http.MethodGet, "/process/interpreter/execute", interpreter, true},
		// E2B code interpreter.
		{http.MethodPost, "/interpreter/e2b/execute", interpreter, true},
		{http.MethodGet, "/interpreter/e2b/contexts", interpreter, true},
		{http.MethodGet, "/interpreter", interpreter, true},
		{http.MethodPost, "/process/code-run", codeRun, true},
		{http.MethodGet, "/process/exec/stream", stream, true},
	} {
		rec := httptest.NewRecorder()
		d.ServeToolbox(ctx, "sb-1", "tok", rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}")))
		if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("%s %s = %d %q, want a 501 saying %q", tc.method, tc.path, rec.Code, rec.Body.String(), tc.want)
		}
		if tc.json {
			var body models.ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error == "" || rec.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("%s %s body %q (%v), want toolboxd's JSON error", tc.method, tc.path, rec.Body.String(), err)
			}
		}
	}
	if invoked != 0 {
		t.Fatalf("the fetch handler ran %d times for unsupported routes", invoked)
	}
	// /process/execute, the one exec the isolate serves, still reaches the
	// handler.
	body, _ := json.Marshal(models.ExecRequest{Command: "/"})
	rec := httptest.NewRecorder()
	d.ServeToolbox(ctx, "sb-1", "tok", rec, httptest.NewRequest(http.MethodPost, "/process/execute", bytes.NewReader(body)))
	var result models.ExecResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil || rec.Code != http.StatusOK || result.Stdout != "tenant output" || invoked != 1 {
		t.Fatalf("/process/execute = %d %+v (%v), handler ran %d times", rec.Code, result, err, invoked)
	}
}

// Every file call, the SDK verbs of plan F1 included, is a 501 with a JSON
// reason the SDKs can show, as on WASM sandboxes.
func TestServeToolboxFileRoutesAnswerJSON501(t *testing.T) {
	d := New(Config{}, nil)
	for _, route := range [][2]string{
		{http.MethodGet, "/files"},
		{http.MethodGet, "/files/info"},
		{http.MethodPost, "/files/move"},
		{http.MethodPost, "/files/copy"},
		{http.MethodPost, "/files/folder"},
		{http.MethodDelete, "/files"},
		{http.MethodPost, "/files/upload"},
		{http.MethodGet, "/files/download"},
		{http.MethodGet, "/files/search"},
		{http.MethodGet, "/version"},
	} {
		rec := httptest.NewRecorder()
		d.ServeToolbox(context.Background(), "sb-1", "tok", rec, httptest.NewRequest(route[0], route[1], nil))
		var body models.ErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusNotImplemented || body.Error == "" {
			t.Fatalf("%s %s = %d %q (%v), want a JSON 501", route[0], route[1], rec.Code, rec.Body.String(), err)
		}
		if strings.HasPrefix(route[1], "/files") && !strings.Contains(body.Error, "isolate") {
			t.Fatalf("%s %s reason = %q", route[0], route[1], body.Error)
		}
	}
}

func TestServeExecInvokeHandler(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}
	host := sup.hosts[0]
	host.invokeFn = func(_ context.Context, id string, r *http.Request) (*http.Response, error) {
		if id != "sb-1" || r.Method != http.MethodPost || r.URL.Path != "/hook" {
			t.Fatalf("invoke: id=%s method=%s path=%s", id, r.Method, r.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("pong")),
			Header:     make(http.Header),
		}, nil
	}

	body, _ := json.Marshal(models.ExecRequest{Command: "/hook", Env: map[string]string{"METHOD": "POST"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/exec", bytes.NewReader(body))
	d.ServeToolbox(ctx, "sb-1", "", rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var result models.ExecResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || result.Stdout != "pong" {
		t.Fatalf("result = %+v", result)
	}
}

func TestServeExecErrorPaths(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}
	host := sup.hosts[0]

	t.Run("invoke_error", func(t *testing.T) {
		host.invokeFn = func(context.Context, string, *http.Request) (*http.Response, error) {
			return nil, errors.New("invoke failed")
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/process", nil)
		d.ServeToolbox(ctx, "sb-1", "", rec, req)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502", rec.Code)
		}
	})

	t.Run("handler_status_4xx", func(t *testing.T) {
		host.invokeFn = func(context.Context, string, *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("missing")),
				Header:     make(http.Header),
			}, nil
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/exec", nil)
		d.ServeToolbox(ctx, "sb-1", "", rec, req)
		var result models.ExecResult
		_ = json.NewDecoder(rec.Body).Decode(&result)
		if result.ExitCode != 1 || !strings.Contains(result.Stderr, "404") {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("default_path", func(t *testing.T) {
		host.invokeFn = func(_ context.Context, _ string, r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/" {
				t.Fatalf("path = %q, want /", r.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("root")),
				Header:     make(http.Header),
			}, nil
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/exec", nil)
		d.ServeToolbox(ctx, "sb-1", "", rec, req)
		var result models.ExecResult
		_ = json.NewDecoder(rec.Body).Decode(&result)
		if result.Stdout != "root" {
			t.Fatalf("stdout = %q", result.Stdout)
		}
	})
}

func TestInvokeHTTP(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}
	host := sup.hosts[0]
	host.invokeFn = func(_ context.Context, id string, r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(id + r.URL.Path)),
			Header:     make(http.Header),
		}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "http://isolate/path", nil)
	resp, err := d.InvokeHTTP(ctx, "sb-1", req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "sb-1/path" {
		t.Fatalf("body = %q", body)
	}

	t.Run("unknown_sandbox", func(t *testing.T) {
		_, err := d.InvokeHTTP(ctx, "sb-missing", req)
		if err == nil {
			t.Fatal("expected error for unknown sandbox")
		}
	})

	t.Run("group_gone", func(t *testing.T) {
		d.mu.Lock()
		rec := d.byID["sb-1"]
		rec.groupKey = "ghost"
		d.mu.Unlock()
		_, err := d.InvokeHTTP(ctx, "sb-1", req)
		if err == nil || !strings.Contains(err.Error(), "gone") {
			t.Fatalf("InvokeHTTP = %v, want group gone error", err)
		}
	})

	t.Run("reload_after_reap", func(t *testing.T) {
		d.mu.Lock()
		rec := d.byID["sb-1"]
		rec.groupKey = ""
		rec.needsReload = true
		d.mu.Unlock()
		resp, err := d.InvokeHTTP(ctx, "sb-1", req)
		if err != nil {
			t.Fatalf("reload invoke: %v", err)
		}
		_ = resp.Body.Close()
	})
}

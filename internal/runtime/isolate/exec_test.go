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

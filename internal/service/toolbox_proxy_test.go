package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeToolboxHost struct {
	wasmRecordingRuntime
}

func (f *fakeToolboxHost) ServeToolbox(ctx context.Context, sandboxID string, token string, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("wasm-toolbox"))
}

type captureToolboxHost struct {
	wasmRecordingRuntime
	path     string
	rawQuery string
	auth     string
	testHdr  string
}

func (c *captureToolboxHost) ServeToolbox(ctx context.Context, sandboxID string, token string, w http.ResponseWriter, r *http.Request) {
	c.path = r.URL.Path
	c.rawQuery = r.URL.RawQuery
	c.auth = r.Header.Get("Authorization")
	c.testHdr = r.Header.Get("X-Test")
	w.WriteHeader(http.StatusOK)
}

func TestServeToolboxReverseProxy_Wasm(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(&fakeToolboxHost{})

	now := time.Now().UTC()
	err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-toolbox",
		Runtime:      models.RuntimeWasm,
		Status:       models.SandboxStatusStarted,
		ToolboxToken: "token123",
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("Create sandbox failed: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	rec := httptest.NewRecorder()

	err = svc.ServeToolboxReverseProxy(ctx, "sb-toolbox", rec, req, "/foo")
	if err != nil {
		t.Fatalf("ServeToolboxReverseProxy failed: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", rec.Code)
	}
	if rec.Body.String() != "wasm-toolbox" {
		t.Fatalf("Expected body wasm-toolbox, got %s", rec.Body.String())
	}
}

func TestRoundTripToolbox_Wasm(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(&fakeToolboxHost{})

	now := time.Now().UTC()
	err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-rt",
		Runtime:      models.RuntimeWasm,
		Status:       models.SandboxStatusStarted,
		ToolboxToken: "token123",
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("Create sandbox failed: %v", err)
	}

	resp, err := svc.RoundTripToolbox(ctx, "sb-rt", "GET", "/bar", nil, nil, nil)
	if err != nil {
		t.Fatalf("RoundTripToolbox failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "wasm-toolbox" {
		t.Fatalf("Expected body wasm-toolbox, got %s", string(body))
	}
}

func TestServeToolboxReverseProxy_Network(t *testing.T) {
	ctx := context.Background()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("net-toolbox"))
	}))
	defer ts.Close()

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.ToolboxPort = 0 // not strictly needed, but let's test with ContainerIP + port

	port := strings.Split(ts.URL, ":")[2]

	now := time.Now().UTC()
	err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-net",
		Runtime:      models.RuntimeDocker,
		Status:       models.SandboxStatusStarted,
		ToolboxToken: "token123",
		ContainerIP:  "127.0.0.1",
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("Create sandbox failed: %v", err)
	}
	// override port for testing
	svc.cfg.ToolboxPort = 0

	// We need ToolboxTarget to return ts.URL.
	// Actually, ToolboxTarget constructs `http://%s:%d`.
	// We can set ToolboxPort in config.
	var portInt int
	fmt.Sscanf(port, "%d", &portInt)
	svc.cfg.ToolboxPort = portInt

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	rec := httptest.NewRecorder()

	err = svc.ServeToolboxReverseProxy(ctx, "sb-net", rec, req, "/foo")
	if err != nil {
		t.Fatalf("ServeToolboxReverseProxy failed: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", rec.Code)
	}
	if rec.Body.String() != "net-toolbox" {
		t.Fatalf("Expected body net-toolbox, got %s", rec.Body.String())
	}
}

func TestRoundTripToolbox_Network(t *testing.T) {
	ctx := context.Background()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("net-toolbox"))
	}))
	defer ts.Close()

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	port := strings.Split(ts.URL, ":")[2]
	var portInt int
	fmt.Sscanf(port, "%d", &portInt)
	svc.cfg.ToolboxPort = portInt

	now := time.Now().UTC()
	err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-net-rt",
		Runtime:      models.RuntimeDocker,
		Status:       models.SandboxStatusStarted,
		ToolboxToken: "token123",
		ContainerIP:  "127.0.0.1",
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("Create sandbox failed: %v", err)
	}

	resp, err := svc.RoundTripToolbox(ctx, "sb-net-rt", "GET", "/bar", nil, nil, nil)
	if err != nil {
		t.Fatalf("RoundTripToolbox failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "net-toolbox" {
		t.Fatalf("Expected body net-toolbox, got %s", string(body))
	}
}

func TestToolboxProxyErrorBranches(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(&recordingRuntime{})

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-wasm-toolbox",
		Runtime:      models.RuntimeWasm,
		Status:       models.SandboxStatusStarted,
		ToolboxToken: "token123",
		CreatedAt:    now,
		UpdatedAt:    now,
	}); err != nil {
		t.Fatalf("Create sandbox failed: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	rec := httptest.NewRecorder()
	err := svc.ServeToolboxReverseProxy(ctx, "sb-wasm-toolbox", rec, req, "/foo")
	if err == nil || !strings.Contains(err.Error(), "does not implement toolbox host") {
		t.Fatalf("ServeToolboxReverseProxy error = %v, want toolbox-host error", err)
	}

	if _, err := svc.RoundTripToolbox(ctx, "sb-wasm-toolbox", "GET", "/foo", nil, nil, nil); err == nil || !strings.Contains(err.Error(), "does not implement toolbox host") {
		t.Fatalf("RoundTripToolbox error = %v, want toolbox-host error", err)
	}
}

func TestToolboxProxyRequestNormalizationAndHeaders(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-toolbox-headers",
		Runtime:      models.RuntimeWasm,
		Status:       models.SandboxStatusStarted,
		ToolboxToken: "token123",
		CreatedAt:    now,
		UpdatedAt:    now,
	}); err != nil {
		t.Fatalf("Create sandbox failed: %v", err)
	}

	capture := &captureToolboxHost{}
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(capture)

	resp, err := svc.RoundTripToolbox(ctx, "sb-toolbox-headers", "GET", "api/v1", url.Values{"q": {"1"}}, nil, http.Header{"X-Test": {"abc"}})
	if err != nil {
		t.Fatalf("RoundTripToolbox wasm: %v", err)
	}
	resp.Body.Close()
	if capture.path != "/api/v1" {
		t.Fatalf("wasm toolbox path = %q, want /api/v1", capture.path)
	}
	if capture.rawQuery != "q=1" {
		t.Fatalf("wasm toolbox query = %q, want q=1", capture.rawQuery)
	}
	if capture.auth != "Bearer token123" || capture.testHdr != "abc" {
		t.Fatalf("wasm toolbox headers = auth:%q test:%q", capture.auth, capture.testHdr)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1" {
			t.Fatalf("network toolbox path = %q, want /api/v1", r.URL.Path)
		}
		if r.URL.RawQuery != "a=1&b=2" {
			t.Fatalf("network toolbox query = %q, want a=1&b=2", r.URL.RawQuery)
		}
		if r.Header.Get("Authorization") != "Bearer token123" || r.Header.Get("X-Test") != "xyz" {
			t.Fatalf("network toolbox headers = auth:%q test:%q", r.Header.Get("Authorization"), r.Header.Get("X-Test"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	port := strings.Split(ts.URL, ":")[2]
	var portInt int
	fmt.Sscanf(port, "%d", &portInt)
	svc.cfg.ToolboxPort = portInt
	stored, err := st.Get(ctx, "sb-toolbox-headers")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	stored.Runtime = models.RuntimeDocker
	stored.ContainerIP = "127.0.0.1"
	if err := st.Upsert(ctx, stored); err != nil {
		t.Fatalf("store.Upsert: %v", err)
	}
	resp, err = svc.RoundTripToolbox(ctx, "sb-toolbox-headers", "GET", "api/v1", url.Values{"a": {"1"}, "b": {"2"}}, nil, http.Header{"X-Test": {"xyz"}})
	if err != nil {
		t.Fatalf("RoundTripToolbox network: %v", err)
	}
	resp.Body.Close()
}

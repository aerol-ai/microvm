package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

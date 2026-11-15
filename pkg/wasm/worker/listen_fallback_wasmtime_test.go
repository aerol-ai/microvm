//go:build wasmtime

package worker

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// TestWasmtimeSandboxServesHTTPThroughFallback runs the real wasmtime engine
// (issue #175). No wasmtime release can hand a WASI guest a pre-opened TCP
// listener (its C API dropped wasi_config_preopen_socket in v20 and its
// preview-1 sock_accept is a stub), so a wasmtime sandbox that exposes a port
// moves to wazero inside its own worker. This proves that path end to end
// with a real guest: the worker loads the module on wasmtime, the listener
// request moves it, and a proxied HTTP request reaches the guest.
func TestWasmtimeSandboxServesHTTPThroughFallback(t *testing.T) {
	modPath := ensureWasip1HTTPWasm(t)
	t.Setenv("AEROL_WASM_ENGINE", wasmengine.EngineNameWasmtime())

	client, cleanup := startTestWorker(t)
	defer cleanup()

	const sandboxID = "sb-wasmtime-listen"
	if _, err := client.LoadModule(sandboxID, modPath, 0); err != nil {
		t.Fatalf("LoadModule on wasmtime: %v", err)
	}
	if err := client.Instantiate(sandboxID, wasmengine.Capabilities{
		WASIListenPort: wasmengine.WASIListenPortDisabled,
		Args:           []string{"wasi", "http"},
	}); err != nil {
		t.Fatalf("Instantiate on wasmtime: %v", err)
	}

	got, err := client.SetListenPorts(sandboxID, []int{8080, 9090}, "127.0.0.1")
	if err != nil {
		t.Fatalf("SetListenPorts: %v", err)
	}
	if got.Engine != wasmengine.EngineNameWazero() || got.FallbackFrom != wasmengine.EngineNameWasmtime() {
		t.Fatalf("listen report = %+v, want engine %q moved from %q", got, wasmengine.EngineNameWazero(), wasmengine.EngineNameWasmtime())
	}
	if got.Primary <= 0 || len(got.Ports) != 2 {
		t.Fatalf("listen report = %+v, want two live listeners", got)
	}

	go func() { _ = client.Invoke(sandboxID, "_start") }()
	for _, port := range []int{8080, 9090} {
		var rec *httptest.ResponseRecorder
		for attempt := 0; attempt < 60; attempt++ {
			req, _ := http.NewRequest(http.MethodPost, "http://gateway/", bytes.NewReader([]byte("wasmtime")))
			rec = httptest.NewRecorder()
			if err := client.ProxyHTTP(sandboxID, port, rec, req); err == nil && rec.Code == http.StatusOK {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if rec.Code != http.StatusOK || rec.Body.String() != "wasmtime\n" {
			t.Fatalf("port %d: status=%d body=%q, want the guest's echo", port, rec.Code, rec.Body.String())
		}
	}
}

// TestWasmtimeListenFallbackOff keeps today's clear error when the operator
// turns the fallback off.
func TestWasmtimeListenFallbackOff(t *testing.T) {
	modPath := ensureWasip1HTTPWasm(t)
	t.Setenv("AEROL_WASM_ENGINE", wasmengine.EngineNameWasmtime())
	t.Setenv(ListenFallbackEnv, "false")

	client, cleanup := startTestWorker(t)
	defer cleanup()

	const sandboxID = "sb-wasmtime-nofallback"
	if _, err := client.LoadModule(sandboxID, modPath, 0); err != nil {
		t.Fatalf("LoadModule on wasmtime: %v", err)
	}
	if _, err := client.SetListenPorts(sandboxID, []int{8080}, "127.0.0.1"); err == nil {
		t.Fatal("a wasmtime sandbox with the fallback off must refuse a listener")
	}
}

//go:build wasmtime

package worker

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// proxyEcho posts body through the worker to the guest's exposed port,
// retrying while the guest starts.
func proxyEcho(t *testing.T, client *Client, sandboxID string, port int, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rec *httptest.ResponseRecorder
	for attempt := 0; attempt < 100; attempt++ {
		method := http.MethodPost
		if body == "" {
			method = http.MethodGet
		}
		req, _ := http.NewRequest(method, "http://gateway"+path, bytes.NewReader([]byte(body)))
		rec = httptest.NewRecorder()
		if err := client.ProxyHTTP(sandboxID, port, rec, req); err == nil && rec.Code == http.StatusOK {
			return rec
		}
		time.Sleep(30 * time.Millisecond)
	}
	return rec
}

// TestWasmtimeSandboxServesHTTPNatively runs the real wasmtime engine
// (issue #175). The engine serves the guest's sockets from its own WASI
// layer, so a wasmtime sandbox that exposes ports stays on wasmtime: no
// move to wazero, and each port reaches the listener the guest serves it
// on.
func TestWasmtimeSandboxServesHTTPNatively(t *testing.T) {
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
		Args:           []string{"aerolhttp", "multiport"},
	}); err != nil {
		t.Fatalf("Instantiate on wasmtime: %v", err)
	}

	got, err := client.SetListenPorts(sandboxID, []int{8080, 9090}, "127.0.0.1")
	if err != nil {
		t.Fatalf("SetListenPorts: %v", err)
	}
	if got.Engine != wasmengine.EngineNameWasmtime() || got.FallbackFrom != "" {
		t.Fatalf("listen report = %+v, want engine %q and no fallback", got, wasmengine.EngineNameWasmtime())
	}
	if got.Primary <= 0 || len(got.Ports) != 2 || got.Ports[8080] == got.Ports[9090] {
		t.Fatalf("listen report = %+v, want two live listeners", got)
	}

	go func() { _ = client.Invoke(sandboxID, "_start") }()
	for _, port := range []int{8080, 9090} {
		if rec := proxyEcho(t, client, sandboxID, port, "/", "wasmtime"); rec.Code != http.StatusOK || rec.Body.String() != "wasmtime\n" {
			t.Fatalf("port %d: status=%d body=%q, want the guest's echo", port, rec.Code, rec.Body.String())
		}
	}
	// Once the guest accepts on each listener, each port reaches its own.
	for _, port := range []int{8080, 9090} {
		want := map[int]string{8080: "8080", 9090: "9090"}[port]
		var body string
		for attempt := 0; attempt < 50; attempt++ {
			if body = proxyEcho(t, client, sandboxID, port, "/port", "").Body.String(); body == want {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if body != want {
			t.Fatalf("port %d answered %q", port, body)
		}
	}
	if err := client.StopInstance(sandboxID); err != nil {
		t.Fatalf("StopInstance while the guest serves: %v", err)
	}
}

// TestWasmtimeListenFallbackOff: with the fallback off a wasmtime sandbox
// still serves, because it never needed to move.
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
	if err := client.Instantiate(sandboxID, wasmengine.Capabilities{
		WASIListenPort: wasmengine.WASIListenPortDisabled,
		Args:           []string{"aerolhttp"},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := client.SetListenPorts(sandboxID, []int{8080}, "127.0.0.1")
	if err != nil {
		t.Fatalf("SetListenPorts with the fallback off: %v", err)
	}
	if got.Engine != wasmengine.EngineNameWasmtime() || got.FallbackFrom != "" {
		t.Fatalf("listen report = %+v", got)
	}
	go func() { _ = client.Invoke(sandboxID, "_start") }()
	if rec := proxyEcho(t, client, sandboxID, 8080, "/", "native"); rec.Body.String() != "native\n" {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

// memorylessWasm is a valid module that exports no memory: the wasmtime
// engine's socket layer cannot serve it, so it still takes the fallback.
func memorylessWasm(t *testing.T) string {
	t.Helper()
	// (module (func (export "_start")))
	mod := []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: () -> ()
		0x03, 0x02, 0x01, 0x00, // func 0: type 0
		0x07, 0x0a, 0x01, 0x06, '_', 's', 't', 'a', 'r', 't', 0x00, 0x00, // export _start
		0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // body: end
	}
	path := filepath.Join(t.TempDir(), "memoryless.wasm")
	if err := os.WriteFile(path, mod, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWasmtimeFallbackStillMovesWhatTheLayerCannotServe(t *testing.T) {
	t.Setenv("AEROL_WASM_ENGINE", wasmengine.EngineNameWasmtime())
	client, cleanup := startTestWorker(t)
	defer cleanup()

	const sandboxID = "sb-wasmtime-memoryless"
	if _, err := client.LoadModule(sandboxID, memorylessWasm(t), 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	got, err := client.SetListenPorts(sandboxID, []int{8080}, "127.0.0.1")
	if err != nil {
		t.Fatalf("SetListenPorts: %v", err)
	}
	if got.Engine != wasmengine.EngineNameWazero() || got.FallbackFrom != wasmengine.EngineNameWasmtime() {
		t.Fatalf("listen report = %+v, want a move to wazero", got)
	}

	t.Setenv(ListenFallbackEnv, "false")
	const other = "sb-wasmtime-memoryless-off"
	client2, cleanup2 := startTestWorker(t)
	defer cleanup2()
	if _, err := client2.LoadModule(other, memorylessWasm(t), 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if _, err := client2.SetListenPorts(other, []int{8080}, "127.0.0.1"); err == nil {
		t.Fatal("with the fallback off, a module the layer cannot serve is refused")
	}
}

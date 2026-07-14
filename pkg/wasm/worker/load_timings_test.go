package worker

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// TestLoadModuleReportsSubStageTimings is the regression guard for the
// wasm_load sub-stage instrumentation: a real wazero worker must return a
// populated LoadTimings so the create path can emit wasm_load_newengine /
// _runtime / _read / _compile Server-Timing entries. Without this, wasm_load
// stays a single opaque ~2.8s number and the resident-module work
// (plans/wasm-resident-module-host.md) can't target the dominant sub-cost.
func TestLoadModuleReportsSubStageTimings(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	// macOS sun_path caps at 104 bytes — keep the socket under /tmp.
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("aerol-wasm-lt-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &Server{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = srv.Serve(c) }(conn)
		}
	}()

	client := NewClient(socketPath)
	if err := client.Ping("sb-lt"); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	timings, err := client.LoadModule("sb-lt", modPath, 0)
	if err != nil {
		t.Fatalf("LoadModule: %v", err)
	}

	// NewEngine (worker builds the first runtime), RuntimeInit (LoadModule
	// rebuilds it at the memory limit), and Compile (wazero CompileModule) all
	// do real work, so each must register a positive duration once the timings
	// survive the IPC round-trip. Read is asserted non-negative only — a tiny
	// module file can round toward zero on a warm page cache.
	if timings.NewEngine <= 0 {
		t.Errorf("NewEngine timing not reported: %v", timings.NewEngine)
	}
	if timings.RuntimeInit <= 0 {
		t.Errorf("RuntimeInit timing not reported: %v", timings.RuntimeInit)
	}
	if timings.Compile <= 0 {
		t.Errorf("Compile timing not reported: %v", timings.Compile)
	}
	if timings.Read < 0 {
		t.Errorf("Read timing negative: %v", timings.Read)
	}
	time.Sleep(10 * time.Millisecond)
}

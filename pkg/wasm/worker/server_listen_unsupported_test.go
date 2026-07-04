package worker

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// noListenEngine is a minimal Engine whose SupportsListen() is false — mirroring
// the wasmtime backend, which cannot yet host a wasip1 TCP listener.
type noListenEngine struct{}

func (noListenEngine) LoadModule(context.Context, string, wasmengine.LoadOptions) error { return nil }
func (noListenEngine) Instantiate(context.Context, wasmengine.Capabilities) error {
	return nil
}
func (noListenEngine) InvokeExport(context.Context, string) error { return nil }
func (noListenEngine) Run(context.Context, wasmengine.Capabilities, string) (wasmengine.RunResult, error) {
	return wasmengine.RunResult{}, nil
}
func (noListenEngine) StopInstance(context.Context) error { return nil }
func (noListenEngine) CaptureSnapshot(context.Context) (wasmengine.SnapshotCapture, error) {
	return wasmengine.SnapshotCapture{}, nil
}
func (noListenEngine) RestoreSnapshot(context.Context, wasmengine.SnapshotRestoreInput, wasmengine.Capabilities) error {
	return nil
}
func (noListenEngine) Close(context.Context) error     { return nil }
func (noListenEngine) ResolvedListenPort() (int, bool) { return 0, false }
func (noListenEngine) SupportsListen() bool            { return false }

// TestSetListenPortRejectedWhenEngineLacksListen asserts that enabling a wasip1
// listener (HTTP ingress / expose_port) on an engine that cannot host one fails
// loudly with a clear error, rather than silently failing to resolve a port.
func TestSetListenPortRejectedWhenEngineLacksListen(t *testing.T) {
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("aerol-wasm-nolisten-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := &Server{}
	srv.mu.Lock()
	srv.eng = noListenEngine{}
	srv.mu.Unlock()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = srv.Serve(c) }(conn)
		}
	}()

	const sandboxID = "sb-nolisten"
	client := NewClient(socketPath)

	// Disabling a listener must still succeed (no-op path).
	if err := client.SetListenPort(sandboxID, wasmengine.WASIListenPortDisabled, ""); err != nil {
		t.Fatalf("SetListenPort(disabled) should succeed, got: %v", err)
	}

	// Enabling a listener must be rejected with a clear, engine-specific error.
	err = client.SetListenPort(sandboxID, 0, "127.0.0.1")
	if err == nil {
		t.Fatal("SetListenPort(enable) on a no-listen engine should fail")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("error should explain ingress is unsupported, got: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
}

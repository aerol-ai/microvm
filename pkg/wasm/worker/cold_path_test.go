package worker

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestWorkerColdPathLoadInstantiateInvoke(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	// macOS sun_path is capped at 104 bytes — keep the socket under /tmp.
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("aerol-wasm-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	sandboxID := "sb-cold"

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
	if err := client.Ping(sandboxID); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := client.LoadModule(sandboxID, modPath); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if err := client.Instantiate(sandboxID, wasmengine.Capabilities{Args: []string{"test"}}); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if err := client.Invoke(sandboxID, "_start"); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if err := client.StopInstance(sandboxID); err != nil {
		t.Fatalf("StopInstance: %v", err)
	}
	// Brief pause so per-conn Serve goroutines can finish before test teardown.
	time.Sleep(10 * time.Millisecond)
}

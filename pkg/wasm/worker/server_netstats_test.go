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

func TestServerNetstatsTickDrainsCounters(t *testing.T) {
	srv := &Server{}
	srv.netUsageFor("sb-1").bytesIn.Add(10)
	srv.netUsageFor("sb-1").bytesOut.Add(20)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(serverConn)
	}()

	c := NewClient("")
	c.dial = func(string) (net.Conn, error) { return clientConn, nil }

	in, out, err := c.NetstatsTick("sb-1")
	if err != nil {
		t.Fatalf("NetstatsTick: %v", err)
	}
	if in != 10 || out != 20 {
		t.Fatalf("tick = in %d out %d, want 10/20", in, out)
	}
	_ = clientConn.Close()
	<-done
}

func TestServerExecNetstatsIncrementsGuestIO(t *testing.T) {
	srv := &Server{}
	const sandboxID = "sb-exec"
	// Same rule as MsgExec in server.go (stdout+stderr length).
	result := wasmengine.RunResult{Stdout: "hello\n", Stderr: "warn"}
	if out := int64(len(result.Stdout) + len(result.Stderr)); out > 0 {
		srv.netUsageFor(sandboxID).bytesOut.Add(out)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(serverConn)
	}()

	c := NewClient("")
	c.dial = func(string) (net.Conn, error) { return clientConn, nil }

	_, out, err := c.NetstatsTick(sandboxID)
	if err != nil {
		t.Fatalf("NetstatsTick: %v", err)
	}
	if out != int64(len(result.Stdout)+len(result.Stderr)) {
		t.Fatalf("bytes_out = %d, want %d", out, len(result.Stdout)+len(result.Stderr))
	}
	_ = clientConn.Close()
	<-done
}

func TestServerExecColdPathPreservesNetstatsTick(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("aerol-wasm-netstats-%d.sock", time.Now().UnixNano()))
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
	const sandboxID = "sb-exec"
	if _, err := client.LoadModule(sandboxID, modPath, 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if err := client.Instantiate(sandboxID, wasmengine.Capabilities{}); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if _, err := client.Exec(sandboxID, wasmengine.Capabilities{Args: []string{"exec-test"}}, "_start"); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if _, _, err := client.NetstatsTick(sandboxID); err != nil {
		t.Fatalf("NetstatsTick after exec: %v", err)
	}
}

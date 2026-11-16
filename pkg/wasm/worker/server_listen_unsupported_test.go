package worker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// noListenEngine is a minimal Engine whose SupportsListen() is false — as
// the wasmtime backend is for a module that exports no memory, or on a host
// other than Linux and macOS.
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

// TestSetListenPortRejectedWhenEngineLacksListen asserts that with the
// wasmtime listen fallback off (SB_WASM_WASMTIME_LISTEN_FALLBACK=false),
// enabling a wasip1 listener (HTTP ingress / expose_port) on an engine that
// cannot host one fails loudly with a clear error, rather than silently
// failing to resolve a port.
func TestSetListenPortRejectedWhenEngineLacksListen(t *testing.T) {
	t.Setenv(ListenFallbackEnv, "false")
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
	// The per-port message is refused the same way, and is not mistaken
	// for an older worker that does not know it.
	_, err = client.SetListenPorts(sandboxID, []int{8080}, "127.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "not supported") || errors.Is(err, ErrListenPortsUnsupported) {
		t.Fatalf("SetListenPorts on a no-listen engine = %v", err)
	}
	time.Sleep(10 * time.Millisecond)
}

// noListenServer is a worker whose engine cannot pre-open a listener (as
// wasmtime for a module it cannot serve), with a real module loaded the way
// load_module records it.
func noListenServer(t *testing.T) (*Server, *Client) {
	t.Helper()
	t.Setenv("AEROL_WASM_ENGINE", "wasmtime")
	srv := &Server{eng: noListenEngine{}}
	srv.loaded = loadedEngine{modulePath: writeMinimalModule(t, t.TempDir()), name: "wasmtime"}
	t.Cleanup(func() {
		srv.mu.Lock()
		eng := srv.eng
		srv.mu.Unlock()
		_ = eng.Close(context.Background())
	})
	c := NewClient("dummy")
	c.dial = func(string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() { _ = srv.Serve(c2) }()
		return c1, nil
	}
	return srv, c
}

// With the fallback on (the default), a sandbox on an engine that cannot
// pre-open a listener moves to wazero when it asks for one, serves there,
// and says which engine it runs.
func TestListenFallsBackToWazero(t *testing.T) {
	t.Setenv(ListenFallbackEnv, "")
	for _, perPort := range []bool{true, false} {
		srv, client := noListenServer(t)
		if perPort {
			got, err := client.SetListenPorts("sb-fallback", []int{8080, 9090}, "127.0.0.1")
			if err != nil {
				t.Fatalf("SetListenPorts: %v", err)
			}
			if got.Engine != "wazero" || got.FallbackFrom != "wasmtime" || got.Primary <= 0 || got.Ports[9090] <= 0 {
				t.Fatalf("report = %+v", got)
			}
		} else {
			if err := client.SetListenPort("sb-fallback", 0, "127.0.0.1"); err != nil {
				t.Fatalf("SetListenPort: %v", err)
			}
			port, err := client.ResolvedListenPort("sb-fallback")
			if err != nil || port <= 0 {
				t.Fatalf("ResolvedListenPort = %d, %v", port, err)
			}
		}
		srv.mu.Lock()
		_, multi := srv.eng.(wasmengine.MultiListenEngine)
		supports := srv.eng.SupportsListen()
		srv.mu.Unlock()
		if !multi || !supports {
			t.Fatalf("engine after the fallback = %T", srv.eng)
		}
		report, err := client.ListenPorts("sb-fallback")
		if err != nil || report.Engine != "wazero" || report.FallbackFrom != "wasmtime" {
			t.Fatalf("ListenPorts = %+v, %v", report, err)
		}
		// Loading the module again starts over on the configured engine.
		srv.mu.Lock()
		srv.noteLoadedLocked(loadModulePayload{Path: srv.loaded.modulePath}, nil)
		fallbackFrom := srv.loaded.fallbackFrom
		srv.mu.Unlock()
		if fallbackFrom != "" {
			t.Fatalf("fallback kept across a load: %q", fallbackFrom)
		}
	}
}

func TestListenFallbackFailures(t *testing.T) {
	t.Setenv(ListenFallbackEnv, "true")
	cases := []struct {
		name  string
		setup func(*Server)
		want  string
	}{
		{"no module loaded", func(s *Server) { s.loaded.modulePath = "" }, "no module loaded"},
		{"module unreadable", func(s *Server) { s.loaded.modulePath = filepath.Join(t.TempDir(), "gone.wasm") }, "serve HTTP on wazero"},
		{"no wazero engine", func(*Server) {
			newListenEngine = func(context.Context) (wasmengine.Engine, error) { return nil, errors.New("no engine") }
		}, "no engine"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := newListenEngine
			t.Cleanup(func() { newListenEngine = orig })
			srv, client := noListenServer(t)
			tc.setup(srv)
			_, err := client.SetListenPorts("sb-fallback", []int{8080}, "")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SetListenPorts = %v, want %q", err, tc.want)
			}
			// The sandbox keeps its engine.
			srv.mu.Lock()
			_, still := srv.eng.(noListenEngine)
			srv.mu.Unlock()
			if !still {
				t.Fatalf("engine replaced after a failed fallback: %T", srv.eng)
			}
		})
	}
}

func TestListenFallbackEnabled(t *testing.T) {
	for value, want := range map[string]bool{"": true, "true": true, "1": true, "false": false, "0": false, "bogus": true} {
		t.Setenv(ListenFallbackEnv, value)
		if got := listenFallbackEnabled(); got != want {
			t.Errorf("%q: listenFallbackEnabled = %v, want %v", value, got, want)
		}
	}
}

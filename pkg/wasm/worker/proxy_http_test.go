package worker

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

const minimalWasmHex = "0061736d0100000001040160000003020100070a01065f737461727400000a040102000b"

func startTestWorker(t *testing.T) (*Client, func()) {
	t.Helper()
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("aerol-wasm-proxy-%d.sock", time.Now().UnixNano()))
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv := &Server{}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) { _ = srv.Serve(c) }(conn)
		}
	}()
	client := NewClient(socketPath)
	cleanup := func() {
		close(done)
		_ = ln.Close()
		_ = os.Remove(socketPath)
		time.Sleep(10 * time.Millisecond)
	}
	return client, cleanup
}

func writeMinimalModule(t *testing.T, dir string) string {
	t.Helper()
	b, err := hex.DecodeString(minimalWasmHex)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "demo.wasm")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// sentinelListener listens on a loopback port and counts the connections it
// gets, for tests that a request's port number is never dialed.
func sentinelListener(t *testing.T) (port int, conns func() int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sentinel listen: %v", err)
	}
	var n atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return ln.Addr().(*net.TCPAddr).Port, n.Load
}

// The exposed port a request names is a routing key. Dialing it would reach
// whatever listens on that port on the host, so the worker must refuse the
// request when its guest has no listener rather than dial the port.
func TestProxyHTTPNeverDialsTheRequestedPort(t *testing.T) {
	client, cleanup := startTestWorker(t)
	defer cleanup()

	sandboxID := "sb-proxy"
	modPath := writeMinimalModule(t, t.TempDir())
	if _, err := client.LoadModule(sandboxID, modPath, 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	sentinel, conns := sentinelListener(t)

	if err := client.Instantiate(sandboxID, wasmengine.Capabilities{
		WASIListenPort: wasmengine.WASIListenPortDisabled,
		Args:           []string{"test"},
	}); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if err := client.SetListenPort(sandboxID, wasmengine.WASIListenPortDisabled, ""); err != nil {
		t.Fatalf("SetListenPort disable: %v", err)
	}

	for _, port := range []int{sentinel, 0} {
		req, err := http.NewRequest(http.MethodGet, "http://gateway/hello", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		rec := httptest.NewRecorder()
		err = client.ProxyHTTP(sandboxID, port, rec, req)
		if err == nil || !strings.Contains(err.Error(), "not listening") {
			t.Fatalf("ProxyHTTP(port %d) = %v (status %d), want a not-listening error", port, err, rec.Code)
		}
	}
	if n := conns(); n != 0 {
		t.Fatalf("sentinel on the requested port got %d connections, want 0", n)
	}
}

// A worker with a live listener sends every request to it, whatever port
// the request names.
func TestProxyHTTPGoesToTheEngineListenerOnly(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("from-guest"))
	}))
	defer backend.Close()
	sentinel, conns := sentinelListener(t)

	s := &Server{eng: &fakeNetworkAwareEngine{port: backend.Listener.Addr().(*net.TCPAddr).Port}}
	result, err := s.proxyGuestHTTPFromPayload(context.Background(), "sb", proxyHTTPPayload{
		GuestPort: sentinel, Method: http.MethodGet, RequestURI: "/",
	})
	if err != nil || string(result.Body) != "from-guest" {
		t.Fatalf("proxy = %q, %v", result.Body, err)
	}
	if n := conns(); n != 0 {
		t.Fatalf("sentinel on the requested port got %d connections, want 0", n)
	}
}

func TestSetListenPortDisabled(t *testing.T) {
	client, cleanup := startTestWorker(t)
	defer cleanup()

	sandboxID := "sb-listen"
	modPath := writeMinimalModule(t, t.TempDir())
	if _, err := client.LoadModule(sandboxID, modPath, 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if err := client.Instantiate(sandboxID, wasmengine.Capabilities{
		WASIListenPort: wasmengine.WASIListenPortDisabled,
		Args:           []string{"test"},
	}); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if err := client.SetListenPort(sandboxID, wasmengine.WASIListenPortDisabled, ""); err != nil {
		t.Fatalf("SetListenPort disable: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://gateway/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	rec := httptest.NewRecorder()
	err = client.ProxyHTTP(sandboxID, 8080, rec, req)
	if err == nil || !strings.Contains(err.Error(), "not listening") {
		t.Fatalf("ProxyHTTP = %v, want a not-listening error when nothing listens", err)
	}
}

func TestBuildProxyHTTPPayloadRejectsOversizedBody(t *testing.T) {
	body := make([]byte, maxProxyHTTPBody+1)
	req, err := http.NewRequest(http.MethodPost, "http://x/", io.NopCloser(io.LimitReader(&repeatReader{b: body}, int64(len(body)))))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := buildProxyHTTPPayload(8080, req); err == nil {
		t.Fatal("buildProxyHTTPPayload expected oversized body error")
	}
}

type repeatReader struct {
	b []byte
	i int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func TestProxyHTTPRecorder(t *testing.T) {
	rec := newLimitedProxyResponseRecorder(10) // tiny limit

	if rec.StatusCode() != http.StatusOK {
		t.Fatalf("expected default 200 OK")
	}

	rec.WriteHeader(http.StatusNotFound)
	if rec.StatusCode() != http.StatusNotFound {
		t.Fatalf("expected 404")
	}

	// Test normal write
	n, err := rec.Write([]byte("12345"))
	if err != nil || n != 5 {
		t.Fatalf("expected 5 bytes written")
	}

	// Test overflow
	n, err = rec.Write([]byte("6789012345"))
	if err != nil || n != 10 {
		t.Fatalf("expected write success")
	}
	if !rec.Overflowed() {
		t.Fatalf("expected overflowed=true")
	}

	body := rec.Body()
	if string(body) != "1234567890" {
		t.Fatalf("expected 10 bytes, got %q", string(body))
	}
}

func TestResolvedListenPort(t *testing.T) {
	c := NewClient("dummy")

	// Test OK
	c.dial = mockDialer(t, Envelope{Type: MsgOK, Payload: []byte(`{"port":8080}`)})
	port, err := c.ResolvedListenPort("dummy")
	if err != nil || port != 8080 {
		t.Fatalf("expected 8080")
	}

	// Test Not Found (no port or 0)
	c.dial = mockDialer(t, Envelope{Type: MsgOK, Payload: []byte(`{"port":0}`)})
	port, err = c.ResolvedListenPort("dummy")
	if err != nil || port != 0 {
		t.Fatalf("expected port 0 without error")
	}

	// Test Error
	payload, _ := encodePayload(errorPayload{Message: "boom"})
	c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: payload})
	_, err = c.ResolvedListenPort("dummy")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestProxyHTTPError(t *testing.T) {
	c := NewClient("dummy")
	payload, _ := encodePayload(errorPayload{Message: "proxy boom"})
	c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: payload})

	req, _ := http.NewRequest(http.MethodGet, "http://gateway/", nil)
	rec := httptest.NewRecorder()
	err := c.ProxyHTTP("dummy", 8080, rec, req)
	if err == nil {
		t.Fatalf("expected error from ProxyHTTP")
	}
}

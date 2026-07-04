package worker

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestProxyHTTPForwardsToGuestBackend(t *testing.T) {
	client, cleanup := startTestWorker(t)
	defer cleanup()

	sandboxID := "sb-proxy"
	modPath := writeMinimalModule(t, t.TempDir())
	if err := client.LoadModule(sandboxID, modPath, 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hello" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("from-guest"))
	}))
	defer backend.Close()

	host, portStr, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}
	_ = host

	if err := client.Instantiate(sandboxID, wasmengine.Capabilities{
		WASIListenPort: wasmengine.WASIListenPortDisabled,
		Args:           []string{"test"},
	}); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if err := client.SetListenPort(sandboxID, wasmengine.WASIListenPortDisabled, ""); err != nil {
		t.Fatalf("SetListenPort disable: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "http://gateway/hello", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	rec := httptest.NewRecorder()
	if err := client.ProxyHTTP(sandboxID, port, rec, req); err != nil {
		t.Fatalf("ProxyHTTP: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "from-guest" {
		t.Fatalf("body = %q", got)
	}
	in, out, err := client.NetstatsTick(sandboxID)
	if err != nil {
		t.Fatalf("NetstatsTick: %v", err)
	}
	if in == 0 || out == 0 {
		t.Fatalf("expected non-zero proxy byte counters in=%d out=%d", in, out)
	}
}

func TestSetListenPortDisabled(t *testing.T) {
	client, cleanup := startTestWorker(t)
	defer cleanup()

	sandboxID := "sb-listen"
	modPath := writeMinimalModule(t, t.TempDir())
	if err := client.LoadModule(sandboxID, modPath, 0); err != nil {
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
	if err != nil {
		t.Fatalf("ProxyHTTP: %v", err)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when nothing listens", rec.Code)
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

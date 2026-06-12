package wasm

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWasiSocketsHost(t *testing.T) {
	ctx := context.Background()
	dialer := &countingDialer{}
	hook := &NetworkHook{Dial: dialer}

	netHost := &wazeroNetHost{
		hook:  hook,
		conns: make(map[uint64]net.Conn),
	}

	host := &wasiSocketsHost{net: netHost}
	mod := &mockModule{mem: &mockMemory{buf: []byte("127.0.0.1:80")}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("ok"))
			c.Close()
		}
	}()

	addr := []byte(ln.Addr().String())
	mod.mem.buf = addr
	stack := []uint64{0, uint64(len(addr)), 0}

	// test tcpConnect
	host.tcpConnect(ctx, mod, stack)
	if int32(stack[0]) <= 0 {
		t.Fatalf("expected valid conn ID, got %v", int32(stack[0]))
	}
	connID := stack[0]

	// test streamRead
	readStack := []uint64{connID, 0, 2}
	host.streamRead(ctx, mod, readStack)
	if int32(readStack[0]) <= 0 {
		t.Fatalf("expected read bytes, got %v", int32(readStack[0]))
	}
	if string(mod.mem.buf[:2]) != "ok" {
		t.Fatalf("expected 'ok', got %s", string(mod.mem.buf[:2]))
	}

	// test streamWrite
	mod.mem.buf = append(mod.mem.buf, []byte("hello")...)
	writeStack := []uint64{connID, uint64(len(addr)), 5}
	host.streamWrite(ctx, mod, writeStack)
	if int32(writeStack[0]) != 5 {
		t.Fatalf("expected write 5 bytes, got %v", int32(writeStack[0]))
	}

	// test streamClose
	closeStack := []uint64{connID}
	host.streamClose(ctx, mod, closeStack)
	if closeStack[0] != 0 {
		t.Fatalf("expected close success, got %v", closeStack[0])
	}
}

func TestWasiHTTPHost(t *testing.T) {
	ctx := context.Background()
	dialer := &countingDialer{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	}))
	defer ts.Close()

	hook := &NetworkHook{Dial: dialer}
	netHost := &wazeroNetHost{
		hook:  hook,
		conns: make(map[uint64]net.Conn),
	}

	host := &wasiHTTPHost{net: netHost}

	// Setup memory big enough for url and response body
	memSize := 1024
	memBuf := make([]byte, memSize)
	urlBytes := []byte(ts.URL)
	copy(memBuf, urlBytes)

	mod := &mockModule{mem: &mockMemory{buf: memBuf}}

	// test httpGet success
	urlPtr := uint64(0)
	urlLen := uint64(len(urlBytes))
	bodyPtr := uint64(512)
	bodyMax := uint64(512)

	stack := []uint64{urlPtr, urlLen, bodyPtr, bodyMax}
	host.httpGet(ctx, mod, stack)

	resLen := int32(stack[0])
	if resLen != 11 {
		t.Fatalf("expected 11 bytes response, got %v", resLen)
	}

	resBody := string(mod.mem.buf[bodyPtr : bodyPtr+uint64(resLen)])
	if resBody != "hello world" {
		t.Fatalf("expected 'hello world', got '%s'", resBody)
	}

	// test httpGet with blocked hook (no dial)
	netHost.hook = nil
	host.httpGet(ctx, mod, stack)
	if stack[0] != 2 { // errBlocked
		t.Fatalf("expected errBlocked(2), got %v", stack[0])
	}

	// test invalid URL (not starting with http://)
	netHost.hook = hook
	invalidURL := []byte("https://example.com")
	copy(memBuf, invalidURL)
	stack = []uint64{0, uint64(len(invalidURL)), bodyPtr, bodyMax}
	host.httpGet(ctx, mod, stack)
	if stack[0] != 3 { // errRequest
		t.Fatalf("expected errRequest(3), got %v", stack[0])
	}
}

func TestWasiSocketsHost_Ensure(t *testing.T) {
	ctx := context.Background()
	e, _ := newWazeroEngine(ctx)
	defer e.Close(ctx)

	e.SetNetworkHook(&NetworkHook{Dial: &countingDialer{}})

	// Test runtime nil
	e.runtime = nil
	if err := e.ensureWasiSocketsHost(ctx); err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}

	// Re-init runtime to test instantiation
	e2, _ := newWazeroEngine(ctx)
	defer e2.Close(ctx)
	e2.SetNetworkHook(&NetworkHook{Dial: &countingDialer{}})
	if err := e2.ensureWasiSocketsHost(ctx); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	// Ensure again returns nil
	if err := e2.ensureWasiSocketsHost(ctx); err != nil {
		t.Fatalf("ensure again: %v", err)
	}
}

func TestWasiHTTPHost_Ensure(t *testing.T) {
	ctx := context.Background()
	e, _ := newWazeroEngine(ctx)
	defer e.Close(ctx)
	e.SetNetworkHook(&NetworkHook{Dial: &countingDialer{}})

	e.runtime = nil
	if err := e.ensureWasiHTTPHost(ctx); err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}

	e2, _ := newWazeroEngine(ctx)
	defer e2.Close(ctx)
	e2.SetNetworkHook(&NetworkHook{Dial: &countingDialer{}})
	if err := e2.ensureWasiHTTPHost(ctx); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := e2.ensureWasiHTTPHost(ctx); err != nil {
		t.Fatalf("ensure again: %v", err)
	}
}

func TestWasiHTTPHost_Errors(t *testing.T) {
	ctx := context.Background()
	hook := &NetworkHook{Dial: &countingDialer{}, Meter: &mockMeter{}}
	netHost := &wazeroNetHost{hook: hook}
	host := &wasiHTTPHost{net: netHost}

	memSize := 1024
	memBuf := make([]byte, memSize)
	mod := &mockModule{mem: &mockMemory{buf: memBuf}}

	// Test Out of Bounds URL Read
	stack := []uint64{2000, 2000, 0, 0}
	host.httpGet(ctx, mod, stack)

	// Test client.Get Error
	urlBytes := []byte("http://127.0.0.1:1") // connection refused
	copy(memBuf, urlBytes)
	stack = []uint64{0, uint64(len(urlBytes)), 512, 512}
	host.httpGet(ctx, mod, stack)
	if stack[0] != 3 { // errRequest
		t.Fatalf("expected errRequest(3), got %v", stack[0])
	}

	// Test client.Get Blocked Error
	netHost.hook.Dial = &mockBlockedDialer{}
	stack = []uint64{0, uint64(len(urlBytes)), 512, 512}
	host.httpGet(ctx, mod, stack)
	if stack[0] != 2 { // errBlocked
		t.Fatalf("expected errBlocked(2), got %v", stack[0])
	}
	netHost.hook.Dial = &countingDialer{}

	// Test Write Error (out of bounds write)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	}))
	defer ts.Close()
	urlBytes = []byte(ts.URL)
	copy(memBuf, urlBytes)
	stack = []uint64{0, uint64(len(urlBytes)), 2000, 512} // bodyPtr out of bounds
	host.httpGet(ctx, mod, stack)
	if stack[0] != 1 { // errInvalid
		t.Fatalf("expected errInvalid(1), got %v", stack[0])
	}
}

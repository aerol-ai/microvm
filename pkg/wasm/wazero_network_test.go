package wasm

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type countingDialer struct {
	bytesOut atomic.Int64
}

func (d *countingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: conn, out: &d.bytesOut}, nil
}

type countingConn struct {
	net.Conn
	out *atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.out.Add(int64(n))
	}
	return n, err
}

func TestWazeroEngineNetworkHookDial(t *testing.T) {
	ctx := context.Background()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("ok"))
	}()

	e, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer func() { _ = e.Close(ctx) }()

	dialer := &countingDialer{}
	e.SetNetworkHook(&NetworkHook{
		SandboxID: "sb-hook",
		Dial:      dialer,
	})
	if err := e.ensureNetworkHost(ctx); err != nil {
		t.Fatalf("ensureNetworkHost: %v", err)
	}

	conn, err := dialer.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if dialer.bytesOut.Load() != 0 {
		t.Fatalf("expected no outbound bytes on read-only client path")
	}
}

func TestWazeroEngineImplementsNetworkAware(t *testing.T) {
	ctx := context.Background()
	e, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer func() { _ = e.Close(ctx) }()
	if _, ok := any(e).(NetworkAwareEngine); !ok {
		t.Fatal("wazeroEngine should implement NetworkAwareEngine")
	}
}

func TestWazeroNetHost_tcpDial(t *testing.T) {
	ctx := context.Background()
	dialer := &countingDialer{}
	hook := &NetworkHook{Dial: dialer}
	host := &wazeroNetHost{
		hook:  hook,
		conns: make(map[uint64]net.Conn),
	}

	mod := &mockModule{mem: &mockMemory{buf: []byte("127.0.0.1:80")}}
	stack := []uint64{0, 12, 0}

	// Test without dialer (errBlocked)
	host.hook = nil
	host.tcpDial(ctx, mod, stack)
	if stack[0] != 3 { // errBlocked
		t.Fatalf("expected errBlocked(3), got %v", stack[0])
	}

	// Test valid dial
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

	host.hook = hook
	addr := []byte(ln.Addr().String())
	mod.mem.buf = addr
	stack = []uint64{0, uint64(len(addr)), 0}
	host.tcpDial(ctx, mod, stack)

	if int32(stack[0]) <= 0 {
		t.Fatalf("expected valid conn ID, got %v", int32(stack[0]))
	}
	connID := stack[0]

	// Test read
	readStack := []uint64{connID, 0, 2}
	host.tcpRead(ctx, mod, readStack)
	if int32(readStack[0]) <= 0 {
		t.Fatalf("expected read bytes, got %v", int32(readStack[0]))
	}
	if string(mod.mem.buf[:2]) != "ok" {
		t.Fatalf("expected 'ok', got %s", string(mod.mem.buf[:2]))
	}

	// Test write
	mod.mem.buf = append(mod.mem.buf, []byte("hello")...)
	writeStack := []uint64{connID, uint64(len(addr)), 5}
	host.tcpWrite(ctx, mod, writeStack)
	if int32(writeStack[0]) != 5 {
		t.Fatalf("expected write 5 bytes, got %v", int32(writeStack[0]))
	}

	// Wait for remote to close
	time.Sleep(10 * time.Millisecond)

	// Test second read (remote closed -> EOF -> err!=nil)
	readStack[0] = connID
	host.tcpRead(ctx, mod, readStack)

	// Test second write (remote closed -> err!=nil)
	writeStack[0] = connID
	host.tcpWrite(ctx, mod, writeStack)

	// Test close
	closeStack := []uint64{connID}
	host.tcpClose(ctx, mod, closeStack)
	if closeStack[0] != 0 {
		t.Fatalf("expected close success, got %v", closeStack[0])
	}

	// Test read on locally closed (conn == nil)
	readStack[0] = connID
	host.tcpRead(ctx, mod, readStack)
	if readStack[0] != 2 { // errClosed
		t.Fatalf("expected errClosed, got %v", readStack[0])
	}

	// Test write on locally closed (conn == nil)
	writeStack[0] = connID
	host.tcpWrite(ctx, mod, writeStack)
	if writeStack[0] != 2 { // errClosed
		t.Fatalf("expected errClosed, got %v", writeStack[0])
	}
	if closeStack[0] != 0 {
	}
}

type mockMeter struct {
	in  atomic.Int64
	out atomic.Int64
}

func (m *mockMeter) AddIn(n int64) {
	m.in.Add(n)
}

func (m *mockMeter) AddOut(n int64) {
	m.out.Add(n)
}

func TestWazeroNetHost_tcpDial_Errors(t *testing.T) {
	ctx := context.Background()
	dialer := &countingDialer{}
	hook := &NetworkHook{Dial: dialer}
	host := &wazeroNetHost{
		hook:  hook,
		conns: make(map[uint64]net.Conn),
	}

	mod := &mockModule{mem: &mockMemory{buf: []byte("127.0.0.1:80")}}
	stack := []uint64{0, 12, 0}

	// Test Memory Read Out of Bounds
	host.tcpDial(ctx, mod, []uint64{1000, 1000, 0})

	// Test Dial Error
	mod.mem.buf = []byte("invalid-address")
	stack = []uint64{0, uint64(len("invalid-address")), 0}
	host.tcpDial(ctx, mod, stack)
	if stack[0] != 2 { // errDial
		t.Fatalf("expected errDial(2), got %v", stack[0])
	}

	// Test Egress Blocked
}

type mockBlockedDialer struct{}

func (m *mockBlockedDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	return nil, ErrNetworkEgressBlocked
}

func TestWazeroNetHost_tcpDial_Blocked(t *testing.T) {
	ctx := context.Background()
	hook := &NetworkHook{Dial: &mockBlockedDialer{}}
	host := &wazeroNetHost{
		hook:  hook,
		conns: make(map[uint64]net.Conn),
	}
	mod := &mockModule{mem: &mockMemory{buf: []byte("127.0.0.1:80")}}
	stack := []uint64{0, 12, 0}
	host.tcpDial(ctx, mod, stack)
	if stack[0] != 3 { // errBlocked
		t.Fatalf("expected errBlocked(3), got %v", stack[0])
	}
}

func TestWazeroNetHost_tcpReadWrite_Errors(t *testing.T) {
	ctx := context.Background()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	meter := &mockMeter{}
	dialer := &countingDialer{}
	hook := &NetworkHook{Dial: dialer, Meter: meter}
	host := &wazeroNetHost{
		hook:  hook,
		conns: make(map[uint64]net.Conn),
	}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close() // immediately close to cause read/write errors
		}
	}()

	mod := &mockModule{mem: &mockMemory{buf: []byte(ln.Addr().String())}}
	stack := []uint64{0, uint64(len(ln.Addr().String())), 0}
	host.tcpDial(ctx, mod, stack)
	connID := stack[0]

	// Test read memory out of bounds
	host.tcpRead(ctx, mod, []uint64{connID, 1000, 1000})

	// Test write memory out of bounds
	host.tcpWrite(ctx, mod, []uint64{connID, 1000, 1000})

	// Test hookMeter
	if m := host.hookMeter(); m == nil {
		t.Fatalf("expected meter")
	}
	host.hook = nil
	if m := host.hookMeter(); m != nil {
		t.Fatalf("expected nil meter")
	}
}

func TestEnsureNetworkHost_Multiple(t *testing.T) {
	ctx := context.Background()
	e, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(ctx)

	e.SetNetworkHook(&NetworkHook{Dial: &countingDialer{}})
	e.initRuntime(ctx, 128)

	err = e.ensureNetworkHost(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = e.ensureNetworkHost(ctx)
	if err != nil {
		t.Fatal(err)
	}
}

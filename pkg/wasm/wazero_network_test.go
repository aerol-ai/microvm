package wasm

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
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

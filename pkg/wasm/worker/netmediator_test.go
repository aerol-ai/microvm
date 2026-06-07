package worker

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
)

func TestNetMediatorDialCountsBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	m := newNetMediator()
	const sandboxID = "sb-sock"
	conn, err := m.DialContext(context.Background(), sandboxID, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = conn.Close()

	in, out := m.DrainUsage(sandboxID)
	if out < 4 {
		t.Fatalf("bytes_out = %d, want >= 4", out)
	}
	if in < 4 {
		t.Fatalf("bytes_in = %d, want >= 4", in)
	}
}

func TestNetMediatorBlocksEgressDial(t *testing.T) {
	m := newNetMediator()
	const sandboxID = "sb-block"
	m.SetBlocks(sandboxID, false, true)
	if _, err := m.DialContext(context.Background(), sandboxID, "tcp", "127.0.0.1:9"); err == nil {
		t.Fatal("expected egress block error")
	} else if !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("error = %v", err)
	}
}

func TestServerSetNetworkBlocksViaIPC(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	srv := &Server{}
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(serverConn)
	}()

	c := NewClient("")
	c.dial = func(string) (net.Conn, error) { return clientConn, nil }

	if err := c.SetNetworkBlocks("sb-1", false, true); err != nil {
		t.Fatalf("SetNetworkBlocks: %v", err)
	}
	if !srv.mediator().egressBlocked("sb-1") {
		t.Fatal("expected egress block on worker mediator")
	}
	_ = clientConn.Close()
	<-done
}

package service

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProbeSSHGatewaySucceedsWhenListenerAccepts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	if err := probeSSHGateway(context.Background(), ln.Addr().String()); err != nil {
		t.Fatalf("probeSSHGateway: %v", err)
	}
}

func TestProbeSSHGatewayFailsWhenNothingListening(t *testing.T) {
	// Pick a port, close the listener, then probe — guaranteed connection refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	// Give the kernel a beat to mark the port as not listening.
	time.Sleep(50 * time.Millisecond)

	err = probeSSHGateway(context.Background(), addr)
	if err == nil {
		t.Fatal("expected probe to fail with no listener")
	}
	if !strings.Contains(err.Error(), "ssh gateway dial") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProbeSSHGatewayRejectsEmptyAddr(t *testing.T) {
	if err := probeSSHGateway(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty addr")
	}
}

func TestProbeSSHGatewayRejectsInvalidAddr(t *testing.T) {
	if err := probeSSHGateway(context.Background(), "no-port"); err == nil {
		t.Fatal("expected error for invalid addr")
	}
}

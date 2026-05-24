package service

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// TestDialL4UpstreamRetriesOnConnRefused: the kernel returns ECONNREFUSED
// instantly when a port is not bound, so a single dial races the
// in-container process bind on every cold start. The retry helper must
// keep trying until the listener accepts or the budget runs out.
//
// Mirrors the HTTP ingress upstream-readiness probe so raw-TCP and
// TLS-SNI L4 routes do not 502 their callers when an idle-stopped
// sandbox is waking.
func TestDialL4UpstreamRetriesOnConnRefused(t *testing.T) {
	// Reserve a port without listening, so dials get ECONNREFUSED.
	scout, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("scout listen: %v", err)
	}
	addr := scout.Addr().String()
	_ = scout.Close()

	// Start the real listener ~150ms later, modelling the cold-start
	// gap between Docker reporting "running" and the user's process
	// binding its port.
	listenerUp := make(chan struct{})
	go func() {
		time.Sleep(150 * time.Millisecond)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Errorf("late listen: %v", err)
			close(listenerUp)
			return
		}
		t.Cleanup(func() { _ = ln.Close() })
		close(listenerUp)
		// Keep accepting so the dial completes cleanly.
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	start := time.Now()
	conn, err := dialL4Upstream(context.Background(), addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
	<-listenerUp
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("dial returned in %v — should have waited for listener to come up", elapsed)
	}
}

// TestDialL4UpstreamReturnsLastErrOnTimeout: when the port never binds
// within the readiness window, the helper must surface the underlying
// ECONNREFUSED rather than swallow it as a deadline error so the
// "dial l4 wake upstream failed" log line stays diagnostic.
func TestDialL4UpstreamReturnsLastErrOnTimeout(t *testing.T) {
	scout, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("scout: %v", err)
	}
	addr := scout.Addr().String()
	_ = scout.Close()

	_, err = dialL4Upstream(context.Background(), addr, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("error = %v, want ECONNREFUSED", err)
	}
}

// TestDialL4UpstreamBailsOnCancelledContext: a cancelled caller
// context must surface immediately — the readiness retry must not
// keep dialling against a dead caller.
func TestDialL4UpstreamBailsOnCancelledContext(t *testing.T) {
	scout, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("scout: %v", err)
	}
	addr := scout.Addr().String()
	_ = scout.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err = dialL4Upstream(ctx, addr, 5*time.Second)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("dial took %v with cancelled context — should bail fast", elapsed)
	}
}

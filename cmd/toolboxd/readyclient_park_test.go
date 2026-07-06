//go:build linux

package main

import (
	"bufio"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/readyproto"
)

func TestParkedReadyOnConn(t *testing.T) {
	oldStart := startUserCommandFn
	var started []string
	startUserCommandFn = func(_ *slog.Logger, args []string) {
		started = append([]string(nil), args...)
	}
	t.Cleanup(func() { startUserCommandFn = oldStart })

	srv := &server{
		logger:      slog.Default(),
		deferredCmd: []string{"echo", "hi"},
		parkedMode:  true,
	}

	guest, host := net.Pipe()
	defer guest.Close()
	defer host.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		br := bufio.NewReader(host)
		if _, err := readyproto.DecodeParked(br); err != nil {
			t.Errorf("decode parked: %v", err)
			return
		}
		if err := readyproto.EncodeAdopt(host, readyproto.AdoptFrame{
			Event: readyproto.EventAdopt, SandboxID: "sb-1", Token: "real-tok", Nonce: "adopt-n",
		}); err != nil {
			t.Errorf("encode adopt: %v", err)
			return
		}
		if _, err := readyproto.Decode(br); err != nil {
			t.Errorf("decode ready: %v", err)
		}
	}()

	if err := parkedReadyOnConn(slog.Default(), srv, guest, "boot-tok", "park-n"); err != nil {
		t.Fatalf("parkedReadyOnConn: %v", err)
	}
	wg.Wait()

	if !srv.servingRequests() || srv.sandboxID != "sb-1" {
		t.Fatalf("server not adopted: id=%q serving=%v", srv.sandboxID, srv.servingRequests())
	}
	if len(started) != 2 || started[0] != "echo" || started[1] != "hi" {
		t.Fatalf("deferred command = %v", started)
	}
}

func TestRunParkedReadyHandshakeNoop(t *testing.T) {
	runParkedReadyHandshake(slog.Default(), nil, "", "tok", "n")
	runParkedReadyHandshake(slog.Default(), &server{}, "  ", "tok", "n")
}

func TestParkedReadyOnConnValidation(t *testing.T) {
	if err := parkedReadyOnConn(nil, &server{}, nil, "t", "n"); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestServingRequestsParkedMode(t *testing.T) {
	srv := &server{parkedMode: true}
	if srv.servingRequests() {
		t.Fatal("pre-adopt should block")
	}
	srv.adoptIdentity("sb", "tok")
	if !srv.servingRequests() {
		t.Fatal("post-adopt should serve")
	}
}

func TestDialParkReadyBounded(t *testing.T) {
	start := time.Now()
	runParkedReadyHandshake(slog.Default(), &server{parkedMode: true}, "/nonexistent.sock", "tok", "n")
	if time.Since(start) > 4*time.Second {
		t.Fatal("handshake exceeded bounded dial timeout")
	}
}

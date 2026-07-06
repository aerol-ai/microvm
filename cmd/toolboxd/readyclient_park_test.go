//go:build linux

package main

import (
	"bufio"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/readyproto"
)

func shortToolboxTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestRunParkedReadyHandshake(t *testing.T) {
	sockPath := shortToolboxTestDir(t) + "/host.sock"
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := &server{
		logger:      slog.Default(),
		deferredCmd: []string{"echo", "hi"},
		parkedMode:  true,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runParkedReadyHandshake(slog.Default(), srv, sockPath, "boot-tok", "park-n")
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()

	br := bufio.NewReader(conn)
	if _, err := readyproto.DecodeParked(br); err != nil {
		t.Fatalf("decode parked: %v", err)
	}
	if err := readyproto.EncodeAdopt(conn, readyproto.AdoptFrame{
		Event: readyproto.EventAdopt, SandboxID: "sb-1", Token: "real-tok", Nonce: "adopt-n",
	}); err != nil {
		t.Fatalf("encode adopt: %v", err)
	}
	sig, err := readyproto.Decode(br)
	if err != nil {
		t.Fatalf("decode ready ack: %v", err)
	}
	if sig.SandboxID != "sb-1" || sig.Token != "real-tok" || sig.Nonce != "adopt-n" {
		t.Fatalf("ready ack = %+v", sig)
	}

	wg.Wait()

	if !srv.servingRequests() || srv.sandboxID != "sb-1" {
		t.Fatalf("server not adopted: id=%q serving=%v", srv.sandboxID, srv.servingRequests())
	}
}

func TestRunParkedReadyHandshakeNoop(t *testing.T) {
	runParkedReadyHandshake(slog.Default(), nil, "", "tok", "n")
	runParkedReadyHandshake(slog.Default(), &server{}, "  ", "tok", "n")
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

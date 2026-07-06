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

func TestRunParkedReadyHandshake(t *testing.T) {
	ln, err := net.Listen("unix", t.TempDir()+"/host.sock")
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
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := readyproto.DecodeParked(bufio.NewReader(conn)); err != nil {
			t.Errorf("parked: %v", err)
			return
		}
		_ = readyproto.EncodeAdopt(conn, readyproto.AdoptFrame{
			Event: readyproto.EventAdopt, SandboxID: "sb-1", Token: "real-tok", Nonce: "adopt-n",
		})
		sig, err := readyproto.Decode(bufio.NewReader(conn))
		if err != nil || sig.SandboxID != "sb-1" {
			t.Errorf("ready ack: %+v err=%v", sig, err)
		}
	}()

	runParkedReadyHandshake(slog.Default(), srv, ln.Addr().String(), "boot-tok", "park-n")
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

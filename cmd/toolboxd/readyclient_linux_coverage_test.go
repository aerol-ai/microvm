//go:build linux

package main

import (
	"bufio"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/readyproto"
)

func TestLinuxAnnounceReadyCoverage(t *testing.T) {
	announceReady(slog.Default(), "", "tok", "nonce", "/tmp/nope.sock")
	announceReady(slog.Default(), "sb", "", "nonce", "/tmp/nope.sock")
	announceReady(slog.Default(), "sb", "tok", "nonce", "")
	scrubReadyEnv()
	runParkedReadyHandshake(slog.Default(), &server{parkedMode: true}, "", "tok", "n")
	runParkedReadyHandshake(slog.Default(), &server{parkedMode: true}, "/nonexistent-ready.sock", "tok", "n")

	// dialReadySocket missing fields + successful write.
	dialReadySocket(slog.Default(), "  ", "sb", "tok", "n")
	dialReadySocket(slog.Default(), "/tmp/x.sock", "", "tok", "n")
	dialReadySocket(slog.Default(), "/tmp/x.sock", "sb", "", "n")
	dialReadySocket(slog.Default(), "/nonexistent.sock", "sb", "tok", "n")

	dir := t.TempDir()
	sock := filepath.Join(dir, "ready.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = readyproto.Decode(bufio.NewReader(c))
	}()
	dialReadySocket(slog.Default(), sock, "sb", "tok", "nonce")
	time.Sleep(50 * time.Millisecond)

	// Park handshake error paths.
	if err := parkedReadyOnConn(slog.Default(), &server{}, nil, "t", "n"); err == nil {
		t.Fatal("expected nil conn error")
	}
	gBlank, hBlank := net.Pipe()
	_ = hBlank.Close()
	_ = gBlank.Close()
	if err := parkedReadyOnConn(slog.Default(), &server{}, gBlank, " ", " "); err == nil {
		t.Fatal("expected blank token/nonce error")
	}
	guest, host := net.Pipe()
	_ = host.Close()
	if err := parkedReadyOnConn(slog.Default(), &server{logger: slog.Default()}, guest, "tok", "nonce"); err == nil {
		t.Fatal("expected parked write/adopt failure on closed peer")
	}
	_ = guest.Close()

	guest2, host2 := net.Pipe()
	t.Cleanup(func() { _ = guest2.Close(); _ = host2.Close() })
	go func() {
		br := bufio.NewReader(host2)
		_, _ = readyproto.DecodeParked(br)
		_ = host2.Close() // fail adopt read
	}()
	if err := parkedReadyOnConn(slog.Default(), &server{logger: slog.Default()}, guest2, "tok", "nonce"); err == nil {
		t.Fatal("expected adopt read failure")
	}

	guest3, host3 := net.Pipe()
	t.Cleanup(func() { _ = guest3.Close(); _ = host3.Close() })
	go func() {
		br := bufio.NewReader(host3)
		_, _ = readyproto.DecodeParked(br)
		_ = readyproto.EncodeAdopt(host3, readyproto.AdoptFrame{
			Event: readyproto.EventAdopt, SandboxID: "sb", Token: "tok", Nonce: "n",
		})
		_ = host3.Close() // fail ready ack write
	}()
	if err := parkedReadyOnConn(slog.Default(), &server{logger: slog.Default()}, guest3, "tok", "nonce"); err == nil {
		t.Fatal("expected ready ack failure")
	}
}

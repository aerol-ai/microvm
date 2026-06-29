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

func TestAnnounceReadyWritesValidSignal(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/ready.sock"
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.Close()
		sig, err := readyproto.Decode(bufio.NewReader(conn))
		if err != nil {
			t.Errorf("decode: %v", err)
			return
		}
		if sig.SandboxID != "sb-1" || sig.Token != "tok" || sig.Nonce != "nonce-1" {
			t.Errorf("signal = %+v", sig)
		}
	}()

	dialReadySocket(slog.Default(), sockPath, "sb-1", "tok", "nonce-1")
	wg.Wait()
}

func TestAnnounceReadyNoopWhenUnset(t *testing.T) {
	announceReady(slog.Default(), "sb", "tok", "nonce", "")
}

func TestScrubReadyEnv(t *testing.T) {
	t.Setenv("SB_READY_SOCKET", "/run/aerol/ready.sock")
	t.Setenv("SB_READY_NONCE", "n")
	scrubReadyEnv()
	if os.Getenv("SB_READY_SOCKET") != "" || os.Getenv("SB_READY_NONCE") != "" {
		t.Fatal("expected env scrubbed")
	}
}

func TestDialReadySocketBounded(t *testing.T) {
	start := time.Now()
	dialReadySocket(slog.Default(), "/nonexistent/path.sock", "sb", "tok", "nonce")
	if time.Since(start) > readyDialTimeout+time.Second {
		t.Fatal("dial exceeded bounded timeout")
	}
}

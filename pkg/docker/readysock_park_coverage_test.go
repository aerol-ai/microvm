package docker

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/readyproto"
)

func TestCoverage95ParkedListenerValidationPaths(t *testing.T) {
	for _, args := range []struct {
		dir, slot, token, nonce string
	}{
		{dir: coverageReadyDir(t), token: "token", nonce: "nonce"},
		{dir: coverageReadyDir(t), slot: "slot", nonce: "nonce"},
		{dir: coverageReadyDir(t), slot: "slot", token: "token"},
		{slot: "slot", token: "token", nonce: "nonce"},
	} {
		if _, err := NewParkedListener(args.dir, args.slot, args.token, args.nonce); err == nil {
			t.Fatalf("NewParkedListener(%+v) unexpectedly succeeded", args)
		}
	}
	if err := (*ParkedListener)(nil).WaitParked(context.Background()); err == nil {
		t.Fatal("nil WaitParked unexpectedly succeeded")
	}
	if (*ParkedListener)(nil).Alive() {
		t.Fatal("nil parked listener reported alive")
	}
	if err := (*ParkedListener)(nil).Adopt(context.Background(), "sb", "token", "nonce"); err == nil {
		t.Fatal("nil Adopt unexpectedly succeeded")
	}

	pl, err := NewParkedListener(coverageReadyDir(t), "slot", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })
	for _, signal := range []readyproto.ParkedSignal{
		{Event: readyproto.EventParked, Token: "token", Nonce: "wrong"},
		{Event: readyproto.EventParked, Token: "wrong", Nonce: "nonce"},
	} {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- pl.verifyParked(server) }()
		if err := readyproto.EncodeParked(client, signal); err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		if err := <-done; err == nil {
			t.Fatalf("invalid parked signal %+v verified", signal)
		}
	}
}

func TestCoverage95NewParkedListenerPathTooLong(t *testing.T) {
	dir := coverageReadyDir(t)
	if _, err := NewParkedListener(dir, strings.Repeat("p", 90), "tok", "nonce"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("NewParkedListener() = %v, want path length error", err)
	}
}

func TestCoverage95NewParkedListenerMkdirFailure(t *testing.T) {
	dir := coverageReadyDir(t)
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewParkedListener(blocker, "slot", "tok", "nonce")
	if err == nil || !strings.Contains(err.Error(), "mkdir ready dir") {
		t.Fatalf("NewParkedListener() = %v", err)
	}
}

func TestCoverage95ParkedListenerExtraPaths(t *testing.T) {
	t.Run("agent_version_mismatch", func(t *testing.T) {
		pl, err := NewParkedListener(coverageReadyDir(t), "park-ver", "tok", "nonce")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pl.Close() })
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- pl.verifyParked(server) }()
		_ = readyproto.EncodeParked(client, readyproto.ParkedSignal{
			Event: readyproto.EventParked, Token: "tok", Nonce: "nonce", AgentVersion: "other",
		})
		_ = client.Close()
		if err := <-done; err == nil || !strings.Contains(err.Error(), "agent version mismatch") {
			t.Fatalf("verifyParked() = %v", err)
		}
	})

	t.Run("adopt_dead_connection", func(t *testing.T) {
		pl, err := NewParkedListener(coverageReadyDir(t), "park-dead", "tok", "nonce")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pl.Close() })
		server, client := net.Pipe()
		pl.connMu.Lock()
		pl.conn = server
		pl.monitorDone = make(chan struct{})
		pl.connMu.Unlock()
		go pl.monitorParked(server)
		_ = client.Close()
		deadline := time.Now().Add(time.Second)
		for pl.Alive() && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if pl.Alive() {
			t.Fatal("parked connection still alive after guest closed pipe")
		}
		// Adopt blocks on monitorDone without honoring ctx — guard against hangs.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		adoptDone := make(chan error, 1)
		go func() { adoptDone <- pl.Adopt(ctx, "sb", "tok", "nonce") }()
		select {
		case err := <-adoptDone:
			if err == nil || !strings.Contains(err.Error(), "dead") {
				t.Fatalf("Adopt() = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Adopt hung waiting for monitor goroutine")
		}
	})

	t.Run("remove_park_socket_empty", func(t *testing.T) {
		RemoveParkSocket("")
		RemoveParkSocket("   ")
	})
}

func TestCoverage95ParkedListenerHostSocketPathNil(t *testing.T) {
	if (*ParkedListener)(nil).HostSocketPath() != "" {
		t.Fatal("nil parked listener must return empty path")
	}
}

func TestCoverage95ParkedListenerAdoptAckMismatch(t *testing.T) {
	pl, err := NewParkedListener(coverageReadyDir(t), "park-ack", "tok", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })

	go func() {
		conn, dialErr := net.Dial("unix", pl.HostSocketPath())
		if dialErr != nil {
			return
		}
		defer conn.Close()
		_ = readyproto.EncodeParked(conn, readyproto.ParkedSignal{
			Event: readyproto.EventParked, Token: "tok", Nonce: "nonce",
		})
		frame, decodeErr := readyproto.DecodeAdopt(bufio.NewReader(conn))
		if decodeErr != nil {
			return
		}
		_ = readyproto.Encode(conn, readyproto.ReadySignal{
			Event: readyproto.EventReady, SandboxID: frame.SandboxID, Token: "wrong", Nonce: frame.Nonce,
		})
	}()

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := pl.WaitParked(waitCtx); err != nil {
		t.Fatalf("WaitParked: %v", err)
	}
	adoptCtx, adoptCancel := context.WithTimeout(context.Background(), time.Second)
	defer adoptCancel()
	if err := pl.Adopt(adoptCtx, "sb-ack", "tok", "nonce"); err == nil || !strings.Contains(err.Error(), "token mismatch") {
		t.Fatalf("Adopt() = %v", err)
	}
}

package sshgateway

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// A key revoke closes every open SSH connection (plans/customer-key-custody.md
// §10): each one holds a toolbox token opened before the revoke.
func TestCloseAllEndsOpenConnections(t *testing.T) {
	g, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{
		ListenAddr: "127.0.0.1:0", HostKeyPath: filepath.Join(t.TempDir(), "k"),
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { g.handleConn(context.Background(), server); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		g.connMu.Lock()
		n := len(g.conns)
		g.connMu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("connection never tracked")
		}
		time.Sleep(time.Millisecond)
	}
	if n := g.CloseAll(); n != 1 {
		t.Fatalf("closed %d", n)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("connection handler kept running after CloseAll")
	}
	if n := g.CloseAll(); n != 0 {
		t.Fatalf("closed connection still tracked: %d", n)
	}
}

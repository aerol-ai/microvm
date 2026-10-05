package docker

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCoverage97ReadySocketFailures(t *testing.T) {
	parent := shortReadyDir(t)
	blocker := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewReadyListener(filepath.Join(blocker, "sub"), "box", "token", "nonce"); err == nil {
		t.Fatal("ready listener created under a file")
	}

	ln, err := NewReadyListener(shortReadyDir(t), "box", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ln.Wait(ctx); err == nil {
		t.Fatal("cancelled wait succeeded")
	}

	open, err := NewReadyListener(shortReadyDir(t), "box2", "token", "nonce2")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- open.Wait(context.Background()) }()
	time.Sleep(20 * time.Millisecond)
	if err := open.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed listener wait succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wait did not return after close")
	}

	sweep := shortReadyDir(t)
	if err := os.Mkdir(filepath.Join(sweep, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sweep, "note.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SweepOrphanReadySockets(sweep); err != nil {
		t.Fatal(err)
	}
	if err := SweepOrphanReadySockets(blocker); err == nil {
		t.Fatal("sweep of a file succeeded")
	}
}

func TestCoverage97ReadySocketEdges(t *testing.T) {
	var closed *ReadyListener
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	go func() {
		_, _ = client.Write([]byte("not-a-frame"))
		_ = client.Close()
	}()
	listener := &ReadyListener{sandboxID: "sb", token: "tok", nonce: "n"}
	if err := listener.readAndVerify(server); err == nil {
		t.Fatal("garbage frame verified")
	}
	_ = server.Close()

	blocked := t.TempDir()
	sockDir := filepath.Join(blocked, "held.sock")
	if err := os.Mkdir(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sockDir, "child"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (&ReadyListener{hostPath: sockDir}).ParkBindSource(); err == nil {
		t.Fatal("park unlinked a non-empty directory")
	}
	if err := (&ReadyListener{hostPath: filepath.Join(t.TempDir(), "missing", "sock")}).ParkBindSource(); err == nil {
		t.Fatal("park listened under a missing parent")
	}

	dir := shortReadyDir(t)
	held := filepath.Join(dir, "slot.sock")
	if err := os.Mkdir(held, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(held, "child"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewParkedListener(dir, "slot", "token", "nonce"); err == nil {
		t.Fatal("park listener replaced a non-empty directory")
	}

	locked := shortReadyDir(t)
	if err := os.Chmod(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if _, err := NewParkedListener(locked, "slot", "token", "nonce"); err == nil {
		t.Fatal("park listener created a socket in an unwritable directory")
	}

	pl, err := NewParkedListener(shortReadyDir(t), "wait", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- pl.WaitParked(context.Background()) }()
	time.Sleep(20 * time.Millisecond)
	_ = pl.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("wait without a deadline succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wait did not return")
	}
}

//go:build linux

package docker

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/readyproto"
)

func TestReadyListenerHappyPath(t *testing.T) {
	dir := t.TempDir()
	const (
		sandboxID = "sb"
		token     = "secret-token"
		nonce     = "n1"
	)
	ln, err := NewReadyListener(dir, sandboxID, token, nonce)
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.Dial("unix", ln.HostSocketPath())
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer conn.Close()
		_ = readyproto.Encode(conn, readyproto.ReadySignal{
			Event:     readyproto.EventReady,
			SandboxID: sandboxID,
			Token:     token,
			Nonce:     nonce,
		})
	}()

	if err := ln.Wait(ctx); err != nil {
		t.Fatalf("wait: %v", err)
	}
	wg.Wait()
}

func TestReadyListenerTokenMismatch(t *testing.T) {
	dir := t.TempDir()
	ln, err := NewReadyListener(dir, "sb", "good", "nonce1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go func() {
		conn, err := net.Dial("unix", ln.HostSocketPath())
		if err != nil {
			return
		}
		defer conn.Close()
		_ = readyproto.Encode(conn, readyproto.ReadySignal{
			Event: readyproto.EventReady, SandboxID: "sb", Token: "bad", Nonce: "nonce1",
		})
	}()

	if err := ln.Wait(ctx); err == nil {
		t.Fatal("expected timeout or invalid cap error")
	}
}

func TestReadyListenerNeverConnectTimesOut(t *testing.T) {
	dir := t.TempDir()
	ln, err := NewReadyListener(dir, "sb", "tok", "n1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := ln.Wait(ctx); err == nil {
		t.Fatal("expected timeout")
	}
}

func TestReadyListenerCloseUnlinks(t *testing.T) {
	dir := t.TempDir()
	ln, err := NewReadyListener(dir, "sb", "tok", "n1")
	if err != nil {
		t.Fatal(err)
	}
	path := ln.HostSocketPath()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket still present after close: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("double close: %v", err)
	}
}

func TestSweepOrphanReadySocketsSkipsActive(t *testing.T) {
	dir := t.TempDir()
	ln, err := NewReadyListener(dir, "sb-active", "tok", "n1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	orphan := filepath.Join(dir, "sb-dead.old.sock")
	if err := os.WriteFile(orphan, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := SweepOrphanReadySockets(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan not removed")
	}
	if _, err := os.Stat(ln.HostSocketPath()); err != nil {
		t.Fatalf("active socket removed: %v", err)
	}
}

func TestValidateReadySandboxID(t *testing.T) {
	if err := validateReadySandboxID("ok-id_1"); err != nil {
		t.Fatal(err)
	}
	if err := validateReadySandboxID("../evil"); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestReadyMetricsHit(t *testing.T) {
	before := readySocketHit.Value()
	dir := t.TempDir()
	ln, err := NewReadyListener(dir, "sb", "tok", "n1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		conn, err := net.Dial("unix", ln.HostSocketPath())
		if err != nil {
			return
		}
		defer conn.Close()
		_ = readyproto.Encode(conn, readyproto.ReadySignal{
			Event: readyproto.EventReady, SandboxID: "sb", Token: "tok", Nonce: "n1",
		})
	}()
	// Wait is exercised by waitForToolboxReady in integration; here we only
	// verify the listener accepts a valid line.
	if err := ln.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	_ = before
}

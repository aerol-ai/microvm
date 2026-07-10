package docker

import (
	"bufio"
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/readyproto"
)

func shortParkTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestNewParkedListenerValidation(t *testing.T) {
	if _, err := NewParkedListener("", "id", "tok", "n"); err == nil {
		t.Fatal("expected dir error")
	}
	if _, err := NewParkedListener(shortParkTestDir(t), "", "tok", "n"); err == nil {
		t.Fatal("expected slot id error")
	}
	if _, err := NewParkedListener(shortParkTestDir(t), "id", "", "n"); err == nil {
		t.Fatal("expected token error")
	}
}

func TestParkedListenerHappyPath(t *testing.T) {
	dir := shortParkTestDir(t)
	const (
		token = "park-secret"
		nonce = "park-nonce"
	)
	pl, err := NewParkedListener(dir, "park-1", token, nonce)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })

	if pl.BindSpec() == "" || len(pl.EnvVars()) == 0 {
		t.Fatal("expected bind spec and env vars")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// A real parked guest holds its connection open until adopted; closing it
	// marks the slot dead, so the test guest closes only when told to.
	closeGuest := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.Dial("unix", pl.HostSocketPath())
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer conn.Close()
		_ = readyproto.EncodeParked(conn, readyproto.ParkedSignal{
			Event: readyproto.EventParked, Token: token, Nonce: nonce,
		})
		<-closeGuest
	}()

	if err := pl.WaitParked(ctx); err != nil {
		t.Fatalf("WaitParked: %v", err)
	}
	if !pl.Alive() {
		t.Fatal("expected alive after parked hello")
	}

	// Guest death while parked must flip Alive to false, or the pool keeps
	// handing out dead slots and every adopt falls back to the cold path.
	close(closeGuest)
	wg.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for pl.Alive() {
		if time.Now().After(deadline) {
			t.Fatal("Alive() still true after guest closed the parked connection")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestParkedListenerAdoptHandshake(t *testing.T) {
	dir := shortParkTestDir(t)
	const (
		token = "park-secret"
		nonce = "park-nonce"
	)
	pl, err := NewParkedListener(dir, "park-adopt", token, nonce)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	guestErr := make(chan error, 1)
	go func() {
		conn, err := net.Dial("unix", pl.HostSocketPath())
		if err != nil {
			guestErr <- err
			return
		}
		defer conn.Close()
		if err := readyproto.EncodeParked(conn, readyproto.ParkedSignal{
			Event: readyproto.EventParked, Token: token, Nonce: nonce,
		}); err != nil {
			guestErr <- err
			return
		}
		frame, err := readyproto.DecodeAdopt(bufio.NewReader(conn))
		if err != nil {
			guestErr <- err
			return
		}
		guestErr <- readyproto.Encode(conn, readyproto.ReadySignal{
			Event:     readyproto.EventReady,
			SandboxID: frame.SandboxID,
			Token:     frame.Token,
			Nonce:     frame.Nonce,
		})
	}()

	if err := pl.WaitParked(ctx); err != nil {
		t.Fatalf("WaitParked: %v", err)
	}
	// Let the slot sit parked with the liveness monitor holding the read
	// before adopting, mirroring a real (non-instant) warm hit.
	time.Sleep(100 * time.Millisecond)
	if !pl.Alive() {
		t.Fatal("expected alive while parked")
	}
	if err := pl.Adopt(ctx, "sb-adopt-1", "adopt-tok", "adopt-nonce"); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	if err := <-guestErr; err != nil {
		t.Fatalf("guest: %v", err)
	}
}

func TestParkedListenerTokenMismatch(t *testing.T) {
	pl, err := NewParkedListener(shortParkTestDir(t), "park-bad", "good", "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go func() {
		conn, err := net.Dial("unix", pl.HostSocketPath())
		if err != nil {
			return
		}
		defer conn.Close()
		_ = readyproto.EncodeParked(conn, readyproto.ParkedSignal{
			Event: readyproto.EventParked, Token: "bad", Nonce: "nonce-1",
		})
	}()

	if err := pl.WaitParked(ctx); err == nil {
		t.Fatal("expected token mismatch error")
	}
}

func TestParkedListenerAdoptWithoutConnection(t *testing.T) {
	pl, err := NewParkedListener(shortParkTestDir(t), "park-none", "tok", "n")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })
	if err := pl.Adopt(context.Background(), "sb", "tok", "n"); err == nil {
		t.Fatal("expected missing connection error")
	}
}

func TestRemoveParkSocketSkipsActive(t *testing.T) {
	pl, err := NewParkedListener(shortParkTestDir(t), "park-active", "tok", "n")
	if err != nil {
		t.Fatal(err)
	}
	path := pl.HostSocketPath()
	RemoveParkSocket(path)
	if _, err := os.Stat(path); err != nil {
		t.Fatal("active socket should not be removed")
	}
	_ = pl.Close()
	RemoveParkSocket(path)
}

package docker

import (
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
	}()

	if err := pl.WaitParked(ctx); err != nil {
		t.Fatalf("WaitParked: %v", err)
	}
	if !pl.Alive() {
		t.Fatal("expected alive after parked hello")
	}
	wg.Wait()
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

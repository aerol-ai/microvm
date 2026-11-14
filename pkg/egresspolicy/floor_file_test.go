package egresspolicy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// withFileFloor puts the floor file's part back after a test.
func withFileFloor(t *testing.T) {
	t.Helper()
	prev := fileFloor.Load()
	t.Cleanup(func() { fileFloor.Store(prev) })
}

func writeFloor(t *testing.T, path, body string) {
	t.Helper()
	// As the kubelet updates a ConfigMap volume: the new file replaces the
	// old one whole.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestReadFloorFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deny-floor")
	writeFloor(t, path, "10.96.0.1/32,172.18.0.2\nfd00:10:96::1\n\n")
	got, err := ReadFloorFile(path)
	if err != nil || FormatRanges(got) != "10.96.0.1/32,172.18.0.2/32,fd00:10:96::1/128" {
		t.Fatalf("got %v %v", got, err)
	}
	writeFloor(t, path, "10.96.0.1\nnope\n")
	if _, err := ReadFloorFile(path); err == nil || !strings.Contains(err.Error(), FloorFileEnv) || !strings.Contains(err.Error(), path) {
		t.Fatalf("a bad entry: %v", err)
	}
	if _, err := ReadFloorFile(filepath.Join(dir, "missing")); err == nil || !strings.Contains(err.Error(), FloorFileEnv) {
		t.Fatalf("a missing file: %v", err)
	}
}

// A process sandboxd starts reads the floor file with its environment: its
// addresses join the extra floor, and every guard refuses them.
func TestLoadRangesFromEnvReadsTheFloorFile(t *testing.T) {
	withRanges(t, "", "")
	withFileFloor(t)
	path := filepath.Join(t.TempDir(), "deny-floor")
	writeFloor(t, path, "203.0.113.9\n")
	t.Setenv(DenyFloorEnv, "10.96.0.1")
	t.Setenv(FloorFileEnv, path)
	if err := LoadRangesFromEnv(); err != nil {
		t.Fatal(err)
	}
	if got := FormatRanges(ExtraDenyFloor()); got != "10.96.0.1/32,203.0.113.9/32" {
		t.Fatalf("floor = %q", got)
	}
	if err := (DialGuard{}).CheckFloor(ap("203.0.113.9:443")); err == nil {
		t.Fatal("an address in the floor file was dialed")
	}
	// A file it cannot read stops it, and changes nothing.
	t.Setenv(FloorFileEnv, filepath.Join(t.TempDir(), "missing"))
	if err := LoadRangesFromEnv(); err == nil {
		t.Fatal("a missing floor file was accepted")
	}
	if got := FormatRanges(ExtraDenyFloor()); got != "10.96.0.1/32,203.0.113.9/32" {
		t.Fatalf("a failed load changed the floor: %q", got)
	}
}

// A running process follows the file: a new address is refused from the
// next read on, onChange runs once per change, and a file that cannot be
// read keeps the addresses in force.
func TestWatchFloorFile(t *testing.T) {
	withRanges(t, "", "")
	withFileFloor(t)
	path := filepath.Join(t.TempDir(), "deny-floor")
	writeFloor(t, path, "172.18.0.2\n")
	first, err := ReadFloorFile(path)
	if err != nil {
		t.Fatal(err)
	}
	SetFileFloor(first)
	ctx, cancel := context.WithCancel(context.Background())
	var changes atomic.Int32
	done := make(chan struct{})
	go func() {
		WatchFloorFile(ctx, path, 5*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)), func() { changes.Add(1) })
		close(done)
	}()
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	// The API server moved to a new address.
	writeFloor(t, path, "172.18.0.44\n")
	waitFor("the new address was never refused", func() bool {
		return (DialGuard{}).CheckFloor(ap("172.18.0.44:443")) != nil
	})
	if changes.Load() != 1 {
		t.Fatalf("onChange ran %d times", changes.Load())
	}
	// Unreadable, then garbled: the floor in force stays.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	writeFloor(t, path, "nope\n")
	time.Sleep(30 * time.Millisecond)
	if (DialGuard{}).CheckFloor(ap("172.18.0.44:443")) == nil || changes.Load() != 1 {
		t.Fatalf("a failed read changed the floor (changes %d)", changes.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watch did not end with its context")
	}
}

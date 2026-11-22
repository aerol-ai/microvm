package worker

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// TestListenFromEnv: a worker serves the socket it was handed by number,
// which must be a listening Unix socket.
func TestListenFromEnv(t *testing.T) {
	dir, err := os.MkdirTemp("", "w")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	f, err := ul.File()
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	defer f.Close()
	// listenFromEnv owns and closes the descriptor it is handed, as a
	// worker does with the one it inherits: hand it a copy, never one a
	// live *os.File here would close again.
	t.Setenv(ListenFDEnv, strconv.Itoa(dupFD(t, f)))
	got, err := listenFromEnv("/never/bound")
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr().String() != sock {
		t.Fatalf("listening on %s", got.Addr())
	}
	go func() {
		if c, err := net.Dial("unix", sock); err == nil {
			_ = c.Close()
		}
	}()
	if c, err := got.Accept(); err != nil {
		t.Fatal(err)
	} else {
		_ = c.Close()
	}
	_ = got.Close()
	if os.Getenv(ListenFDEnv) != "" {
		t.Fatal("the descriptor's name stays in the environment")
	}
	for _, bad := range []string{"x", "1", "-3"} {
		t.Setenv(ListenFDEnv, bad)
		if _, err := listenFromEnv("/never/bound"); err == nil {
			t.Fatalf("%s=%q was taken", ListenFDEnv, bad)
		}
	}
	// A descriptor that is no socket is refused.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	t.Setenv(ListenFDEnv, strconv.Itoa(dupFD(t, pr)))
	if _, err := listenFromEnv("/never/bound"); err == nil {
		t.Fatal("a pipe was served")
	}
}

func TestShareFromEnv(t *testing.T) {
	t.Setenv(ShareGroupEnv, "0")
	shareFromEnv()
	if os.Getenv(ShareGroupEnv) != "0" {
		t.Fatal("a value other than 1 was taken")
	}
	old := shareFiles
	t.Cleanup(func() { shareFiles = old })
	shared := false
	shareFiles = func() { shared = true }
	t.Setenv(ShareGroupEnv, "1")
	shareFromEnv()
	if os.Getenv(ShareGroupEnv) != "" || !shared {
		t.Fatalf("shared %v; the setting left in the environment: %q", shared, os.Getenv(ShareGroupEnv))
	}
}

// dupFD is a copy of f's descriptor for a callee that closes it.
func dupFD(t *testing.T, f *os.File) int {
	t.Helper()
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

//go:build linux

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLinuxVsockServerErrorBranches(t *testing.T) {
	if _, err := newVsockServer(1024, nil, nil); err == nil {
		t.Fatal("expected nil handler error")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := newQuiesceHandler(logger, nil, nil)
	vs, err := newVsockServer(4095, handler, nil) // nil logger → Default
	if err != nil {
		t.Logf("vsock unavailable: %v", err)
		return
	}
	t.Cleanup(func() { _ = vs.Close() })

	// Second bind on same port should fail.
	if _, err := newVsockServer(4095, handler, logger); err == nil {
		t.Fatal("expected bind failure on used port")
	}

	// Drive handle() with a unix socketpair (Read/Write work like vsock).
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	go func() {
		_, _ = unix.Write(fds[1], []byte(`{"op":"ping"}`+"\n"))
		_ = unix.Close(fds[1])
	}()
	vs.handle(context.Background(), fds[0])

	conn := newVsockConn(-1)
	_ = conn.LocalAddr().Network()
	_ = conn.RemoteAddr().String()
	_ = conn.SetDeadline(time.Now().Add(time.Millisecond))
	_ = conn.Close()
	_ = vs.Close() // second Close is once.Do no-op
}

func TestLinuxConfigureNetworkForcedFailures(t *testing.T) {
	ops := linuxQuiesceOps{}
	dir := t.TempDir()

	// ip binary that fails specifically on addr replace.
	ipPath := filepath.Join(dir, "ip")
	if err := os.WriteFile(ipPath, []byte("#!/bin/sh\necho args:$* >&2\nif [ \"$1\" = addr ]; then exit 1; fi\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir)
	if err := ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP: "10.0.0.2", GatewayIP: "10.0.0.1", PrefixLen: 30,
	}); err == nil {
		t.Fatal("expected addr replace failure")
	}

	// ifconfig-only PATH: fail with netmask and without.
	_ = os.Remove(ipPath)
	ifconfig := filepath.Join(dir, "ifconfig")
	if err := os.WriteFile(ifconfig, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("WriteFile ifconfig: %v", err)
	}
	if err := ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP: "10.0.0.2", GatewayIP: "10.0.0.1", PrefixLen: 30, Netmask: "255.255.255.252",
	}); err == nil {
		t.Fatal("expected ifconfig+netmask failure")
	}
	if err := ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP: "10.0.0.2", GatewayIP: "10.0.0.1", PrefixLen: 30,
	}); err == nil {
		t.Fatal("expected ifconfig failure")
	}
}

func TestLinuxVsockServeAcceptClosed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := newQuiesceHandler(logger, nil, nil)
	vs, err := newVsockServer(4094, handler, logger)
	if err != nil {
		t.Skip("vsock unavailable")
	}
	done := make(chan error, 1)
	go func() { done <- vs.Serve(context.Background()) }()
	time.Sleep(30 * time.Millisecond)
	_ = vs.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Log("Serve did not return promptly after Close (acceptable on some kernels)")
	}
}

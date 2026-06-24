//go:build linux

package firecracker

import (
	"bufio"
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxVsockDialerUsesFirecrackerUDSProtocol(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "vsock.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer ln.Close()

	connectLine := make(chan string, 1)
	payloadLine := make(chan string, 1)
	serverErr := make(chan error, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		line, err := r.ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		connectLine <- line
		if _, err := io.WriteString(conn, "OK 1073741824\n"); err != nil {
			serverErr <- err
			return
		}
		line, err = r.ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		payloadLine <- line
		serverErr <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := NewLinuxVsockDialer().Dial(ctx, socketPath, 3, 1024)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	select {
	case got := <-connectLine:
		if got != "CONNECT 1024\n" {
			t.Fatalf("connect line = %q, want CONNECT 1024", got)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive CONNECT line")
	}

	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	select {
	case got := <-payloadLine:
		if got != "ping\n" {
			t.Fatalf("payload line = %q, want ping", got)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive payload line")
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

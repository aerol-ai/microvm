package docker

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCoverage95ExecStartOKStatus(t *testing.T) {
	dir, err := os.MkdirTemp("", "ex")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "e.sock")
	sock = execSocketServerAt(t, sock, "HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	c := &Client{socketPath: sock}
	sess, err := c.ExecStart(context.Background(), "exec-ok", false)
	if err != nil {
		t.Fatalf("ExecStart() = %v", err)
	}
	if sess.ID != "exec-ok" {
		t.Fatalf("session ID = %q", sess.ID)
	}
	_ = sess.Close()
}

func execSocketServerAt(t *testing.T, sock, response string) string {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		_, _ = conn.Write([]byte(response))
		time.Sleep(50 * time.Millisecond)
	}()
	return sock
}

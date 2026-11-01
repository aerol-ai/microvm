//go:build linux

package toolboxhttp

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// sockopts reads the keepalive and user-timeout options off a dialed socket.
func sockopts(t *testing.T, conn net.Conn) (keepAlive, idle, interval, count, userTimeoutMS int) {
	t.Helper()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var getErr error
	get := func(fd int, level, opt int) int {
		v, err := unix.GetsockoptInt(fd, level, opt)
		if err != nil && getErr == nil {
			getErr = err
		}
		return v
	}
	if err := raw.Control(func(fd uintptr) {
		f := int(fd)
		keepAlive = get(f, unix.SOL_SOCKET, unix.SO_KEEPALIVE)
		idle = get(f, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE)
		interval = get(f, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL)
		count = get(f, unix.IPPROTO_TCP, unix.TCP_KEEPCNT)
		userTimeoutMS = get(f, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
	}); err != nil {
		t.Fatal(err)
	}
	if getErr != nil {
		t.Fatal(getErr)
	}
	return
}

// TestDialSetsDeadPeerSocketOptions: the kernel holds the options the bound
// asks for: keepalive 15s idle, 5s interval, 3 probes, and a 30s
// TCP_USER_TIMEOUT. With the bound off, no user timeout is set.
func TestDialSetsDeadPeerSocketOptions(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	withDeadPeerTimeout(t, DefaultDeadPeerTimeout)
	conn, err := DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ka, idle, interval, count, user := sockopts(t, conn)
	conn.Close()
	if ka != 1 || idle != 15 || interval != 5 || count != 3 || user != int((30*time.Second)/time.Millisecond) {
		t.Fatalf("bounded socket: SO_KEEPALIVE=%d TCP_KEEPIDLE=%d TCP_KEEPINTVL=%d TCP_KEEPCNT=%d TCP_USER_TIMEOUT=%dms", ka, idle, interval, count, user)
	}

	SetDeadPeerTimeout(0)
	conn, err = DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ka, idle, _, _, user = sockopts(t, conn)
	conn.Close()
	if ka != 1 || idle != 30 || user != 0 {
		t.Fatalf("unbounded socket: SO_KEEPALIVE=%d TCP_KEEPIDLE=%d TCP_USER_TIMEOUT=%dms, want Go's 30s idle and no user timeout", ka, idle, user)
	}
}

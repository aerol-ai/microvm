//go:build linux

package cluster

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// TestInternalDialerSocketOptions checks what the kernel was actually told
// on a real connection: TCP_USER_TIMEOUT and the keepalive probes that end
// a connection to a peer that dropped off the network (internal_transport.go).
func TestInternalDialerSocketOptions(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			buf := make([]byte, 1)
			_, _ = c.Read(buf)
		}
	}()
	conn, err := newInternalDialer().Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		for name, opt := range map[string][2]int{
			"TCP_USER_TIMEOUT": {unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT},
			"SO_KEEPALIVE":     {unix.SOL_SOCKET, unix.SO_KEEPALIVE},
			"TCP_KEEPIDLE":     {unix.IPPROTO_TCP, unix.TCP_KEEPIDLE},
			"TCP_KEEPINTVL":    {unix.IPPROTO_TCP, unix.TCP_KEEPINTVL},
			"TCP_KEEPCNT":      {unix.IPPROTO_TCP, unix.TCP_KEEPCNT},
		} {
			v, err := unix.GetsockoptInt(int(fd), opt[0], opt[1])
			if err != nil {
				gerr = err
				return
			}
			got[name] = v
		}
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	want := map[string]int{"TCP_USER_TIMEOUT": 15000, "SO_KEEPALIVE": 1, "TCP_KEEPIDLE": 5, "TCP_KEEPINTVL": 5, "TCP_KEEPCNT": 3}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}
}

//go:build linux

package egress

import (
	"errors"
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func peercredCoverListen(t *testing.T, name string) *net.UnixConn {
	t.Helper()
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(t.TempDir(), name), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func peercredCoverCred(t *testing.T, c *net.UnixConn) *unix.Ucred {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		t.Fatal(err)
	}
	if credErr != nil {
		t.Fatal(credErr)
	}
	return cred
}

func TestUnixPeerCheckCoverErrors(t *testing.T) {
	t.Run("no socket", func(t *testing.T) {
		if err := UnixPeerCheck(nil, "")(&net.UnixConn{}); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("empty UnixConn = %v", err)
		}
	})

	t.Run("closed", func(t *testing.T) {
		c := peercredCoverListen(t, "closed.sock")
		_ = c.Close()
		if err := UnixPeerCheck(nil, "")(c); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed conn = %v", err)
		}
	})

	t.Run("not a socket", func(t *testing.T) {
		// SO_PEERCRED can't fail on a socket. A pipe duplicated over the
		// conn's descriptor makes getsockopt see a non-socket.
		c := peercredCoverListen(t, "pipe.sock")
		var p [2]int
		if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(p[0]); _ = unix.Close(p[1]) })
		raw, err := c.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var dupErr error
		if err := raw.Control(func(fd uintptr) { dupErr = unix.Dup3(p[1], int(fd), unix.O_CLOEXEC) }); err != nil || dupErr != nil {
			t.Fatalf("dup: %v %v", err, dupErr)
		}
		if err := UnixPeerCheck(nil, "")(c); !errors.Is(err, unix.ENOTSOCK) {
			t.Fatalf("non-socket descriptor = %v", err)
		}
	})

	t.Run("peer without a process", func(t *testing.T) {
		// An unconnected datagram socket has no peer: pid 0, which has no
		// /proc entry to read the cgroup from.
		c := peercredCoverListen(t, "unbound.sock")
		cred := peercredCoverCred(t, c)
		if cred.Pid != 0 {
			t.Fatalf("unconnected socket reports peer pid %d", cred.Pid)
		}
		err := UnixPeerCheck([]uint32{cred.Uid}, "sandboxd.service")(c)
		if err == nil || !strings.Contains(err.Error(), "read peer cgroup") {
			t.Fatalf("peer without /proc entry = %v", err)
		}
	})
}

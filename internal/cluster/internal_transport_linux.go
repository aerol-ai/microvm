//go:build linux

package cluster

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setInternalUserTimeout sets TCP_USER_TIMEOUT on an internal-channel
// socket before it connects (internal_transport.go). A failed setsockopt
// fails the dial: every server and worker runs Linux, where the option has
// existed since 2.6.37, so a failure means something is badly wrong.
func setInternalUserTimeout(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(internalUserTimeout.Milliseconds()))
	}); err != nil {
		return err
	}
	return serr
}

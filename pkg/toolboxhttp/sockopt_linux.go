//go:build linux

package toolboxhttp

import (
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// userTimeoutControl sets TCP_USER_TIMEOUT on a toolbox socket before it
// connects (see deadPeerSettings).
func userTimeoutControl(d time.Duration) func(network, address string, c syscall.RawConn) error {
	ms := int(d / time.Millisecond)
	return func(_, _ string, c syscall.RawConn) error {
		var setErr error
		if err := c.Control(func(fd uintptr) {
			setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, ms)
		}); err != nil {
			return err
		}
		return setErr
	}
}

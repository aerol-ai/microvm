//go:build linux

package gatewayd

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// freebindControl sets IP_FREEBIND so listeners can bind a bridge address
// before the bridge has it (aerolvm0 appears on the first CNI ADD).
func freebindControl(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
	}); err != nil {
		return err
	}
	return serr
}

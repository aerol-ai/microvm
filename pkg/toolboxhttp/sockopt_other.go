//go:build !linux

package toolboxhttp

import (
	"syscall"
	"time"
)

// userTimeoutControl is nil off Linux: there is no TCP_USER_TIMEOUT, and
// keepalive alone bounds a connection idle when its peer died.
func userTimeoutControl(time.Duration) func(network, address string, c syscall.RawConn) error {
	return nil
}

//go:build !linux

package cluster

import "syscall"

// setInternalUserTimeout is a no-op off Linux, where cluster nodes do not
// run (TCP_USER_TIMEOUT is Linux-only); the keepalive probes still apply.
func setInternalUserTimeout(_, _ string, _ syscall.RawConn) error { return nil }

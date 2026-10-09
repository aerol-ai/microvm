//go:build !linux

package gatewayd

import "syscall"

// freebindControl is a no-op off Linux (developer hosts and tests).
func freebindControl(_, _ string, _ syscall.RawConn) error { return nil }

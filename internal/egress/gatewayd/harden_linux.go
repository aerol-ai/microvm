//go:build linux

package gatewayd

import "golang.org/x/sys/unix"

func unixPrctlNoDump() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }

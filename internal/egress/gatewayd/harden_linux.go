//go:build linux

package gatewayd

import "golang.org/x/sys/unix"

// unixPrctlNoDump is PR_SET_DUMPABLE. Tests substitute a failure: a real
// prctl does not fail for this process, and the caller must still refuse to
// start when hardening does.
var unixPrctlNoDump = func() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }

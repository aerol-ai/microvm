//go:build !linux

package isolate

import (
	"fmt"
	"os/exec"
)

// applyJail is unavailable off Linux — chroot/setuid/seccomp/cgroup are
// Linux-only. Returning an error makes Start FAIL CLOSED when a jail is
// required, so an isolate host is never run unconfined while the operator
// believes it is jailed.
func applyJail(_ *exec.Cmd, _ JailConfig) error {
	return fmt.Errorf("isolate jail: realization requires linux (chroot/setuid/seccomp are Linux-only)")
}

// jailRealizable reports that this (non-Linux) platform cannot realize the jail.
func jailRealizable() bool { return false }

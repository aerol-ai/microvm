//go:build !linux

package isolate

import (
	"fmt"
	"os/exec"
)

// applyJail is unavailable off Linux — chroot/setuid/seccomp/cgroup are
// Linux-only. A required jail therefore fails closed here (see Host.Start);
// this is also why JailRealizable() is false on these platforms.
func applyJail(*exec.Cmd, JailConfig, []string) (*jailRealized, error) {
	return nil, fmt.Errorf("isolate jail: realization requires linux (chroot/setuid/seccomp/cgroup are Linux-only)")
}

func jailRealizable() bool { return false }

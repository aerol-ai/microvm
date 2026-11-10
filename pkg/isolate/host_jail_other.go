//go:build !linux

package isolate

import (
	"fmt"
	"os/exec"
)

// errJailNeedsLinux: chroot/setuid/seccomp/cgroup are Linux-only. A
// required jail therefore fails closed here (see Host.Start); this is also
// why JailRealizable() is false on these platforms.
var errJailNeedsLinux = fmt.Errorf("isolate jail: realization requires linux (chroot/setuid/seccomp/cgroup are Linux-only)")

func prepareJailFS(JailConfig) (*jailRealized, error) { return nil, errJailNeedsLinux }

func applyJail(*exec.Cmd, JailConfig, []string, *jailRealized) error { return errJailNeedsLinux }

func jailRealizable() bool { return false }

//go:build linux

package rootd

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// mkfifoAt makes a FIFO at name in the folder dfd.
func mkfifoAt(dfd int, _, name string, mode uint32) error { return unix.Mkfifoat(dfd, name, mode) }

// protectedHardlinksPath is the sysctl that lets only a file's owner, or a
// process with CAP_FOWNER, make a hard link to it. A var for tests.
var protectedHardlinksPath = "/proc/sys/fs/protected_hardlinks"

// checkLinkCapability refuses to start a root helper that could not name
// the agent's ready sockets (ensureReadySocket): with fs.protected_hardlinks
// on (the kernel's default), a hard link to a file someone else owns needs
// CAP_FOWNER. Without it every create would fail at its ready socket, and
// as EPERM, which the call reads as a link it must refuse: a security
// alarm for a capability the operator dropped.
//
// The check is for root, which every real helper is: the supervisor and
// the VM unit run it as root, and its network, cgroup and mount work needs
// root anyway. A root process with a trimmed capability set is the mistake
// it catches. A helper that is not root is a test's (its socket, folders
// and peer check under the test's own user); it never had CAP_FOWNER, and
// the tests that give it another user as the agent link no ready socket.
func checkLinkCapability(agentUID uint32) error {
	euid := geteuid()
	if euid != 0 || uint32(euid) == agentUID {
		return nil
	}
	raw, err := os.ReadFile(protectedHardlinksPath)
	if err != nil || strings.TrimSpace(string(raw)) == "0" {
		return nil
	}
	ok, err := hasEffectiveCap(unix.CAP_FOWNER)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("root helper: fs.protected_hardlinks is on and the helper lacks CAP_FOWNER, " +
			"which it needs to name the agent's ready sockets in its own folder; give the helper CAP_FOWNER")
	}
	return nil
}

// geteuid is os.Geteuid; tests replace it to stand for root.
var geteuid = os.Geteuid

// hasEffectiveCap reports whether this process has capability c in its
// effective set. A var for tests.
var hasEffectiveCap = func(c int) (bool, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false, err
	}
	return data[c/32].Effective&(1<<(uint(c)%32)) != 0, nil
}

//go:build linux

package egress

import (
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// UnixPeerCheck vets a UDS peer with SO_PEERCRED (CEO D22): the uid must be
// allowed and, when requiredCgroup is set, the peer process must run in that
// systemd unit's cgroup (sandboxd.service). Anything else is rejected, so only
// sandboxd can change who reaches the internet.
func UnixPeerCheck(allowedUIDs []uint32, requiredCgroup string) PeerCheck {
	return func(c net.Conn) error {
		uc, ok := c.(*net.UnixConn)
		if !ok {
			return fmt.Errorf("egress: peer is not a unix socket")
		}
		raw, err := uc.SyscallConn()
		if err != nil {
			return err
		}
		var cred *unix.Ucred
		var credErr error
		if err := raw.Control(func(fd uintptr) {
			cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		}); err != nil {
			return err
		}
		if credErr != nil {
			return credErr
		}
		if !slices.Contains(allowedUIDs, cred.Uid) {
			return fmt.Errorf("egress: peer uid %d not allowed", cred.Uid)
		}
		if requiredCgroup == "" {
			return nil
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", cred.Pid))
		if err != nil {
			return fmt.Errorf("egress: read peer cgroup: %w", err)
		}
		if !strings.Contains(string(data), requiredCgroup) {
			return fmt.Errorf("egress: peer pid %d is not in %s", cred.Pid, requiredCgroup)
		}
		return nil
	}
}

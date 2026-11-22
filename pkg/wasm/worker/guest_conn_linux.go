//go:build linux

package worker

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// checkTCPListenerKind refuses a listening socket whose connections do not
// all come through TCP's port space on every device (checkGuestListener):
// one not IPv4 or IPv6, not SOCK_STREAM, not TCP or MPTCP, or bound to a
// device.
func checkTCPListenerKind(fd int) error {
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return fmt.Errorf("its family: %w", err)
	}
	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return fmt.Errorf("its type: %w", err)
	}
	proto, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
	if err != nil {
		return fmt.Errorf("its protocol: %w", err)
	}
	if (domain != unix.AF_INET && domain != unix.AF_INET6) || typ != unix.SOCK_STREAM || (proto != unix.IPPROTO_TCP && proto != unix.IPPROTO_MPTCP) {
		return fmt.Errorf("the attached socket is not TCP (family %d, type %d, protocol %d)", domain, typ, proto)
	}
	ifindex, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
	if errors.Is(err, unix.ENOPROTOOPT) {
		// Before Linux 5.0 only the device's name can be read.
		var dev string
		if dev, err = unix.GetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE); err == nil && dev != "" {
			ifindex = -1
		}
	}
	switch {
	case err != nil:
		return fmt.Errorf("its device: %w", err)
	case ifindex != 0:
		return errors.New("the attached socket is bound to a device")
	}
	return nil
}

//go:build linux

package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// soOriginalDst is SO_ORIGINAL_DST from linux/netfilter_ipv4.h.
const soOriginalDst = 80

// OriginalDst returns the destination a REDIRECTed connection was originally
// addressed to. The kernel returns a sockaddr_in; IPv6Mreq is the 20-byte
// getsockopt shape that fits it.
func OriginalDst(c net.Conn) (netip.AddrPort, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("egress proxy: %T is not a TCP connection", c)
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var mreq *unix.IPv6Mreq
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		mreq, gerr = unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, soOriginalDst)
	}); err != nil {
		return netip.AddrPort{}, err
	}
	if gerr != nil {
		return netip.AddrPort{}, fmt.Errorf("SO_ORIGINAL_DST: %w", gerr)
	}
	b := mreq.Multiaddr
	port := binary.BigEndian.Uint16(b[2:4])
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), port), nil
}

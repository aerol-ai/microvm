//go:build !linux

package proxy

import (
	"net"
	"net/netip"
)

// OriginalDst off Linux returns the local address: there is no REDIRECT, so
// the connection's own destination is the original one (developer hosts and
// tests only).
func OriginalDst(c net.Conn) (netip.AddrPort, error) {
	return netip.ParseAddrPort(c.LocalAddr().String())
}

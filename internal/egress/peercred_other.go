//go:build !linux

package egress

import "net"

// UnixPeerCheck is permissive off Linux, where the gateway never runs in
// production; it exists so the package builds and tests on developer hosts.
func UnixPeerCheck([]uint32, string) PeerCheck {
	return func(net.Conn) error { return nil }
}

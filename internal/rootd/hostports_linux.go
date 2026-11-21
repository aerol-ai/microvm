//go:build linux

package rootd

import (
	"net/netip"

	"github.com/vishvananda/netlink"

	"github.com/aerol-ai/microvm/internal/network/hostport"
)

// kernelHostPorts is the helper's HostPortHost: sandboxd's own forwarder
// (iptables, as in single mode) and the kernel's list of this node's
// addresses.
type kernelHostPorts struct{ *hostport.Forwarder }

// openHostPorts opens the forwarder; its chains and jumps go in on its
// first write.
func openHostPorts() (HostPortHost, error) {
	b, err := hostport.NewIPTablesBackend()
	if err != nil {
		return nil, err
	}
	return kernelHostPorts{hostport.New(b, hostport.FlushConntrack)}, nil
}

// IsLocal reads every IPv4 address on every link of the helper's
// namespace, the host's: read on each check, as the node's addresses
// change.
func (kernelHostPorts) IsLocal(a netip.Addr) (bool, error) {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return false, err
	}
	for _, x := range addrs {
		if ip, ok := netip.AddrFromSlice(x.IP); ok && ip.Unmap() == a {
			return true, nil
		}
	}
	return false, nil
}

//go:build linux

package hostport

import (
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// FlushConntrack drops tracked TCP connections whose ORIGINAL destination
// port is hostPort. Without this, DNAT'd sessions outlive their rule and an
// unexpose would not cut access.
func FlushConntrack(hostPort int) error {
	filter := &netlink.ConntrackFilter{}
	if err := filter.AddProtocol(unix.IPPROTO_TCP); err != nil {
		return err
	}
	if err := filter.AddPort(netlink.ConntrackOrigDstPort, uint16(hostPort)); err != nil {
		return err
	}
	_, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, unix.AF_INET, filter)
	return err
}

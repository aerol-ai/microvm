//go:build linux

package hostnet

import (
	"fmt"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// ipv4AddrsIn dumps the IPv4 addresses of the namespace behind ns. A var
// because unit tests cannot open a netlink socket in another namespace
// (the kerneltest covers the real thing). NewHandleAt enters ns on a
// locked thread only to open the socket and puts the thread back; the dump
// itself runs from here.
var ipv4AddrsIn = func(ns netns.NsHandle) ([]netlink.Addr, error) {
	h, err := netlink.NewHandleAt(ns, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	return h.AddrList(nil, netlink.FAMILY_V4)
}

func netnsIPv4Addrs(path string) ([]string, error) {
	target, err := nsFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("read netns addresses: open netns %s: %w", path, err)
	}
	defer target.Close()
	addrs, err := ipv4AddrsIn(target)
	if err != nil {
		return nil, fmt.Errorf("read netns addresses: %s: %w", path, err)
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a.IPNet == nil {
			continue
		}
		if ip := a.IP.To4(); ip != nil && !ip.IsLoopback() {
			out = append(out, ip.String())
		}
	}
	return out, nil
}

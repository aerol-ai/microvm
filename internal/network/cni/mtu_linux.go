//go:build linux

package cni

import (
	"os"
	"strings"
)

// defaultRouteInterface reads /proc/net/route for the interface that owns the
// IPv4 default route (Destination column 00000000). This needs no
// CAP_NET_ADMIN and no netlink socket, so it is safe to call at daemon boot.
func defaultRouteInterface() string {
	raw, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		if i == 0 { // header: Iface Destination Gateway Flags ...
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

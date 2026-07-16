package cni

import "net"

const (
	// DefaultBridgeMTU is the fallback bridge veth MTU when the host uplink MTU
	// cannot be determined. Docker-parity default.
	DefaultBridgeMTU = 1500
)

var (
	defaultRouteInterfaceFn = defaultRouteInterface
	interfaceByNameFn       = net.InterfaceByName
)

// BridgeMTU is the docker-parity default MTU. Callers that want uplink parity
// use UplinkMTU() and fall back to this.
func BridgeMTU() int {
	return DefaultBridgeMTU
}

// UplinkMTU returns the MTU of the host's default-route interface, or 0 when it
// cannot be determined (non-linux, or no default route). Sizing the bridge/veth
// to the uplink avoids two failure modes the hardcoded 1500 caused: on a
// jumbo-frame uplink (AWS ENA is 9001) a 1500 bridge caps throughput, and on a
// sub-1500 uplink (overlay/VPN/GRE) a 1500 bridge blackholes egress via PMTUD.
func UplinkMTU() int {
	iface := defaultRouteInterfaceFn()
	if iface == "" {
		return 0
	}
	ni, err := interfaceByNameFn(iface)
	if err != nil || ni.MTU <= 0 {
		return 0
	}
	return ni.MTU
}

package cni

const (
	// DefaultBridgeMTU is the bridge veth MTU for containerd CNI topology.
	// Must match docker0 / the aerolvm.conflist bridge plugin mtu field.
	DefaultBridgeMTU = 1500
)

// BridgeMTU returns the MTU wired into the CNI bridge conflist. Today this is
// the docker-parity default; host-uplink-derived MTU can slot in here later.
func BridgeMTU() int {
	return DefaultBridgeMTU
}

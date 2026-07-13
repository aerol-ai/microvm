//go:build !linux

package cni

// defaultRouteInterface is linux-only (reads /proc/net/route); elsewhere the
// uplink MTU is undeterminable and callers fall back to DefaultBridgeMTU.
func defaultRouteInterface() string { return "" }

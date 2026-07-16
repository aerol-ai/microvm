package cni

import (
	"errors"
	"net"
	"testing"
)

func TestBridgeMTUDefault(t *testing.T) {
	if got := BridgeMTU(); got != DefaultBridgeMTU {
		t.Fatalf("BridgeMTU() = %d, want %d", got, DefaultBridgeMTU)
	}
	if DefaultBridgeMTU != 1500 {
		t.Fatalf("DefaultBridgeMTU = %d, want docker-parity 1500", DefaultBridgeMTU)
	}
}

func TestUplinkMTUBranches(t *testing.T) {
	origRoute := defaultRouteInterfaceFn
	origIfaceByName := interfaceByNameFn
	t.Cleanup(func() {
		defaultRouteInterfaceFn = origRoute
		interfaceByNameFn = origIfaceByName
	})

	t.Run("no default route interface", func(t *testing.T) {
		defaultRouteInterfaceFn = func() string { return "" }
		interfaceByNameFn = func(name string) (*net.Interface, error) {
			t.Fatalf("interfaceByNameFn should not be called for empty route iface")
			return nil, nil
		}
		if got := UplinkMTU(); got != 0 {
			t.Fatalf("UplinkMTU() = %d, want 0", got)
		}
	})

	t.Run("interface lookup error", func(t *testing.T) {
		defaultRouteInterfaceFn = func() string { return "uplink0" }
		interfaceByNameFn = func(name string) (*net.Interface, error) {
			if name != "uplink0" {
				t.Fatalf("name=%q, want uplink0", name)
			}
			return nil, errors.New("no such iface")
		}
		if got := UplinkMTU(); got != 0 {
			t.Fatalf("UplinkMTU() = %d, want 0", got)
		}
	})

	t.Run("non-positive mtu", func(t *testing.T) {
		defaultRouteInterfaceFn = func() string { return "uplink1" }
		interfaceByNameFn = func(string) (*net.Interface, error) {
			return &net.Interface{MTU: 0}, nil
		}
		if got := UplinkMTU(); got != 0 {
			t.Fatalf("UplinkMTU() = %d, want 0", got)
		}
	})

	t.Run("valid mtu", func(t *testing.T) {
		defaultRouteInterfaceFn = func() string { return "uplink2" }
		interfaceByNameFn = func(string) (*net.Interface, error) {
			return &net.Interface{MTU: 9001}, nil
		}
		if got := UplinkMTU(); got != 9001 {
			t.Fatalf("UplinkMTU() = %d, want 9001", got)
		}
	})
}

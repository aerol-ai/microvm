package workerfence

import (
	"net/netip"
	"testing"
)

// Review round 4, F5: a kernel without nft fib that still puts
// "broadcast <network>" in the local table delivers a datagram to a
// subnet's network address to the node's UDP services on 0.0.0.0, as it
// does one to the broadcast address. The listed plan drops both for every
// IPv4 subnet wider than /31, and neither for /31, /32 or IPv6.
func TestPlanNoFibDropsSubnetNetworkAddress(t *testing.T) {
	pfx := netip.MustParsePrefix
	rules, err := Plan(Spec{UID: 7, NoFib: true, Local: []netip.Prefix{
		pfx("172.17.0.2/16"), pfx("10.1.2.5/30"), pfx("192.0.2.8/31"), pfx("198.51.100.7/32"), pfx("2001:db8::5/64"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	dropped := map[netip.Addr]bool{}
	for _, r := range rules {
		if r.Kind == KindDrop && r.Prefix.Bits() == r.Prefix.Addr().BitLen() {
			dropped[r.Prefix.Addr()] = true
		}
	}
	for _, a := range []string{"172.17.0.0", "172.17.255.255", "10.1.2.4", "10.1.2.7"} {
		if !dropped[netip.MustParseAddr(a)] {
			t.Errorf("%s is not dropped: %s", a, Key(rules))
		}
	}
	for _, a := range []string{"192.0.2.8", "198.51.100.7"} {
		// A /31's and a /32's only addresses are node addresses, dropped as
		// such; nothing else of theirs is.
		if !dropped[netip.MustParseAddr(a)] {
			t.Errorf("node address %s is not dropped", a)
		}
	}
	for _, a := range []string{"192.0.2.9", "2001:db8::"} {
		if dropped[netip.MustParseAddr(a)] {
			t.Errorf("%s is dropped, but is no subnet address of the node's", a)
		}
	}
}

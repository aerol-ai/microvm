package egresspolicy

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// stubNodeAddrs makes the node's interfaces carry addrs for one test.
func stubNodeAddrs(t *testing.T, addrs ...string) *int {
	t.Helper()
	calls := 0
	prev := interfaceAddrs
	interfaceAddrs = func() ([]net.Addr, error) {
		calls++
		var out []net.Addr
		for _, a := range addrs {
			ip := net.ParseIP(a)
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(24, 8*len(ip))})
		}
		out = append(out, &net.IPAddr{IP: net.ParseIP("192.0.2.200")}) // not an IPNet: ignored
		return out, nil
	}
	nodeAddrs.Store(nil)
	prevAllowed := nodeAllowed.Load()
	t.Cleanup(func() {
		interfaceAddrs = prev
		nodeAddrs.Store(nil)
		nodeAllowed.Store(prevAllowed)
	})
	return &calls
}

func reasonOf(err error) string {
	var de *DialError
	if errors.As(err, &de) {
		return de.Reason
	}
	return ""
}

// TestCheckNode: the node's own addresses are never a sandbox destination,
// except an allowed port on a non-loopback address.
func TestCheckNode(t *testing.T) {
	stubNodeAddrs(t, "10.250.1.5", "172.31.250.1", "198.51.100.77", "fd00:250::5")
	SetNodeAllowedPorts([]uint16{443, 80, 443})
	cases := []struct {
		addr   string
		reason string
	}{
		{"127.0.0.1:9100", DialReasonLoopback},
		{"127.0.0.1:443", DialReasonLoopback}, // an allowed port never opens loopback
		{"[::1]:9100", DialReasonLoopback},
		{"0.0.0.0:9100", DialReasonUnspecified},
		{"0.1.2.3:9100", DialReasonUnspecified},
		{"10.250.1.5:9100", DialReasonNode},    // the node's private address
		{"172.31.250.1:514", DialReasonNode},   // a bridge gateway
		{"198.51.100.77:22", DialReasonNode},   // a locally bound public address
		{"[fd00:250::5]:9100", DialReasonNode}, // and its IPv6 one
		{"[::ffff:10.250.1.5]:9100", DialReasonNode},
		{"10.250.1.5:443", ""},   // ingress, allowed
		{"198.51.100.77:80", ""}, // ingress, allowed
		{"10.250.1.6:9100", ""},  // a neighbour, not the node
		{"1.1.1.1:443", ""},
	}
	for _, tc := range cases {
		if got := reasonOf(CheckNode(netip.MustParseAddrPort(tc.addr))); got != tc.reason {
			t.Errorf("CheckNode(%s) = %q, want %q", tc.addr, got, tc.reason)
		}
	}
	if reasonOf(CheckNode(netip.AddrPort{})) != DialReasonInvalid {
		t.Error("an invalid address is refused")
	}
	if got := NodeAllowedPorts(); !slices.Equal(got, []uint16{80, 443}) {
		t.Fatalf("allowed ports are sorted and deduped: %v", got)
	}
	SetNodeAllowedPorts(nil)
	if CheckNode(netip.MustParseAddrPort("10.250.1.5:443")) == nil {
		t.Fatal("with nothing allowed, every node port is refused")
	}
	nodeAllowed.Store(nil)
	if NodeAllowedPorts() != nil || CheckNode(netip.MustParseAddrPort("10.250.1.5:443")) == nil {
		t.Fatal("a process never told otherwise allows nothing (the egress gateway)")
	}
}

// TestDialGuardRefusesTheNode: no policy CIDR, internal zone or allowed
// name opens the node, in either guard posture.
func TestDialGuardRefusesTheNode(t *testing.T) {
	stubNodeAddrs(t, "10.250.1.5")
	p, err := Compile(Spec{AllowOut: []string{"10.0.0.0/8", "db.corp.internal"}})
	if err != nil {
		t.Fatal(err)
	}
	zone, err := NewInternalZone([]string{"corp.internal"}, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []DialGuard{{}, {Zone: zone}, {Strict: true, Zone: zone, ZoneInStrict: true}} {
		for _, tgt := range []DialTarget{
			{Addr: netip.MustParseAddrPort("10.250.1.5:9100")},
			{Name: "db.corp.internal", NameAllowed: true, Addr: netip.MustParseAddrPort("10.250.1.5:5432")},
		} {
			if got := reasonOf(g.Check(p, tgt)); got != DialReasonNode {
				t.Errorf("guard %+v target %+v: %q, want node", g, tgt, got)
			}
		}
	}
	// A neighbour inside the allowed CIDR is still reachable.
	if err := (DialGuard{}).Check(p, DialTarget{Addr: netip.MustParseAddrPort("10.250.1.6:9100")}); err != nil {
		t.Fatalf("a neighbour: %v", err)
	}
}

func TestNodePortsEnvRoundTrip(t *testing.T) {
	if got := FormatNodePorts([]uint16{80, 443}); got != "80,443" {
		t.Fatalf("format = %q", got)
	}
	if got := ParseNodePorts(" 80, x, 0, 70000, 443 ,"); !slices.Equal(got, []uint16{80, 443}) {
		t.Fatalf("parse = %v", got)
	}
	if ParseNodePorts("") != nil {
		t.Fatal("empty")
	}
}

// TestNodeAddrCache: the interface list is read at most once per TTL, a
// stale list is refreshed, and a failed read keeps the last good list.
func TestNodeAddrCache(t *testing.T) {
	calls := stubNodeAddrs(t, "10.250.1.5")
	for range 5 {
		if !isNodeAddr(netip.MustParseAddr("10.250.1.5")) {
			t.Fatal("node address")
		}
	}
	if *calls != 1 {
		t.Fatalf("read %d times within the TTL", *calls)
	}
	old := nodeAddrs.Load()
	nodeAddrs.Store(&nodeAddrSet{at: time.Now().Add(-2 * nodeAddrTTL), addr: old.addr})
	isNodeAddr(netip.MustParseAddr("10.250.1.5"))
	if *calls != 2 {
		t.Fatalf("a stale list must be re-read: %d", *calls)
	}
	interfaceAddrs = func() ([]net.Addr, error) { return nil, errors.New("netlink hiccup") }
	nodeAddrs.Store(&nodeAddrSet{at: time.Now().Add(-2 * nodeAddrTTL), addr: old.addr})
	if !isNodeAddr(netip.MustParseAddr("10.250.1.5")) {
		t.Fatal("a failed read keeps the last good list")
	}
	nodeAddrs.Store(nil)
	if isNodeAddr(netip.MustParseAddr("10.250.1.5")) {
		t.Fatal("with no list at all, nothing is known to be the node")
	}
}

func TestSetNodeAddrsSource(t *testing.T) {
	restore := SetNodeAddrsSource(func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("10.250.9.9"), Mask: net.CIDRMask(24, 32)}}, nil
	})
	if !isNodeAddr(netip.MustParseAddr("10.250.9.9")) {
		t.Fatal("the replaced source is used")
	}
	restore()
	if isNodeAddr(netip.MustParseAddr("10.250.9.9")) {
		t.Fatal("restore puts the real source back")
	}
}

package egress

import (
	"net/netip"
	"slices"
	"testing"
)

// TestNodeWideElems (§5.10 PC-2): every bridge subnet gets every floor CIDR
// and every control endpoint; IPv6 and zero ports are skipped.
func TestNodeWideElems(t *testing.T) {
	nw := NodeWide{
		Subnets: []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16"), netip.MustParsePrefix("10.88.0.5/16"), netip.MustParsePrefix("fd00::/64")},
		Floor:   []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd01::/64")},
		Control: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.5:21212"), netip.MustParseAddrPort("10.0.0.5:0"), netip.MustParseAddrPort("[::1]:7002")},
	}
	floor, control := nw.elems()
	if len(floor) != 2 || len(control) != 2 {
		t.Fatalf("floor=%v control=%v", floor, control)
	}
	want := Elem{Src: netip.MustParseAddr("10.88.0.0"), SrcEnd: netip.MustParseAddr("10.88.255.255"),
		Dst: netip.MustParseAddr("10.20.0.0"), DstEnd: netip.MustParseAddr("10.20.255.255")}
	if floor[1] != want {
		t.Fatalf("floor elem = %+v, want %+v (subnet masked)", floor[1], want)
	}
	if control[0].Dst != netip.MustParseAddr("10.0.0.5") || control[0].Port != 21212 || control[0].SrcEnd != netip.MustParseAddr("172.17.255.255") {
		t.Fatalf("control elem = %+v", control[0])
	}
}

// TestNodeWideControlPools: a pool is one element per bridge subnet and
// port, its whole range as the destination; an endpoint the pool covers is
// left to it (the set's intervals may not overlap), one it doesn't cover
// (another port, another address) stays; IPv6, invalid and zero entries
// are skipped, and a repeated port counts once.
func TestNodeWideControlPools(t *testing.T) {
	pool := ControlPool{Prefix: netip.MustParsePrefix("172.16.3.9/16"), Ports: []uint16{21212, 22, 0, 22}}
	nw := NodeWide{
		Subnets: []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16"), netip.MustParsePrefix("172.16.0.0/16")},
		Control: []netip.AddrPort{
			netip.MustParseAddrPort("172.16.0.1:21212"), // a TAP address: the pool has it
			netip.MustParseAddrPort("172.16.0.5:7000"),  // a port the pool doesn't list
			netip.MustParseAddrPort("10.0.0.5:21212"),
		},
		ControlPools: []ControlPool{pool, {Prefix: netip.MustParsePrefix("fd00::/64"), Ports: []uint16{22}}, {Ports: []uint16{22}}},
	}
	_, control := nw.elems()
	if len(control) != 2*(2+2) {
		t.Fatalf("control = %d elems %+v, want 2 subnets x (2 endpoints + 2 pool ports)", len(control), control)
	}
	want := Elem{Src: netip.MustParseAddr("172.17.0.0"), SrcEnd: netip.MustParseAddr("172.17.255.255"),
		Dst: netip.MustParseAddr("172.16.0.0"), DstEnd: netip.MustParseAddr("172.16.255.255"), Port: 21212}
	if !slices.Contains(control, want) {
		t.Fatalf("pool element %+v missing from %+v", want, control)
	}
	for _, e := range control {
		if e.Dst == netip.MustParseAddr("172.16.0.1") {
			t.Fatalf("an endpoint the pool covers was listed too: %+v", e)
		}
	}
	if !nw.pooled(netip.MustParseAddrPort("172.16.200.1:22")) || nw.pooled(netip.MustParseAddrPort("172.16.0.1:7000")) || nw.pooled(netip.MustParseAddrPort("172.18.0.1:22")) {
		t.Fatal("pooled")
	}
	// Remembered and put back after a rebuild, like the rest.
	g, be, _ := newTestGateway(t)
	nw.ControlKnown = true
	if err := g.SetNodeWide(nw); err != nil {
		t.Fatal(err)
	}
	if be.Len(SetNodeControl) != len(control) || !be.Has(SetNodeControl, want) {
		t.Fatalf("applied %d", be.Len(SetNodeControl))
	}
	be.DropLayout()
	if err := g.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if !be.Has(SetNodeControl, want) {
		t.Fatal("a rebuilt table must get the pools back")
	}
}

// TestSetNodeWide: replaced atomically, remembered, put back after a table
// rebuild, and the control set is left alone until sandboxd has sent it.
func TestSetNodeWide(t *testing.T) {
	g, be, _ := newTestGateway(t)
	nw := NodeWide{
		Subnets: []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")},
		Floor:   []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
	}
	pre := Elem{Src: netip.MustParseAddr("172.17.0.0"), SrcEnd: netip.MustParseAddr("172.17.255.255"), Dst: netip.MustParseAddr("10.0.0.9"), Port: 21212}
	if err := be.Replace(map[string][]Elem{SetNodeControl: {pre}}); err != nil {
		t.Fatal(err)
	}
	if err := g.SetNodeWide(nw); err != nil {
		t.Fatal(err)
	}
	if be.Len(SetDenyFloor) != 1 || !be.Has(SetNodeControl, pre) {
		t.Fatal("floor applied; control untouched while unknown")
	}
	nw.Control, nw.ControlKnown = []netip.AddrPort{netip.MustParseAddrPort("10.0.0.5:7002")}, true
	if err := g.SetNodeWide(nw); err != nil {
		t.Fatal(err)
	}
	if be.Len(SetNodeControl) != 1 || be.Has(SetNodeControl, pre) {
		t.Fatal("a known control list replaces the set")
	}
	be.DropLayout()
	if err := g.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if be.Len(SetDenyFloor) != 1 || be.Len(SetNodeControl) != 1 {
		t.Fatal("a rebuilt table must get the node-wide rules back")
	}
	if got := SortedControl([]netip.AddrPort{netip.MustParseAddrPort("10.0.0.9:1"), netip.MustParseAddrPort("10.0.0.1:2")}); got[0].Addr() != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("sorted = %v", got)
	}
}

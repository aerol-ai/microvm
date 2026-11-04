package egress

import (
	"errors"
	"net/netip"
	"testing"
)

// TestMemBackendLayoutReplacement: MemBackend stands in for nft in other
// packages' tests, so it must keep the kernel's layout contract: a matching
// layout is left alone, another one carries the sources and the node-wide
// sets over (with the sources blocked until Sync), and a missing table
// can't be listed.
func TestMemBackendLayoutReplacement(t *testing.T) {
	if _, err := NewMemBackend().List(SetFQDNSrc); !errors.Is(err, ErrLayoutMissing) {
		t.Fatalf("List without a layout = %v, want ErrLayoutMissing", err)
	}
	be := NewMemBackend()
	cfg := LayoutConfig{DNSPort: 1, ProxyPort: 2}
	if err := be.EnsureLayout(cfg); err != nil {
		t.Fatal(err)
	}
	src := Elem{Src: ipA}
	floor := Elem{Src: netip.MustParseAddr("10.88.0.0"), SrcEnd: netip.MustParseAddr("10.88.255.255"),
		Dst: netip.MustParseAddr("10.20.0.0"), DstEnd: netip.MustParseAddr("10.20.255.255")}
	if err := be.Apply([]Op{{Set: SetFQDNSrc, Elems: []Elem{src}}, {Set: SetDenyFloor, Elems: []Elem{floor}}}); err != nil {
		t.Fatal(err)
	}
	if err := be.EnsureLayout(cfg); err != nil || !be.Has(SetFQDNSrc, src) || be.Has(SetBlockedSrc, src) {
		t.Fatalf("a matching layout must be left untouched: %v", err)
	}
	if err := be.EnsureLayout(LayoutConfig{DNSPort: 3, ProxyPort: 4}); err != nil {
		t.Fatal(err)
	}
	if !be.Has(SetFQDNSrc, src) || !be.Has(SetDenyFloor, floor) {
		t.Fatal("a replaced layout must carry the sources and the floor")
	}
	if !be.Has(SetBlockedSrc, src) {
		t.Fatal("a carried source must stay blocked until the next Sync")
	}
	if got, err := be.List(SetNodeControl); err != nil || len(got) != 0 {
		t.Fatalf("a set the old layout lacked starts empty: %v, %v", got, err)
	}
}

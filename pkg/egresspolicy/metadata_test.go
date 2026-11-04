package egresspolicy

import (
	"net/netip"
	"slices"
	"testing"
)

// TestWithMetadataFloor: the metadata endpoints are added to any floor once,
// after the operator's entries, and the caller's slice is not modified.
func TestWithMetadataFloor(t *testing.T) {
	if got := WithMetadataFloor(nil); !slices.Equal(got, MetadataPrefixes) {
		t.Fatalf("no floor = %v", got)
	}
	op := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), MetadataPrefixes[0]}
	got := WithMetadataFloor(op)
	if len(got) != 1+len(MetadataPrefixes) || got[0] != op[0] || got[1] != MetadataPrefixes[0] {
		t.Fatalf("with an operator floor = %v", got)
	}
	if len(op) != 2 {
		t.Fatal("the operator's floor was modified")
	}
	for _, p := range MetadataPrefixes {
		if err := (DialGuard{}).CheckFloor(netip.AddrPortFrom(p.Addr(), 80)); err == nil {
			t.Errorf("%s passes the floor", p)
		}
	}
}

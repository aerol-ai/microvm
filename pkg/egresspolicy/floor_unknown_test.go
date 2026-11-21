package egresspolicy

import (
	"errors"
	"net/netip"
	"testing"
)

// A process that cannot read the floor file fails closed: every address
// counts as on the floor until it can again.
func TestFileFloorUnknownRefusesEverything(t *testing.T) {
	t.Cleanup(func() { SetFileFloorUnknown(false) })
	g := DialGuard{}
	public := netip.MustParseAddrPort("1.1.1.1:443")
	if err := g.CheckFloor(public); err != nil {
		t.Fatalf("known floor refused a public address: %v", err)
	}
	SetFileFloorUnknown(true)
	if !FileFloorUnknown() {
		t.Fatal("unknown not recorded")
	}
	err := g.CheckFloor(public)
	var de *DialError
	if !errors.As(err, &de) || de.Reason != DialReasonDenyFloor || de.Rule != "floor file unreadable" {
		t.Fatalf("unknown floor = %v", err)
	}
	if err := g.Check(nil, DialTarget{Addr: public}); err == nil {
		t.Fatal("policy check passed with the floor unknown")
	}
	SetFileFloorUnknown(false)
	if err := g.CheckFloor(public); err != nil {
		t.Fatalf("floor known again, still refused: %v", err)
	}
}

func TestParseFloorFile(t *testing.T) {
	got, err := ParseFloorFile("/f", []byte("10.0.0.1\n10.1.0.0/16\n"))
	if err != nil || len(got) != 2 || got[1] != netip.MustParsePrefix("10.1.0.0/16") {
		t.Fatalf("ParseFloorFile = %v, %v", got, err)
	}
	if _, err := ParseFloorFile("/f", []byte("nope\n")); err == nil {
		t.Fatal("bad floor parsed")
	}
}

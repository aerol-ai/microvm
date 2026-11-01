package egress

import (
	"fmt"
	"net/netip"
	"testing"
)

// TestAttachIsOneTransaction guards the per-attach cost the create budget
// (plans/egress-domain-filtering.md §8.2) rests on: attaching a sandbox is
// one incremental batch of set elements, whatever else is attached; a
// re-attach of an unchanged spec (a retried or duplicate create) writes
// nothing; and a detach is one batch again. No attach ever rewrites a whole
// set (Replace is the full Sync's alone).
func TestAttachIsOneTransaction(t *testing.T) {
	g, be, _ := newTestGateway(t)
	for i := 0; i < 100; i++ {
		ip := netip.AddrFrom4([4]byte{10, 88, 1, byte(i + 2)})
		if err := g.Attach(Spec{ID: fmt.Sprintf("other-%d", i), IP: ip, AllowOut: []string{"pypi.org", "10.0.0.0/8"}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name string
		spec Spec
	}{
		{"allowlist", Spec{ID: "sb", IP: ipA, AllowOut: []string{"pypi.org", "files.pythonhosted.org"}}},
		{"allowlist with cidrs", Spec{ID: "sb", IP: ipA, AllowOut: []string{"pypi.org", "10.0.0.0/8", "1.2.3.4/32"}}},
		{"denylist", Spec{ID: "sb", IP: ipA, AllowOut: []string{"pypi.org"}, DenyOut: []string{"0.0.0.0/0"}}},
		{"learn", Spec{ID: "sb", IP: ipA, Learn: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := be.Calls
			if err := g.Attach(tc.spec); err != nil {
				t.Fatal(err)
			}
			if got := be.Calls - before; got != 1 {
				t.Fatalf("attach made %d transactions, want 1", got)
			}
			if err := g.Attach(tc.spec); err != nil {
				t.Fatal(err)
			}
			if got := be.Calls - before; got != 1 {
				t.Fatalf("an unchanged re-attach wrote again (%d transactions)", got)
			}
			if err := g.Detach(tc.spec.ID, tc.spec.IP); err != nil {
				t.Fatal(err)
			}
			if got := be.Calls - before; got != 2 {
				t.Fatalf("attach+detach made %d transactions, want 2", got)
			}
			for _, set := range managedSets {
				elems, _ := be.List(set)
				for _, e := range elems {
					if e.Src == tc.spec.IP {
						t.Fatalf("detach left %s in %s", e.Src, set)
					}
				}
			}
		})
	}
}

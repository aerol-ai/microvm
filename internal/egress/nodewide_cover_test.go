package egress

import (
	"errors"
	"net/netip"
	"testing"
)

// TestSetNodeWideFailedWrite: a refused transaction is not remembered, so a
// table rebuild puts back what the kernel last held, not rules it never got.
func TestSetNodeWideFailedWrite(t *testing.T) {
	g, be, _ := newTestGateway(t)
	be.FailApply = errors.New("netlink: EBUSY")
	nw := NodeWide{Subnets: []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")}, Floor: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	if err := g.SetNodeWide(nw); !errors.Is(err, be.FailApply) {
		t.Fatalf("err = %v, want the backend's", err)
	}
	if got := g.NodeWideState(); len(got.Subnets) != 0 {
		t.Fatalf("remembered %+v after a failed write", got)
	}
}

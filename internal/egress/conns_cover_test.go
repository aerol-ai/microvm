package egress

import (
	"net"
	"net/netip"
	"testing"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// TestTrackedConnDsts: a keep-alive exchange that redials an upstream
// records it once, and one that reaches more than maxTrackedDsts keeps the
// latest, so the operator guard checks what the connection talks to now.
func TestTrackedConnDsts(t *testing.T) {
	g, _, _ := newTestGateway(t)
	a, b := net.Pipe()
	defer b.Close()
	tc := g.Track("sb", "pypi.org", 443, a)
	defer tc.Close()
	first := netip.MustParseAddrPort("1.1.1.1:443")
	tc.AddDst(first)
	tc.AddDst(first)
	if len(tc.dsts) != 1 {
		t.Fatalf("dsts = %v, want one", tc.dsts)
	}
	var last netip.AddrPort
	for i := 0; i < maxTrackedDsts; i++ {
		last = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 443)
		tc.AddDst(last)
	}
	if len(tc.dsts) != maxTrackedDsts || tc.dsts[0] == first || tc.dsts[maxTrackedDsts-1] != last {
		t.Fatalf("dsts = %v, want the latest %d", tc.dsts, maxTrackedDsts)
	}
}

// TestSourcePermitsAndRevoked: the proxy's test for a connection registered
// after a policy change's sweep. Under unchanged rules a connection is
// revoked exactly when it is no longer permitted; a rule change revokes one
// that is still permitted, since it must be decided again.
func TestSourcePermitsAndRevoked(t *testing.T) {
	g, _, _ := newTestGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org", "10.0.0.0/8")); err != nil {
		t.Fatal(err)
	}
	allow, ok := g.Source(ipA)
	if !ok || allow.Mode != ModeAllowlist {
		t.Fatalf("source = %+v, %v", allow, ok)
	}
	cases := []struct {
		name string
		src  Source
		host string
		port uint16
		want bool
	}{
		{"allowed host", allow, "pypi.org", 443, true},
		{"other host", allow, "evil.com", 443, false},
		{"allowed address", allow, "10.1.2.3", 22, true},
		{"other address", allow, "192.0.2.1", 22, false},
		{"denylist admits", Source{Mode: ModeDenylist}, "evil.com", 443, true},
		{"allowlist without a policy", Source{Mode: ModeAllowlist}, "pypi.org", 443, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.src.Permits(tc.host, tc.port); got != tc.want {
				t.Fatalf("Permits = %v, want %v", got, tc.want)
			}
			if got := tc.src.Revoked(tc.src.Rules, tc.host, tc.port); got != !tc.want {
				t.Fatalf("Revoked under unchanged rules = %v, want %v", got, !tc.want)
			}
		})
	}
	admitted, err := egresspolicy.CompileRules([]egresspolicy.RuleSpec{{Host: "pypi.org", Methods: []string{"GET"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !allow.Revoked(admitted, "pypi.org", 80) {
		t.Fatal("a connection admitted under rules the source no longer has must be revoked")
	}
}

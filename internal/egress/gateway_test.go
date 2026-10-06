package egress

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

var (
	ipA = netip.MustParseAddr("10.88.0.10")
	ipB = netip.MustParseAddr("10.88.0.11")
)

type flushRecorder struct {
	mu  sync.Mutex
	ips []netip.Addr
	err error
}

func (f *flushRecorder) FlushSource(ip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ips = append(f.ips, ip)
	return f.err
}

func (f *flushRecorder) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ips)
}

func newTestGateway(t *testing.T) (*Gateway, *MemBackend, *flushRecorder) {
	t.Helper()
	be := NewMemBackend()
	ct := &flushRecorder{}
	g := New(Options{Backend: be, Conntrack: ct, Layout: LayoutConfig{DNSPort: 53054, ProxyPort: 15080}})
	if err := g.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	return g, be, ct
}

func allowSpec(id string, ip netip.Addr, allow ...string) Spec {
	return Spec{ID: id, IP: ip, AllowOut: allow}
}

func TestAttachInstallsElementsPerMode(t *testing.T) {
	cases := []struct {
		name    string
		spec    Spec
		modeSet string
	}{
		{"allowlist", Spec{ID: "sb", IP: ipA, AllowOut: []string{"pypi.org", "10.0.0.0/8", "1.2.3.4/32"}}, SetSrcDenyDefault},
		{"mixed allow-wins", Spec{ID: "sb", IP: ipA, AllowOut: []string{"pypi.org", "10.0.0.0/8", "1.2.3.4/32"}, DenyOut: []string{"10.1.0.0/16"}}, SetSrcAccept},
		{"learn", Spec{ID: "sb", IP: ipA, Learn: true}, SetLearnSrc},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, be, _ := newTestGateway(t)
			if err := g.Attach(tc.spec); err != nil {
				t.Fatal(err)
			}
			if !be.Has(SetFQDNSrc, Elem{Src: ipA}) || !be.Has(tc.modeSet, Elem{Src: ipA}) {
				t.Fatal("source not in fqdn_src and its mode set")
			}
			if tc.spec.Learn {
				return
			}
			want := Elem{Src: ipA, Dst: netip.MustParseAddr("10.0.0.0"), DstEnd: netip.MustParseAddr("10.255.255.255")}
			if !be.Has(SetAllowCIDR, want) {
				t.Fatal("allow CIDR interval missing")
			}
			if !be.Has(SetAllowCIDR, Elem{Src: ipA, Dst: netip.MustParseAddr("1.2.3.4"), DstEnd: netip.MustParseAddr("1.2.3.4")}) {
				t.Fatal("a /32 must be a one-address interval")
			}
			if be.Len(SetAllowCIDR) != 2 {
				t.Fatalf("hostnames must not reach the nft layer; allow_cidr=%d", be.Len(SetAllowCIDR))
			}
			if be.Len(SetDenyCIDR) != len(tc.spec.DenyOut) {
				t.Fatal("deny CIDRs not installed")
			}
			if be.Has(SetBlockedSrc, Elem{Src: ipA}) {
				t.Fatal("unblocked sandbox in blocked_src")
			}
			src, ok := g.Source(ipA)
			if !ok || src.Policy == nil {
				t.Fatal("Source must expose the compiled policy")
			}
			if allowed, _ := src.Policy.MatchHost("pypi.org"); !allowed {
				t.Fatal("compiled matcher must allow pypi.org")
			}
		})
	}
}

func TestAttachRejectsBadSpecs(t *testing.T) {
	g, _, _ := newTestGateway(t)
	bad := []Spec{
		{IP: ipA, AllowOut: []string{"pypi.org"}},
		{ID: "x", IP: netip.MustParseAddr("fd00::1"), AllowOut: []string{"pypi.org"}},
		{ID: "x", IP: ipA, DenyOut: []string{"evil.com"}},
		{ID: "x", IP: ipA, AllowOut: []string{"*.com"}},
		{ID: "x", IP: ipA, DenyOut: []string{"0.0.0.0/0"}},
		{ID: "x", IP: ipA, AllowOut: []string{"2001:db8::/32"}},
	}
	for i, s := range bad {
		if err := g.Attach(s); err == nil {
			t.Fatalf("case %d (%+v): want error", i, s)
		}
	}
}

// TestRecycledIPOwnership is the D5 regression: a new owner attaches before
// the old owner's late Detach; the new owner stays redirected and restricted
// and inherits nothing learned.
func TestRecycledIPOwnership(t *testing.T) {
	g, be, _ := newTestGateway(t)
	if err := g.Attach(allowSpec("old", ipA, "github.com:22")); err != nil {
		t.Fatal(err)
	}
	if err := g.AddLearned("old", netip.MustParseAddr("140.82.112.3"), 22, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := g.Attach(allowSpec("new", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	if be.Len(SetAllowLearned) != 0 {
		t.Fatal("new owner inherited the old owner's learned elements")
	}
	if err := g.Detach("old", ipA); err != nil {
		t.Fatal(err)
	}
	if !be.Has(SetFQDNSrc, Elem{Src: ipA}) || !be.Has(SetSrcDenyDefault, Elem{Src: ipA}) {
		t.Fatal("late Detach of the old owner removed the new owner's redirect")
	}
	spec, _, ok := g.Lookup(ipA)
	if !ok || spec.ID != "new" {
		t.Fatalf("Lookup(ipA) = %+v, %v", spec, ok)
	}
}

func TestDetachRemovesEverything(t *testing.T) {
	g, be, ct := newTestGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "10.0.0.0/8", "github.com:22")); err != nil {
		t.Fatal(err)
	}
	if err := g.AddLearned("sb", netip.MustParseAddr("140.82.112.3"), 22, time.Minute); err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	defer c2.Close()
	g.Track("sb", "github.com", c1)
	if err := g.Detach("sb", ipA); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{SetFQDNSrc, SetSrcDenyDefault, SetAllowCIDR, SetAllowLearned} {
		if be.Len(s) != 0 {
			t.Fatalf("%s still has elements after Detach", s)
		}
	}
	if g.ConnCount("sb") != 0 {
		t.Fatal("tracked connection survived Detach")
	}
	if ct.count() == 0 {
		t.Fatal("conntrack not flushed on Detach")
	}
	if err := g.Detach("sb", ipA); err != nil {
		t.Fatal("Detach must be idempotent")
	}
}

// TestBlockReasonsAreKeyed covers eng re-review D2: the sandbox stays in
// @blocked_src while any kernel reason is set; the restart block never
// reaches the kernel.
func TestBlockReasonsAreKeyed(t *testing.T) {
	g, be, ct := newTestGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	defer c2.Close()
	g.Track("sb", "pypi.org", c1)
	if err := g.SetBlocked("sb", BlockAll, true); err != nil {
		t.Fatal(err)
	}
	if !be.Has(SetBlockedSrc, Elem{Src: ipA}) || !be.Has(SetFQDNSrc, Elem{Src: ipA}) {
		t.Fatal("blocked sandbox must be in blocked_src AND stay in fqdn_src")
	}
	if g.ConnCount("sb") != 0 || ct.count() == 0 {
		t.Fatal("blocking must close tracked conns and flush conntrack")
	}
	if err := g.SetBlocked("sb", BlockQuota, true); err != nil {
		t.Fatal(err)
	}
	if err := g.SetBlocked("sb", BlockQuota, false); err != nil {
		t.Fatal(err)
	}
	if !be.Has(SetBlockedSrc, Elem{Src: ipA}) || !g.IsBlocked("sb") {
		t.Fatal("lifting quota must not lift block-all")
	}
	if err := g.SetBlocked("sb", BlockAll, false); err != nil {
		t.Fatal(err)
	}
	if be.Has(SetBlockedSrc, Elem{Src: ipA}) || g.IsBlocked("sb") {
		t.Fatal("no reasons left: sandbox must be unblocked")
	}
	if err := g.SetBlocked("sb", BlockRestart, true); err != nil {
		t.Fatal(err)
	}
	if be.Has(SetBlockedSrc, Elem{Src: ipA}) {
		t.Fatal("restart block must stay in memory")
	}
	if !g.IsBlocked("sb") {
		t.Fatal("restart block must still make the DNS filter and proxy deny")
	}
	if err := g.SetBlocked("ghost", BlockAll, true); !errors.Is(err, ErrNotAttached) {
		t.Fatalf("unknown sandbox err = %v", err)
	}
}

// TestSetBlockedFailedWriteKeepsInMemoryBlock: if the nft write fails, the
// in-memory bit still denies at the DNS filter and proxy (S3).
func TestSetBlockedFailedWriteKeepsInMemoryBlock(t *testing.T) {
	g, be, _ := newTestGateway(t)
	if err := g.Attach(allowSpec("sb", ipA)); err != nil {
		t.Fatal(err)
	}
	be.FailApply = errors.New("netlink: busy")
	if err := g.SetBlocked("sb", BlockHold, true); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if !g.IsBlocked("sb") {
		t.Fatal("failed write must leave the in-memory block set")
	}
}

// TestAttachKeepsExistingBlocks: an Attach (re-apply, PUT, profile fan-out)
// never lifts a block the gateway holds; only SetBlocked lifts.
func TestAttachKeepsExistingBlocks(t *testing.T) {
	g, be, _ := newTestGateway(t)
	if err := g.Attach(allowSpec("sb", ipA)); err != nil {
		t.Fatal(err)
	}
	if err := g.SetBlocked("sb", BlockQuota, true); err != nil {
		t.Fatal(err)
	}
	if err := g.Update(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	if !be.Has(SetBlockedSrc, Elem{Src: ipA}) {
		t.Fatal("Update re-opened a quota-blocked sandbox")
	}
	spec := allowSpec("sb2", ipB)
	spec.Blocked = BlockHold
	if err := g.Attach(spec); err != nil {
		t.Fatal(err)
	}
	if !be.Has(SetBlockedSrc, Elem{Src: ipB}) {
		t.Fatal("Attach must apply the spec's block reasons in the same batch")
	}
}

func TestUpdateNarrowingFlushesLearned(t *testing.T) {
	g, be, ct := newTestGateway(t)
	if err := g.Update(allowSpec("ghost", ipA)); !errors.Is(err, ErrNotAttached) {
		t.Fatalf("update of unknown sandbox err = %v", err)
	}
	if err := g.Attach(allowSpec("sb", ipA, "github.com:22", "10.0.0.0/8")); err != nil {
		t.Fatal(err)
	}
	if err := g.AddLearned("sb", netip.MustParseAddr("140.82.112.3"), 22, time.Minute); err != nil {
		t.Fatal(err)
	}
	before := ct.count()
	if err := g.Update(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	if be.Len(SetAllowLearned) != 0 || be.Len(SetAllowCIDR) != 0 {
		t.Fatal("narrowing must flush learned elements and drop removed CIDRs")
	}
	if ct.count() == before {
		t.Fatal("narrowing must flush conntrack for the source")
	}
}

func TestAttachMovesIP(t *testing.T) {
	g, be, _ := newTestGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "10.0.0.0/8")); err != nil {
		t.Fatal(err)
	}
	if err := g.Attach(allowSpec("sb", ipB, "10.0.0.0/8")); err != nil {
		t.Fatal(err)
	}
	if be.Has(SetFQDNSrc, Elem{Src: ipA}) || !be.Has(SetFQDNSrc, Elem{Src: ipB}) {
		t.Fatal("re-attach on a new IP must move the elements")
	}
	if _, _, ok := g.Lookup(ipA); ok {
		t.Fatal("old IP still maps to the sandbox")
	}
}

func TestAttachFailureChangesNothing(t *testing.T) {
	g, be, _ := newTestGateway(t)
	be.FailApply = errors.New("netlink: busy")
	if err := g.Attach(allowSpec("sb", ipA)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if _, _, ok := g.Lookup(ipA); ok {
		t.Fatal("failed attach must not register the sandbox")
	}
	be.FailApply = nil
	be.DropLayout()
	if err := g.Attach(allowSpec("sb", ipA)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing layout err = %v", err)
	}
	if err := g.CheckLayout(); !errors.Is(err, ErrLayoutMissing) {
		t.Fatalf("CheckLayout = %v", err)
	}
}

// TestSyncReplacesAndPreservesLearned covers D13: managed sets are replaced
// atomically; learned elements survive for unchanged sandboxes and are
// flushed for removed or changed ones; Sync lifts the restart block.
func TestSyncReplacesAndPreservesLearned(t *testing.T) {
	g, be, _ := newTestGateway(t)
	keep := allowSpec("keep", ipA, "github.com:22")
	gone := allowSpec("gone", ipB, "github.com:22")
	for _, s := range []Spec{keep, gone} {
		if err := g.Attach(s); err != nil {
			t.Fatal(err)
		}
	}
	gh := netip.MustParseAddr("140.82.112.3")
	_ = g.AddLearned("keep", gh, 22, time.Minute)
	_ = g.AddLearned("gone", gh, 22, time.Minute)
	if err := g.Restore([]Spec{keep}); err != nil {
		t.Fatal(err)
	}
	if !g.IsBlocked("keep") {
		t.Fatal("restored sandbox must be restart-blocked until Sync")
	}
	newIP := netip.MustParseAddr("10.88.0.12")
	if err := g.Sync([]Spec{keep, allowSpec("fresh", newIP)}); err != nil {
		t.Fatal(err)
	}
	if g.IsBlocked("keep") {
		t.Fatal("Sync must lift the restart block")
	}
	if !be.Has(SetAllowLearned, Elem{Src: ipA, Dst: gh, Port: 22}) {
		t.Fatal("unchanged sandbox lost its learned element")
	}
	if be.Has(SetAllowLearned, Elem{Src: ipB, Dst: gh, Port: 22}) {
		t.Fatal("removed sandbox kept its learned element")
	}
	if be.Has(SetFQDNSrc, Elem{Src: ipB}) || !be.Has(SetFQDNSrc, Elem{Src: newIP}) {
		t.Fatal("Sync did not replace source sets")
	}
	if err := g.Sync([]Spec{{ID: "bad", IP: ipA, DenyOut: []string{"evil.com"}}}); err == nil {
		t.Fatal("Sync must validate specs")
	}
	be.FailApply = errors.New("busy")
	if err := g.Sync(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Sync failure err = %v", err)
	}
	if _, _, ok := g.Lookup(ipA); !ok {
		t.Fatal("failed Sync must leave state untouched")
	}
}

// TestAddLearnedShadowAndCap covers D18 (no write while more than half the
// TTL is left) and EF-62 (cap fails closed).
func TestAddLearnedShadowAndCap(t *testing.T) {
	be := NewMemBackend()
	now := time.Unix(1_700_000_000, 0)
	g := New(Options{Backend: be, LearnedMax: 2, Now: func() time.Time { return now }})
	if err := g.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := g.AddLearned("sb", netip.MustParseAddr("1.1.1.1"), 22, time.Minute); !errors.Is(err, ErrNotAttached) {
		t.Fatalf("unattached err = %v", err)
	}
	if err := g.Attach(allowSpec("sb", ipA, "github.com:22")); err != nil {
		t.Fatal(err)
	}
	d1 := netip.MustParseAddr("140.82.112.3")
	if err := g.AddLearned("sb", d1, 22, time.Minute); err != nil {
		t.Fatal(err)
	}
	calls := be.Calls
	now = now.Add(20 * time.Second)
	if err := g.AddLearned("sb", d1, 22, time.Minute); err != nil {
		t.Fatal(err)
	}
	if be.Calls != calls {
		t.Fatal("refresh within half the TTL must not write")
	}
	now = now.Add(20 * time.Second)
	if err := g.AddLearned("sb", d1, 22, time.Minute); err != nil {
		t.Fatal(err)
	}
	if be.Calls != calls+1 {
		t.Fatal("refresh past half the TTL must write once")
	}
	if err := g.AddLearned("sb", netip.MustParseAddr("140.82.112.4"), 22, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := g.AddLearned("sb", netip.MustParseAddr("140.82.112.5"), 22, time.Minute); !errors.Is(err, ErrLearnedCap) {
		t.Fatalf("cap err = %v, want ErrLearnedCap", err)
	}
	now = now.Add(2 * time.Minute)
	if err := g.AddLearned("sb", netip.MustParseAddr("140.82.112.5"), 22, time.Minute); err != nil {
		t.Fatalf("expired entries must free cap space: %v", err)
	}
	if err := g.AddLearned("sb", netip.MustParseAddr("fd00::1"), 22, time.Minute); err == nil {
		t.Fatal("IPv6 learned destination must be refused")
	}
	be.FailApply = errors.New("busy")
	if err := g.AddLearned("sb", netip.MustParseAddr("140.82.112.9"), 22, time.Minute); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failed write err = %v", err)
	}
}

func TestSpecsAndConnRegistry(t *testing.T) {
	g, _, _ := newTestGateway(t)
	_ = g.Attach(allowSpec("b", ipB))
	_ = g.Attach(allowSpec("a", ipA))
	_ = g.SetBlocked("a", BlockAll, true)
	specs := g.Specs()
	if len(specs) != 2 || specs[0].ID != "a" || specs[0].Blocked != BlockAll {
		t.Fatalf("Specs = %+v", specs)
	}
	c1, c2 := net.Pipe()
	defer c2.Close()
	c3, c4 := net.Pipe()
	defer c4.Close()
	g.Track("b", "pypi.org", c1)
	g.Track("b", "github.com", c3)
	if n := g.CloseConnsWhere("b", func(h string) bool { return h == "github.com" }); n != 1 {
		t.Fatalf("closed %d, want 1", n)
	}
	if g.ConnCount("b") != 1 {
		t.Fatal("only the non-matching connection should remain")
	}
	if !g.IsBlocked("nobody") {
		t.Fatal("an unknown sandbox must read as blocked")
	}
}

func TestConntrackErrorIsLoggedNotFatal(t *testing.T) {
	g, _, ct := newTestGateway(t)
	ct.err = errors.New("no conntrack")
	if err := g.Attach(allowSpec("sb", ipA)); err != nil {
		t.Fatal(err)
	}
	if err := g.Detach("sb", ipA); err != nil {
		t.Fatalf("conntrack failure must not fail Detach: %v", err)
	}
}

func TestLastAddr(t *testing.T) {
	cases := map[string]string{
		"10.0.0.0/8":     "10.255.255.255",
		"1.2.3.4/32":     "1.2.3.4",
		"192.168.1.0/24": "192.168.1.255",
		"0.0.0.0/0":      "255.255.255.255",
	}
	for in, want := range cases {
		if got := lastAddr(netip.MustParsePrefix(in)); got.String() != want {
			t.Fatalf("lastAddr(%s) = %s, want %s", in, got, want)
		}
	}
}

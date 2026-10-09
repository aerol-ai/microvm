package egress

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

var errGatewayCover = errors.New("backend write refused")

// gatewayCoverBackend fails chosen calls of a MemBackend, so one write or
// listing can fail while every other one goes through.
type gatewayCoverBackend struct {
	*MemBackend
	ensureErr error
	failApply func(ops []Op) bool
	failList  func(set string) bool
}

func (b *gatewayCoverBackend) EnsureLayout(cfg LayoutConfig) error {
	if b.ensureErr != nil {
		return b.ensureErr
	}
	return b.MemBackend.EnsureLayout(cfg)
}

func (b *gatewayCoverBackend) Apply(ops []Op) error {
	if b.failApply != nil && b.failApply(ops) {
		return errGatewayCover
	}
	return b.MemBackend.Apply(ops)
}

func (b *gatewayCoverBackend) List(set string) ([]Elem, error) {
	if b.failList != nil && b.failList(set) {
		return nil, errGatewayCover
	}
	return b.MemBackend.List(set)
}

func newGatewayCoverGateway(t *testing.T) (*Gateway, *gatewayCoverBackend, *flushRecorder) {
	t.Helper()
	be := &gatewayCoverBackend{MemBackend: NewMemBackend()}
	ct := &flushRecorder{}
	g := New(Options{Backend: be, Conntrack: ct, Layout: LayoutConfig{DNSPort: 53054, ProxyPort: 15080}})
	if err := g.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	return g, be, ct
}

// gatewayCoverBlockedWrite matches the single-op @blocked_src write a block
// change makes, so the attach batch around it still goes through.
func gatewayCoverBlockedWrite(del bool) func([]Op) bool {
	return func(ops []Op) bool {
		return len(ops) == 1 && ops[0].Set == SetBlockedSrc && ops[0].Del == del
	}
}

func gatewayCoverLearnedDelete(ops []Op) bool {
	for _, op := range ops {
		if op.Set == SetAllowLearned && op.Del {
			return true
		}
	}
	return false
}

func TestGatewayCoverBootstrapFailures(t *testing.T) {
	be := &gatewayCoverBackend{MemBackend: NewMemBackend(), ensureErr: errGatewayCover}
	if err := New(Options{Backend: be}).Bootstrap(); !errors.Is(err, errGatewayCover) || !strings.Contains(err.Error(), "egress layout") {
		t.Fatalf("layout failure = %v", err)
	}

	g, gbe, _ := newGatewayCoverGateway(t)
	nw := NodeWide{
		Subnets: []netip.Prefix{netip.MustParsePrefix("10.88.0.0/16")},
		Floor:   []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")},
	}
	if err := g.SetNodeWide(nw); err != nil {
		t.Fatal(err)
	}
	// The layout matches, so only the remembered node-wide rules are written.
	gbe.FailApply = errGatewayCover
	if err := g.Bootstrap(); !errors.Is(err, errGatewayCover) || !strings.Contains(err.Error(), "node-wide") {
		t.Fatalf("node-wide failure = %v", err)
	}
}

func TestGatewayCoverCompileRejects(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		want string
	}{
		{"rule host is not a hostname", Spec{ID: "sb", IP: ipA, AllowOut: []string{"pypi.org"},
			Rules: []egresspolicy.RuleSpec{{Host: "10.0.0.0/8"}}}, egresspolicy.FieldEgressRules},
		{"IPv6 deny CIDR", Spec{ID: "sb", IP: ipA, AllowOut: []string{"pypi.org"}, DenyOut: []string{"2001:db8::/32"}},
			"IPv6 is not supported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compile(tc.spec); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("compile = %v, want %q", err, tc.want)
			}
		})
	}
}

// A failed purge of a recycled IP's previous owner must fail the attach and
// leave the previous owner in place, not hand its source over half-cleaned.
func TestGatewayCoverPurgeFailureKeepsOwner(t *testing.T) {
	g, be, _ := newGatewayCoverGateway(t)
	if err := g.Attach(allowSpec("old", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	be.FailApply = errGatewayCover
	if err := g.Attach(allowSpec("new", ipA, "pypi.org")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("attach over a failed purge = %v", err)
	}
	if err := g.Detach("old", ipA); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("detach with a failed write = %v", err)
	}
	if s, ok := g.Source(ipA); !ok || s.Spec.ID != "old" {
		t.Fatalf("source owner = %+v %v, want old", s.Spec, ok)
	}
}

// A changed policy whose conntrack flush fails is shut by the gateway; when
// even that block can't be written, the attach still fails and memory keeps
// the sandbox blocked for the DNS filter and proxy.
func TestGatewayCoverAttachCleanupBlockWriteFails(t *testing.T) {
	g, be, ct := newGatewayCoverGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	ct.err = errors.New("conntrack busy")
	be.failApply = gatewayCoverBlockedWrite(false)
	if err := g.Attach(allowSpec("sb", ipA, "github.com")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("attach with failed cleanup = %v", err)
	}
	if !g.IsBlocked("sb") || be.Has(SetBlockedSrc, Elem{Src: ipA}) {
		t.Fatal("cleanup block must hold in memory while its kernel write failed")
	}
}

// The cleanup block of a recycled source is lifted only once its write
// succeeds; a failed lift fails the attach, and RetryDirty finishes it.
func TestGatewayCoverAttachLiftCleanupBlockFails(t *testing.T) {
	g, be, ct := newGatewayCoverGateway(t)
	if err := g.Attach(allowSpec("old", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	ct.err = errors.New("conntrack busy")
	if err := g.Detach("old", ipA); err != nil {
		t.Fatal(err)
	}
	ct.err = nil
	be.failApply = gatewayCoverBlockedWrite(true)
	err := g.Attach(allowSpec("new", ipA, "pypi.org"))
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "lift the cleanup block") {
		t.Fatalf("attach with a failed lift = %v", err)
	}
	if !be.Has(SetBlockedSrc, Elem{Src: ipA}) {
		t.Fatal("source must stay in blocked_src while the lift failed")
	}
	be.failApply = nil
	if err := g.RetryDirty(); err != nil {
		t.Fatal(err)
	}
	if be.Has(SetBlockedSrc, Elem{Src: ipA}) || g.IsBlocked("new") {
		t.Fatal("RetryDirty must lift the cleanup block once it can be written")
	}
}

func TestGatewayCoverRetryDirtyLiftFails(t *testing.T) {
	g, be, ct := newGatewayCoverGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	ct.err = errors.New("conntrack busy")
	if err := g.Attach(allowSpec("sb", ipA, "github.com")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("attach with failed cleanup = %v", err)
	}
	if !be.Has(SetBlockedSrc, Elem{Src: ipA}) {
		t.Fatal("setup: cleanup block not written")
	}
	ct.err = nil
	be.failApply = gatewayCoverBlockedWrite(true)
	if err := g.RetryDirty(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("RetryDirty with a failed lift = %v", err)
	}
	if !be.Has(SetBlockedSrc, Elem{Src: ipA}) {
		t.Fatal("a failed lift must leave the source blocked")
	}
	be.failApply = nil
	if err := g.RetryDirty(); err != nil {
		t.Fatal(err)
	}
	if be.Has(SetBlockedSrc, Elem{Src: ipA}) || g.IsBlocked("sb") {
		t.Fatal("the retried lift must open the source")
	}
}

// Cleanup of a source nobody owns any more finishes without a block to lift.
func TestGatewayCoverRetryDirtyUnownedSource(t *testing.T) {
	g, _, ct := newGatewayCoverGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	ct.err = errors.New("conntrack busy")
	if err := g.Detach("sb", ipA); err != nil {
		t.Fatal(err)
	}
	ct.err = nil
	if err := g.RetryDirty(); err != nil {
		t.Fatal(err)
	}
	if g.cleanupPending(ipA) {
		t.Fatal("conntrack cleanup still pending after RetryDirty")
	}
}

// An attach newer than the Sync's snapshot keeps its source: the stale
// owner the snapshot names for that IP is dropped, not installed over it.
func TestGatewayCoverSyncNewerAttachWinsSource(t *testing.T) {
	g, _, _ := newGatewayCoverGateway(t)
	tok := g.SyncToken()
	if err := g.Attach(allowSpec("new", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	if err := g.SyncFrom(tok, []Spec{allowSpec("old", ipA, "pypi.org")}); err != nil {
		t.Fatal(err)
	}
	specs := g.Specs()
	if len(specs) != 1 || specs[0].ID != "new" {
		t.Fatalf("specs after a stale sync = %+v", specs)
	}
}

func TestGatewayCoverReapplyFailures(t *testing.T) {
	g, be, ct := newGatewayCoverGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	be.FailApply = errGatewayCover
	if err := g.Reapply(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Reapply with a failed replace = %v", err)
	}
	be.FailApply = nil

	// A quota block whose conntrack flush failed leaves cleanup pending
	// after the block lifts; Reapply must shut the source again, and say so
	// when that write fails.
	ct.err = errors.New("conntrack busy")
	if err := g.SetBlocked("sb", BlockQuota, true); err != nil {
		t.Fatal(err)
	}
	if err := g.SetBlocked("sb", BlockQuota, false); err != nil {
		t.Fatal(err)
	}
	be.failApply = gatewayCoverBlockedWrite(false)
	err := g.Reapply()
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "pending cleanup") {
		t.Fatalf("Reapply with a failed cleanup block = %v", err)
	}
	if !g.IsBlocked("sb") {
		t.Fatal("pending cleanup must block the sandbox in memory")
	}
}

// After a restart the shadow is empty, so a Sync finds stale learned
// elements only in the kernel. A failed delete keeps them pending, and the
// next owner of the source waits for them.
func TestGatewayCoverSweepDeleteFailureStaysPending(t *testing.T) {
	g, be, _ := newGatewayCoverGateway(t)
	stale := Elem{Src: ipA, Dst: netip.MustParseAddr("140.82.112.3"), Port: 22}
	if err := be.MemBackend.Apply([]Op{{Set: SetAllowLearned, Elems: []Elem{stale}}}); err != nil {
		t.Fatal(err)
	}
	be.failApply = gatewayCoverLearnedDelete
	if err := g.Sync(nil); err != nil {
		t.Fatal(err)
	}
	if !g.cleanupPending(ipA) {
		t.Fatal("a failed stale delete must stay pending")
	}
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("attach over pending cleanup = %v", err)
	}
	if !g.IsBlocked("sb") {
		t.Fatal("the new owner must stay shut while the stale element is there")
	}
	be.failApply = nil
	if err := g.RetryDirty(); err != nil {
		t.Fatal(err)
	}
	if be.Has(SetAllowLearned, stale) || g.IsBlocked("sb") {
		t.Fatal("RetryDirty must delete the stale element and open the source")
	}
}

// A redone sweep only takes the swept source's elements the shadow doesn't
// know: another source's, and ones learned since the failed listing, stay.
func TestGatewayCoverResweepKeepsOthersAndKnown(t *testing.T) {
	g, be, _ := newGatewayCoverGateway(t)
	if err := g.Attach(allowSpec("a", ipA, "github.com:22")); err != nil {
		t.Fatal(err)
	}
	if err := g.Attach(allowSpec("b", ipB, "github.com:22")); err != nil {
		t.Fatal(err)
	}
	dstB := netip.MustParseAddr("140.82.112.3")
	if err := g.AddLearned("b", dstB, 22, time.Hour); err != nil {
		t.Fatal(err)
	}
	be.failList = func(set string) bool { return set == SetAllowLearned || set == SetBinLearned }
	if err := g.Sync([]Spec{allowSpec("a", ipA, "gitlab.com:22"), allowSpec("b", ipB, "github.com:22")}); err != nil {
		t.Fatal(err)
	}
	if !g.IsBlocked("a") || !g.sweepPendingFor(ipA) {
		t.Fatal("setup: a failed sweep must shut the changed sandbox")
	}
	be.failList = nil
	dstA := netip.MustParseAddr("172.65.251.78")
	if err := g.AddLearned("a", dstA, 22, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := g.RetryDirty(); err != nil {
		t.Fatal(err)
	}
	if !be.Has(SetAllowLearned, Elem{Src: ipB, Dst: dstB, Port: 22}) || !be.Has(SetAllowLearned, Elem{Src: ipA, Dst: dstA, Port: 22}) {
		t.Fatal("resweep removed an element it does not own or already knows")
	}
	if g.IsBlocked("a") {
		t.Fatal("the finished resweep must lift the cleanup block")
	}
}

func TestGatewayCoverRetainBlocksDropsDetachedRecord(t *testing.T) {
	g, _, _ := newGatewayCoverGateway(t)
	for _, s := range []Spec{allowSpec("gone", ipA, "pypi.org"), allowSpec("live", ipB, "pypi.org")} {
		if err := g.Attach(s); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.Detach("gone", ipA); err != nil {
		t.Fatal(err)
	}
	g.RetainBlocks(nil)
	g.mu.RLock()
	_, gone := g.attachWrites["gone"]
	_, live := g.attachWrites["live"]
	g.mu.RUnlock()
	if gone || !live {
		t.Fatalf("attach records after RetainBlocks: gone=%v live=%v", gone, live)
	}
}

func TestGatewayCoverRestore(t *testing.T) {
	g, be, _ := newGatewayCoverGateway(t)
	spec := allowSpec("sb", ipA, "pypi.org")
	if err := g.Attach(spec); err != nil {
		t.Fatal(err)
	}
	if err := g.SetBlocked("sb", BlockQuota, true); err != nil {
		t.Fatal(err)
	}
	// A restarted gateway learns from the kernel which sources are already
	// blocked, so its first write deletes rather than re-adds.
	g2 := New(Options{Backend: be})
	if err := g2.Restore([]Spec{spec}); err != nil {
		t.Fatal(err)
	}
	g2.mu.RLock()
	in := g2.byID["sb"].inBlockedSrc
	g2.mu.RUnlock()
	if !in || !g2.IsBlocked("sb") {
		t.Fatal("restored entry must know its source is in blocked_src")
	}
	if err := g2.Restore([]Spec{{IP: ipA}}); err == nil {
		t.Fatal("Restore accepted a spec without an id")
	}
}

// A learned flush whose delete fails and whose listing fails too stays
// pending in full, and RetryDirty finishes it.
func TestGatewayCoverLearnedFlushListFails(t *testing.T) {
	g, be, _ := newGatewayCoverGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "github.com:22")); err != nil {
		t.Fatal(err)
	}
	learned := Elem{Src: ipA, Dst: netip.MustParseAddr("140.82.112.3"), Port: 22}
	if err := g.AddLearned("sb", learned.Dst, learned.Port, time.Hour); err != nil {
		t.Fatal(err)
	}
	be.failApply = gatewayCoverLearnedDelete
	be.failList = func(set string) bool { return set == SetAllowLearned }
	if err := g.Detach("sb", ipA); err != nil {
		t.Fatal(err)
	}
	if !g.cleanupPending(ipA) || !be.Has(SetAllowLearned, learned) {
		t.Fatal("a failed learned flush must stay pending")
	}
	be.failApply, be.failList = nil, nil
	if err := g.RetryDirty(); err != nil {
		t.Fatal(err)
	}
	if g.cleanupPending(ipA) || be.Has(SetAllowLearned, learned) {
		t.Fatal("RetryDirty must finish the learned flush")
	}
}

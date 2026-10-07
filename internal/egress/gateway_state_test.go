package egress

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// hookBackend wraps a MemBackend so a test can fail or stall chosen writes.
type hookBackend struct {
	*MemBackend
	mu        sync.Mutex
	onApply   func(ops []Op) error
	replaces  atomic.Int32
	onReplace func()
}

func (h *hookBackend) Apply(ops []Op) error {
	h.mu.Lock()
	hook := h.onApply
	h.mu.Unlock()
	if hook != nil {
		if err := hook(ops); err != nil {
			return err
		}
	}
	return h.MemBackend.Apply(ops)
}

func (h *hookBackend) Replace(contents map[string][]Elem) error {
	h.replaces.Add(1)
	if h.onReplace != nil {
		h.onReplace()
	}
	return h.MemBackend.Replace(contents)
}

func (h *hookBackend) setApply(f func(ops []Op) error) {
	h.mu.Lock()
	h.onApply = f
	h.mu.Unlock()
}

func newHookGateway(t *testing.T) (*Gateway, *hookBackend, *flushRecorder) {
	t.Helper()
	be := &hookBackend{MemBackend: NewMemBackend()}
	ct := &flushRecorder{}
	g := New(Options{Backend: be, Conntrack: ct, Layout: LayoutConfig{DNSPort: 53054, ProxyPort: 15080}})
	if err := g.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	return g, be, ct
}

func hasOp(ops []Op, set string, del bool) bool {
	return slices.ContainsFunc(ops, func(o Op) bool { return o.Set == set && o.Del == del })
}

// TestSyncCannotInterleaveAttach (review finding 1): a Sync arriving while an
// Attach is between its kernel write and its map update waits for it, so
// the gateway's memory and the kernel always agree on who is attached. Before
// the fix the Sync could replace the sets under the Attach, which then
// published an entry with no kernel rules and reported success.
func TestSyncCannotInterleaveAttach(t *testing.T) {
	g, be, _ := newHookGateway(t)
	inApply, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	be.setApply(func(ops []Op) error {
		if hasOp(ops, SetFQDNSrc, false) {
			once.Do(func() { close(inApply) })
			<-release
		}
		return nil
	})
	attached := make(chan error, 1)
	go func() { attached <- g.Attach(allowSpec("sb", ipA, "pypi.org")) }()
	<-inApply
	synced := make(chan error, 1)
	go func() { synced <- g.Sync(nil) }()
	time.Sleep(50 * time.Millisecond)
	if be.replaces.Load() != 0 {
		t.Fatal("Sync replaced the sets while an Attach was mid-transition")
	}
	close(release)
	if err := <-attached; err != nil {
		t.Fatal(err)
	}
	if err := <-synced; err != nil {
		t.Fatal(err)
	}
	_, inMemory := g.Source(ipA)
	if inKernel := be.Has(SetFQDNSrc, Elem{Src: ipA}); inMemory != inKernel {
		t.Fatalf("memory (%v) and kernel (%v) disagree on the source", inMemory, inKernel)
	}
}

// TestBlockedRetryReachesKernel (review finding 4): a failed @blocked_src
// write is not recorded as applied. The in-memory block denies at once and
// the open connections close anyway; an identical retry, or RetryDirty,
// writes the kernel.
func TestBlockedRetryReachesKernel(t *testing.T) {
	g, be, ct := newHookGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	defer c2.Close()
	tc := g.Track("sb", "pypi.org", 443, c1)
	defer tc.Close()
	fail := errors.New("nft busy")
	be.setApply(func(ops []Op) error {
		if hasOp(ops, SetBlockedSrc, false) {
			return fail
		}
		return nil
	})
	flushes := ct.count()
	if err := g.SetBlocked("sb", BlockQuota, true); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if !g.IsBlocked("sb") || be.Has(SetBlockedSrc, Elem{Src: ipA}) {
		t.Fatal("the block must deny in memory while the kernel write is pending")
	}
	if _, err := c2.Write([]byte("x")); err == nil {
		t.Fatal("open connections must close even when the kernel write fails")
	}
	if ct.count() == flushes {
		t.Fatal("conntrack must be flushed even when the kernel write fails")
	}
	be.setApply(nil)
	if err := g.SetBlocked("sb", BlockQuota, true); err != nil {
		t.Fatal(err)
	}
	if !be.Has(SetBlockedSrc, Elem{Src: ipA}) {
		t.Fatal("an identical retry must reach the kernel")
	}

	// The same through the heartbeat's RetryDirty, for an unblock.
	be.setApply(func(ops []Op) error {
		if hasOp(ops, SetBlockedSrc, true) {
			return fail
		}
		return nil
	})
	if err := g.SetBlocked("sb", BlockQuota, false); err == nil {
		t.Fatal("the failed unblock must be reported")
	}
	if err := g.RetryDirty(); err == nil {
		t.Fatal("RetryDirty must report a write that still fails")
	}
	be.setApply(nil)
	if err := g.RetryDirty(); err != nil {
		t.Fatal(err)
	}
	if be.Has(SetBlockedSrc, Elem{Src: ipA}) || g.IsBlocked("sb") {
		t.Fatal("RetryDirty must finish the unblock")
	}
}

// TestNarrowingWaitsForStaleLearned (review finding 5): a narrowing whose
// learned-element delete fails is not acknowledged. The elements stay
// pending, the next Attach (or RetryDirty) deletes them, and only then does
// an Attach succeed.
func TestNarrowingWaitsForStaleLearned(t *testing.T) {
	g, be, ct := newHookGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "github.com:22")); err != nil {
		t.Fatal(err)
	}
	learned := Elem{Src: ipA, Dst: netip.MustParseAddr("140.82.112.3"), Port: 22}
	if err := g.AddLearned("sb", learned.Dst, 22, time.Hour); err != nil {
		t.Fatal(err)
	}
	be.setApply(func(ops []Op) error {
		if hasOp(ops, SetAllowLearned, true) {
			return errors.New("nft busy")
		}
		return nil
	})
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a narrowing that leaves a learned element must fail, got %v", err)
	}
	if !be.Has(SetAllowLearned, learned) {
		t.Fatal("test setup: the delete should have failed")
	}
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err == nil {
		t.Fatal("a retry must not succeed while the stale element is still there")
	}
	be.setApply(nil)
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	if be.Has(SetAllowLearned, learned) {
		t.Fatal("the retry must delete the stale element")
	}

	// A failed conntrack flush on a narrowing is held the same way.
	ct.mu.Lock()
	ct.err = errors.New("netlink busy")
	ct.mu.Unlock()
	if err := g.Attach(allowSpec("sb", ipA, "files.pythonhosted.org")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a narrowing whose conntrack flush fails must fail, got %v", err)
	}
	ct.mu.Lock()
	ct.err = nil
	ct.mu.Unlock()
	if err := g.RetryDirty(); err != nil {
		t.Fatal(err)
	}
	if err := g.Attach(allowSpec("sb", ipA, "files.pythonhosted.org")); err != nil {
		t.Fatal(err)
	}
}

// TestPendingCleanupBlocksTheNextOwner: a detach whose learned delete fails
// leaves the elements pending against the source IP, and a new sandbox on
// the recycled IP isn't attached until they are gone, so it can't inherit
// the old owner's destinations.
func TestPendingCleanupBlocksTheNextOwner(t *testing.T) {
	g, be, _ := newHookGateway(t)
	if err := g.Attach(allowSpec("old", ipA, "github.com:22")); err != nil {
		t.Fatal(err)
	}
	learned := Elem{Src: ipA, Dst: netip.MustParseAddr("140.82.112.3"), Port: 22}
	if err := g.AddLearned("old", learned.Dst, 22, time.Hour); err != nil {
		t.Fatal(err)
	}
	be.setApply(func(ops []Op) error {
		if hasOp(ops, SetAllowLearned, true) {
			return errors.New("nft busy")
		}
		return nil
	})
	if err := g.Detach("old", ipA); err != nil {
		t.Fatalf("detach itself succeeds: %v", err)
	}
	if err := g.Attach(allowSpec("new", ipA, "pypi.org")); err == nil {
		t.Fatal("the next owner must not attach over the old owner's learned element")
	}
	be.setApply(nil)
	if err := g.Attach(allowSpec("new", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	if be.Has(SetAllowLearned, learned) {
		t.Fatal("the old owner's element must be gone")
	}
}

// TestLearnedFlushToleratesExpiredElements: an element that expired on its
// own is gone from the kernel, and deleting it would fail the whole batch;
// the flush narrows to what is still there instead of staying pending.
func TestLearnedFlushToleratesExpiredElements(t *testing.T) {
	g, be, _ := newHookGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "github.com:22")); err != nil {
		t.Fatal(err)
	}
	gone := Elem{Src: ipA, Dst: netip.MustParseAddr("140.82.112.3"), Port: 22}
	kept := Elem{Src: ipA, Dst: netip.MustParseAddr("140.82.112.4"), Port: 22}
	for _, e := range []Elem{gone, kept} {
		if err := g.AddLearned("sb", e.Dst, 22, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if err := be.MemBackend.Apply([]Op{{Set: SetAllowLearned, Del: true, Elems: []Elem{gone}}}); err != nil {
		t.Fatal(err)
	}
	// The kernel refuses a delete that names a missing element, like nft.
	be.setApply(func(ops []Op) error {
		for _, o := range ops {
			if o.Set == SetAllowLearned && o.Del && slices.Contains(o.Elems, gone) {
				return errors.New("ENOENT")
			}
		}
		return nil
	})
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	if be.Has(SetAllowLearned, kept) {
		t.Fatal("the element still there must be deleted")
	}
}

// TestSandboxLocksAreReleased (review finding 15): per-sandbox locks go away
// with their last holder, so churn doesn't grow the map.
func TestSandboxLocksAreReleased(t *testing.T) {
	g, _, _ := newHookGateway(t)
	for i := 0; i < 1000; i++ {
		id := "sb-" + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i/676))
		if err := g.Attach(allowSpec(id, ipA, "pypi.org")); err != nil {
			t.Fatal(err)
		}
		if err := g.Detach(id, ipA); err != nil {
			t.Fatal(err)
		}
	}
	if n := g.lockCount(); n != 0 {
		t.Fatalf("%d sandbox locks left after churn", n)
	}
	// Held and waited-on locks stay while in use.
	unlock := g.lockSandbox("busy")
	done := make(chan struct{})
	go func() { u := g.lockSandbox("busy"); u(); close(done) }()
	time.Sleep(20 * time.Millisecond)
	if g.lockCount() != 1 {
		t.Fatal("a lock with a waiter must stay")
	}
	unlock()
	<-done
	if g.lockCount() != 0 {
		t.Fatal("the lock must go with its last holder")
	}
}

// TestRevalidateConns: a tightened guard closes the streams it now refuses;
// a connection with no recorded address (not dialed directly) is left to
// its next request's dial.
func TestRevalidateConns(t *testing.T) {
	g, _, _ := newHookGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	defer c2.Close()
	d1, d2 := net.Pipe()
	defer d2.Close()
	denied := g.Track("sb", "pypi.org", 443, c1)
	denied.SetDst(netip.MustParseAddrPort("10.50.0.7:443"))
	kept := g.Track("sb", "pypi.org", 80, d1)
	defer kept.Close()
	n := g.RevalidateConns(func(_ *egresspolicy.Policy, host string, dst netip.AddrPort) bool {
		return dst.IsValid() && netip.MustParsePrefix("10.50.0.0/16").Contains(dst.Addr())
	})
	if n != 1 {
		t.Fatalf("closed %d connections, want 1", n)
	}
	if _, err := c2.Write([]byte("x")); err == nil {
		t.Fatal("the refused stream must be closed")
	}
	go func() { _, _ = d1.Write([]byte("y")) }()
	buf := make([]byte, 1)
	if _, err := d2.Read(buf); err != nil {
		t.Fatal("a connection without a dialed address stays open")
	}
}

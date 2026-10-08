package egress

// Regression tests from the second review of PR #622: each reproduces a
// finding against the reviewed head and passes with its fix.

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

type learnedDeleteFail struct{ *MemBackend }

func (b *learnedDeleteFail) Apply(ops []Op) error {
	for _, op := range ops {
		if op.Set == SetAllowLearned && op.Del {
			return errors.New("delete temporarily rejected")
		}
	}
	return b.MemBackend.Apply(ops)
}
func TestSyncShutsASandboxWhoseRevocationFailed(t *testing.T) {
	b := &learnedDeleteFail{NewMemBackend()}
	g := New(Options{Backend: b})
	if err := g.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := g.Attach(allowSpec("sb", ipA, "github.com:22")); err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParseAddr("140.82.112.3")
	if err := g.AddLearned("sb", dst, 22, time.Hour); err != nil {
		t.Fatal(err)
	}
	err := g.Sync([]Spec{allowSpec("sb", ipA, "pypi.org")})
	if err == nil && b.Has(SetAllowLearned, Elem{Src: ipA, Dst: dst, Port: 22}) && !b.Has(SetBlockedSrc, Elem{Src: ipA}) {
		t.Fatal("Sync acknowledged a narrowed policy while its revoked destination remains allowed and unblocked")
	}
}

func TestDelayedDNSAnswerCannotReopenARevokedHost(t *testing.T) {
	g, b, _ := newTestGateway(t)
	if err := g.Attach(allowSpec("sb", ipA, "github.com:22")); err != nil {
		t.Fatal(err)
	}
	// DNS was admitted under this policy and its upstream response is delayed.
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParseAddr("140.82.112.3")
	// The answer reaches the learner after the successful policy update.
	err := g.LearnFor("sb", "github.com", dst, 22, time.Hour)
	if err == nil && b.Has(SetAllowLearned, Elem{Src: ipA, Dst: dst, Port: 22}) {
		t.Fatal("delayed DNS answer reinstalled a revoked host:port under the new policy")
	}
}

// TestCleanupBlockLiftsWhenCleanupSucceeds: the gateway's own cleanup block
// set by a Sync goes once RetryDirty deletes what the kernel kept, and a
// sweep that couldn't list the learned sets is redone the same way.
func TestCleanupBlockLiftsWhenCleanupSucceeds(t *testing.T) {
	b := &learnedDeleteFail{NewMemBackend()}
	g := New(Options{Backend: b})
	if err := g.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := g.Attach(allowSpec("sb", ipA, "github.com:22")); err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParseAddr("140.82.112.3")
	if err := g.AddLearned("sb", dst, 22, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := g.Sync([]Spec{allowSpec("sb", ipA, "pypi.org")}); err != nil {
		t.Fatal(err)
	}
	if !b.Has(SetBlockedSrc, Elem{Src: ipA}) || !g.IsBlocked("sb") {
		t.Fatal("setup: the failed revocation must shut the sandbox")
	}
	if err := g.RetryDirty(); err == nil {
		t.Fatal("a delete that still fails must be reported")
	}
	// The kernel deletes again: the element goes, then the block.
	g.be = b.MemBackend
	if err := g.RetryDirty(); err != nil {
		t.Fatal(err)
	}
	if b.Has(SetAllowLearned, Elem{Src: ipA, Dst: dst, Port: 22}) || b.Has(SetBlockedSrc, Elem{Src: ipA}) || g.IsBlocked("sb") {
		t.Fatal("RetryDirty must delete the element and lift the cleanup block")
	}

	// A sweep that couldn't list is redone: mark the source as unlisted.
	if err := b.MemBackend.Apply([]Op{{Set: SetAllowLearned, Elems: []Elem{{Src: ipA, Dst: dst, Port: 22}}}}); err != nil {
		t.Fatal(err)
	}
	g.learnedMu.Lock()
	g.sweepPending[ipA] = true
	g.learnedMu.Unlock()
	if err := g.RetryDirty(); err != nil {
		t.Fatal(err)
	}
	if b.Has(SetAllowLearned, Elem{Src: ipA, Dst: dst, Port: 22}) {
		t.Fatal("the redone sweep must delete an element the shadow doesn't know")
	}
}

// TestSyncSinceKeepsNewerBlockWrites (review 3 finding 1): a full Sync
// built from a snapshot taken before a block write never undoes it; a write
// the snapshot covers is replaced by the spec, a release included.
func TestSyncSinceKeepsNewerBlockWrites(t *testing.T) {
	g := New(Options{Backend: NewMemBackend()})
	if err := g.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	a, b := allowSpec("a", ipA, "pypi.org"), allowSpec("b", ipB, "pypi.org")
	for _, s := range []Spec{a, b} {
		if err := g.Attach(s); err != nil {
			t.Fatal(err)
		}
	}
	// b is held before the snapshot and released in it.
	if err := g.SetBlocked("b", BlockHold, true); err != nil {
		t.Fatal(err)
	}
	since := g.BlockGen()
	// a is held after the snapshot was read: the stale spec says unheld.
	if err := g.SetBlocked("a", BlockHold, true); err != nil {
		t.Fatal(err)
	}
	if err := g.SyncSince(since, []Spec{a, b}); err != nil {
		t.Fatal(err)
	}
	if !g.IsBlocked("a") {
		t.Fatal("a stale snapshot lifted a hold written after it")
	}
	if g.IsBlocked("b") {
		t.Fatal("a hold the snapshot covers is replaced by the spec")
	}
	// A release written after the snapshot wins over a stale held spec.
	since = g.BlockGen()
	if err := g.SetBlocked("a", BlockHold, false); err != nil {
		t.Fatal(err)
	}
	held := a
	held.Blocked = BlockHold
	if err := g.SyncSince(since, []Spec{held, b}); err != nil {
		t.Fatal(err)
	}
	if g.IsBlocked("a") {
		t.Fatal("a release written after the snapshot must win over its stale hold")
	}
	// A plain Sync is current: it covers every write and drops the records.
	if err := g.Sync([]Spec{a, b}); err != nil {
		t.Fatal(err)
	}
	g.mu.RLock()
	n := len(g.writes)
	g.mu.RUnlock()
	if n != 0 {
		t.Fatalf("writes a Sync covers must be dropped, %d left", n)
	}
}

// TestAttachTakesABlockWrittenBeforeIt: a hold set while the sandbox wasn't
// attached (racing its attach) applies when it attaches; a release doesn't
// lift a spec's hold that way. RetainBlocks drops records of sandboxes the
// node no longer holds.
func TestAttachTakesABlockWrittenBeforeIt(t *testing.T) {
	g := New(Options{Backend: NewMemBackend()})
	if err := g.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := g.SetBlocked("sb", BlockHold, true); !errors.Is(err, ErrNotAttached) {
		t.Fatalf("SetBlocked before attach = %v", err)
	}
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	if !g.IsBlocked("sb") {
		t.Fatal("a hold written before the attach must apply")
	}
	if err := g.SetBlocked("other", BlockHold, false); !errors.Is(err, ErrNotAttached) {
		t.Fatal(err)
	}
	held := allowSpec("other", ipB, "pypi.org")
	held.Blocked = BlockHold
	if err := g.Attach(held); err != nil {
		t.Fatal(err)
	}
	if !g.IsBlocked("other") {
		t.Fatal("a release written before the attach must not lift the spec's hold")
	}
	g.RetainBlocks([]string{"sb"})
	g.mu.RLock()
	_, kept := g.writes["sb"]
	_, dropped := g.writes["other"]
	g.mu.RUnlock()
	if !kept || dropped {
		t.Fatalf("RetainBlocks kept=%v dropped=%v", kept, dropped)
	}
}

// TestAttachKeepsTheCleanupBlockUntilClean (review 3 finding 5): a source
// with cleanup pending is attached shut, and the block lifts once the
// cleanup, a redone sweep included, has finished.
func TestAttachKeepsTheCleanupBlockUntilClean(t *testing.T) {
	be := NewMemBackend()
	g := New(Options{Backend: be})
	if err := g.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	g.learnedMu.Lock()
	g.sweepPending[ipA] = true
	g.learnedMu.Unlock()
	stale := Elem{Src: ipA, Dst: netip.MustParseAddr("140.82.112.3"), Port: 22}
	if err := be.Apply([]Op{{Set: SetAllowLearned, Elems: []Elem{stale}}}); err != nil {
		t.Fatal(err)
	}
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	if be.Has(SetAllowLearned, stale) || g.IsBlocked("sb") || be.Has(SetBlockedSrc, Elem{Src: ipA}) {
		t.Fatal("a successful cleanup must delete the stale element and lift the block")
	}
}

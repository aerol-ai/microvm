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

package egress

// Regression tests from the third review of PR #622: each reproduces a
// finding against the reviewed head (7935cfe6) and passes with its fix.

import (
	"errors"
	"net/netip"
	"testing"
)

type learnedListFailure struct {
	*MemBackend
	fail bool
}

func (b *learnedListFailure) List(set string) ([]Elem, error) {
	if b.fail && (set == SetAllowLearned || set == SetBinLearned) {
		return nil, errors.New("temporary learned set read failure")
	}
	return b.MemBackend.List(set)
}
func TestAttachKeepsAPendingSweepShut(t *testing.T) {
	b := &learnedListFailure{MemBackend: NewMemBackend()}
	g := New(Options{Backend: b})
	if err := g.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := g.Attach(allowSpec("sb", ipA, "github.com:22")); err != nil {
		t.Fatal(err)
	}
	// Surviving kernel tuple not in the process shadow, as after restart.
	old := Elem{Src: ipA, Dst: netip.MustParseAddr("140.82.112.3"), Port: 22}
	if err := b.Apply([]Op{{Set: SetAllowLearned, Elems: []Elem{old}}}); err != nil {
		t.Fatal(err)
	}
	b.fail = true
	next := allowSpec("sb", ipA, "pypi.org")
	if err := g.Sync([]Spec{next}); err != nil {
		t.Fatal(err)
	}
	if !g.IsBlocked("sb") {
		t.Fatal("setup: failed sweep did not block source")
	}
	err := g.Attach(next)
	if err == nil && !g.IsBlocked("sb") && b.Has(SetAllowLearned, old) {
		t.Fatal("Attach acknowledged and removed cleanup block with unknown revoked tuple still in kernel")
	}
}

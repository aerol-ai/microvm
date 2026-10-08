package egress

// Regression tests from the fifth review of PR #622: each reproduces a
// finding against the reviewed head (a9b64e06) and passes with its fix.

import (
	"errors"
	"testing"
)

func TestOlderSyncAfterNewerSyncKeepsHold(t *testing.T) {
	g, _, _ := newTestGateway(t)
	spec := allowSpec("sb", ipA, "pypi.org")
	if err := g.Attach(spec); err != nil {
		t.Fatal(err)
	}
	oldToken := g.SyncToken()
	oldSnapshot := g.Specs()
	if err := g.SetBlocked("sb", BlockHold, true); err != nil {
		t.Fatal(err)
	}
	// A gateway self-resync can finish while sandboxd's earlier full Sync
	// is still assembling its database snapshot / waiting to send it.
	newToken := g.SyncToken()
	if err := g.SyncFrom(newToken, g.Specs()); err != nil {
		t.Fatal(err)
	}
	if !g.IsBlocked("sb") {
		t.Fatal("setup: newer snapshot lost hold")
	}
	if err := g.SyncFrom(oldToken, oldSnapshot); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an older token after a newer Sync must be refused, got %v", err)
	}
	if !g.IsBlocked("sb") {
		t.Fatal("the refused Sync must leave the hold in place")
	}
}

func TestStaleSnapshotDoesNotRemoveANewerAttach(t *testing.T) {
	g, be, _ := newTestGateway(t)
	a := allowSpec("a", ipA, "pypi.org")
	b := allowSpec("b", ipB, "github.com")
	if err := g.Attach(a); err != nil {
		t.Fatal(err)
	}
	// The three operations resyncSelf performs are not one transaction.
	tok := g.SyncToken()
	snapshot := g.Specs()
	if err := g.Attach(b); err != nil {
		t.Fatal(err)
	}
	if err := g.SyncFrom(tok, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.Source(ipB); !ok || !be.Has(SetFQDNSrc, Elem{Src: ipB}) {
		t.Fatal("table-loss self-resync removed a sandbox whose Attach had already succeeded")
	}
}

// TestSyncKeepsAttachesAndDetachesNewerThanItsSnapshot (review 5 finding
// 2, for any caller): a snapshot taken before an attach keeps the attach
// (and the newer entry wins its source over a stale owner in the specs);
// one taken before a detach doesn't bring the sandbox back.
func TestSyncKeepsAttachesAndDetachesNewerThanItsSnapshot(t *testing.T) {
	g, be, _ := newTestGateway(t)
	a := allowSpec("a", ipA, "pypi.org")
	gone := allowSpec("gone", ipB, "pypi.org")
	for _, s := range []Spec{a, gone} {
		if err := g.Attach(s); err != nil {
			t.Fatal(err)
		}
	}
	tok := g.SyncToken()
	snapshot := g.Specs()
	// After the snapshot: "gone" leaves, and "new" takes over a's source.
	if err := g.Detach("gone", ipB); err != nil {
		t.Fatal(err)
	}
	if err := g.Attach(allowSpec("new", ipA, "github.com")); err != nil {
		t.Fatal(err)
	}
	if err := g.SyncFrom(tok, snapshot); err != nil {
		t.Fatal(err)
	}
	if src, ok := g.Source(ipA); !ok || src.Spec.ID != "new" {
		t.Fatalf("the newer attach must keep its source: %+v %v", src.Spec, ok)
	}
	if _, ok := g.Source(ipB); ok || be.Has(SetFQDNSrc, Elem{Src: ipB}) {
		t.Fatal("a sandbox detached after the snapshot must stay detached")
	}
	// A current snapshot still replaces everything.
	if err := g.Sync([]Spec{a}); err != nil {
		t.Fatal(err)
	}
	if src, ok := g.Source(ipA); !ok || src.Spec.ID != "a" {
		t.Fatalf("a current Sync is authoritative: %+v %v", src.Spec, ok)
	}
}

// TestSyncFenceRefusesAnOlderToken (review 5 finding 1): once a Sync has
// applied, an older token is refused (the evidence it needs is pruned); an
// equal one is accepted.
func TestSyncFenceRefusesAnOlderToken(t *testing.T) {
	g, _, _ := newTestGateway(t)
	spec := allowSpec("sb", ipA, "pypi.org")
	if err := g.Attach(spec); err != nil {
		t.Fatal(err)
	}
	old := g.SyncToken()
	if err := g.SetBlocked("sb", BlockQuota, true); err != nil {
		t.Fatal(err)
	}
	cur := g.SyncToken()
	held := spec
	held.Blocked = BlockQuota
	if err := g.SyncFrom(cur, []Spec{held}); err != nil {
		t.Fatal(err)
	}
	if err := g.SyncFrom(old, []Spec{spec}); !errors.Is(err, ErrUnavailable) || !g.IsBlocked("sb") {
		t.Fatalf("an older token: %v blocked=%v", err, g.IsBlocked("sb"))
	}
	if err := g.SyncFrom(cur, []Spec{held}); err != nil {
		t.Fatalf("an equal token: %v", err)
	}
}

// TestReapplyRestoresTheSetsFromLiveState: after a table loss, Reapply
// writes every attached sandbox back, including one attached a moment
// before, with its block state.
func TestReapplyRestoresTheSetsFromLiveState(t *testing.T) {
	g, be, _ := newTestGateway(t)
	if err := g.Attach(allowSpec("a", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	if err := g.Attach(allowSpec("b", ipB, "github.com")); err != nil {
		t.Fatal(err)
	}
	if err := g.SetBlocked("b", BlockHold, true); err != nil {
		t.Fatal(err)
	}
	if err := be.Replace(map[string][]Elem{SetFQDNSrc: nil, SetBlockedSrc: nil}); err != nil {
		t.Fatal(err)
	}
	if err := g.Reapply(); err != nil {
		t.Fatal(err)
	}
	if !be.Has(SetFQDNSrc, Elem{Src: ipA}) || !be.Has(SetFQDNSrc, Elem{Src: ipB}) || !be.Has(SetBlockedSrc, Elem{Src: ipB}) {
		t.Fatal("Reapply must restore every attached source and its block")
	}
}

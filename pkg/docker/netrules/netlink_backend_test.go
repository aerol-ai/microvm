//go:build linux

package netrules

import (
	"errors"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type fakeNFT struct {
	rules    []*nftables.Rule
	getErr   error
	flushErr error
	delErr   error
	inserted []*nftables.Rule
	deleted  []*nftables.Rule
}

func (f *fakeNFT) GetRules(*nftables.Table, *nftables.Chain) ([]*nftables.Rule, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	out := make([]*nftables.Rule, len(f.rules))
	copy(out, f.rules)
	return out, nil
}

func (f *fakeNFT) InsertRule(r *nftables.Rule) *nftables.Rule {
	f.inserted = append(f.inserted, r)
	// Mirror into rules so a subsequent Exists sees it.
	cp := *r
	cp.Handle = uint64(len(f.rules) + 1)
	f.rules = append([]*nftables.Rule{&cp}, f.rules...)
	return &cp
}

func (f *fakeNFT) DelRule(r *nftables.Rule) error {
	if f.delErr != nil {
		return f.delErr
	}
	f.deleted = append(f.deleted, r)
	kept := f.rules[:0]
	for _, existing := range f.rules {
		if existing.Handle != r.Handle {
			kept = append(kept, existing)
		}
	}
	f.rules = kept
	return nil
}

func (f *fakeNFT) Flush() error { return f.flushErr }

// testNetlinkBackend wires a backend whose per-op connection factory always
// hands back the same fake, so tests can assert on its recorded calls.
func testNetlinkBackend(fake *fakeNFT) *netlinkBackend {
	return &netlinkBackend{newConn: func() (nftAPI, error) { return fake, nil }}
}

func TestNetlinkBackendExistsInsertDelete(t *testing.T) {
	spec := []string{"-s", "10.0.0.2", "-j", "DROP"}
	want, err := exprsFromRulespec(spec...)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeNFT{}
	b := testNetlinkBackend(fake)

	ok, err := b.Exists("filter", "DOCKER-USER", spec...)
	if err != nil || ok {
		t.Fatalf("Exists empty = %v, %v; want false,nil", ok, err)
	}

	if err := b.Insert("filter", "DOCKER-USER", 1, spec...); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if len(fake.inserted) != 1 {
		t.Fatalf("inserted = %d, want 1", len(fake.inserted))
	}
	ok, err = b.Exists("filter", "DOCKER-USER", spec...)
	if err != nil || !ok {
		t.Fatalf("Exists after insert = %v, %v", ok, err)
	}

	// Non-matching rule in the chain must not confuse Exists.
	fake.rules = append(fake.rules, &nftables.Rule{
		Handle: 99,
		Exprs:  []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
	})
	ok, err = b.Exists("filter", "DOCKER-USER", spec...)
	if err != nil || !ok {
		t.Fatalf("Exists with distractor = %v, %v", ok, err)
	}

	if err := b.Delete("filter", "DOCKER-USER", spec...); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(fake.deleted) != 1 {
		t.Fatalf("deleted = %d, want 1", len(fake.deleted))
	}
	_ = want
}

func TestNetlinkBackendInsertAtPosition(t *testing.T) {
	spec := []string{"-d", "10.0.0.3", "-j", "DROP"}
	fake := &fakeNFT{rules: []*nftables.Rule{
		{Handle: 10, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}},
		{Handle: 20, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}},
	}}
	b := testNetlinkBackend(fake)
	if err := b.Insert("filter", "DOCKER-USER", 2, spec...); err != nil {
		t.Fatalf("Insert pos=2: %v", err)
	}
	// iptables -I chain 2 → insert before the current 2nd rule (0-based
	// index pos-1), so Position is rules[1].Handle.
	if len(fake.inserted) != 1 || fake.inserted[0].Position != 20 {
		t.Fatalf("Position = %v, want handle 20 (rules[pos-1])", fake.inserted[0].Position)
	}
}

func TestNetlinkBackendErrorPaths(t *testing.T) {
	b := testNetlinkBackend(&fakeNFT{})

	if _, err := b.Exists("nat", "DOCKER-USER", "-s", "10.0.0.1", "-j", "DROP"); err == nil {
		t.Fatal("want unsupported table error")
	}
	if _, err := b.Exists("filter", "DOCKER-USER", "-p", "tcp"); err == nil {
		t.Fatal("want rulespec parse error")
	}
	if err := b.Insert("filter", "DOCKER-USER", 1, "-p", "tcp"); err == nil {
		t.Fatal("want insert parse error")
	}
	if err := b.Delete("nat", "PREROUTING", "-s", "10.0.0.1", "-j", "DROP"); err == nil {
		t.Fatal("want delete lookup error")
	}

	b = testNetlinkBackend(&fakeNFT{getErr: errors.New("get failed")})
	if _, err := b.Exists("filter", "DOCKER-USER", "-s", "10.0.0.1", "-j", "DROP"); err == nil {
		t.Fatal("want get rules error")
	}
	if err := b.Insert("filter", "DOCKER-USER", 2, "-s", "10.0.0.1", "-j", "DROP"); err == nil {
		t.Fatal("want insert get-for-pos error")
	}
	if err := b.Delete("filter", "DOCKER-USER", "-s", "10.0.0.1", "-j", "DROP"); err == nil {
		t.Fatal("want delete get rules error")
	}

	b = testNetlinkBackend(&fakeNFT{flushErr: errors.New("flush boom")})
	if err := b.Insert("filter", "DOCKER-USER", 1, "-s", "10.0.0.1", "-j", "DROP"); err == nil {
		t.Fatal("want insert flush error")
	}

	want, _ := exprsFromRulespec("-s", "10.0.0.1", "-j", "DROP")
	b = testNetlinkBackend(&fakeNFT{
		rules:    []*nftables.Rule{{Handle: 1, Exprs: want}},
		delErr:   errors.New("del boom"),
		flushErr: nil,
	})
	if err := b.Delete("filter", "DOCKER-USER", "-s", "10.0.0.1", "-j", "DROP"); err == nil {
		t.Fatal("want del rule error")
	}

	b = testNetlinkBackend(&fakeNFT{
		rules:    []*nftables.Rule{{Handle: 1, Exprs: want}},
		flushErr: syscall.ENOENT,
	})
	if err := b.Delete("filter", "DOCKER-USER", "-s", "10.0.0.1", "-j", "DROP"); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("flush ENOENT = %v, want ENOENT passthrough", err)
	}

	b = testNetlinkBackend(&fakeNFT{
		rules:    []*nftables.Rule{{Handle: 1, Exprs: want}},
		flushErr: errors.New("flush other"),
	})
	if err := b.Delete("filter", "DOCKER-USER", "-s", "10.0.0.1", "-j", "DROP"); err == nil {
		t.Fatal("want wrapped flush del error")
	}

	b = testNetlinkBackend(&fakeNFT{rules: []*nftables.Rule{{Handle: 1, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}}}})
	if err := b.Delete("filter", "DOCKER-USER", "-s", "10.0.0.1", "-j", "DROP"); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("no match = %v, want ENOENT", err)
	}

	connErr := errors.New("factory boom")
	b = &netlinkBackend{newConn: func() (nftAPI, error) { return nil, connErr }}
	if _, err := b.Exists("filter", "DOCKER-USER", "-s", "10.0.0.1", "-j", "DROP"); !errors.Is(err, connErr) {
		t.Fatalf("Exists conn error = %v, want factory error", err)
	}
	if err := b.Insert("filter", "DOCKER-USER", 1, "-s", "10.0.0.1", "-j", "DROP"); !errors.Is(err, connErr) {
		t.Fatalf("Insert conn error = %v, want factory error", err)
	}
	if err := b.Delete("filter", "DOCKER-USER", "-s", "10.0.0.1", "-j", "DROP"); !errors.Is(err, connErr) {
		t.Fatalf("Delete conn error = %v, want factory error", err)
	}
}

func TestNetlinkBackendInsertPosBeyondLen(t *testing.T) {
	fake := &fakeNFT{rules: []*nftables.Rule{{Handle: 1}}}
	b := testNetlinkBackend(fake)
	if err := b.Insert("filter", "DOCKER-USER", 99, "-s", "10.0.0.1", "-j", "DROP"); err != nil {
		t.Fatal(err)
	}
	if fake.inserted[0].Position != 0 {
		t.Fatalf("Position = %d, want 0 when idx past end", fake.inserted[0].Position)
	}
}

// Rules created by the exec backend (iptables-nft CLI) carry a counter expr
// with live packet/byte totals. Exists and Delete must still match them, or
// an operator flipping SB_NETRULES_BACKEND strands the old backend's
// ACCEPT/DROP rules on recycled container IPs.
func TestNetlinkBackendMatchesExecCreatedRules(t *testing.T) {
	spec := []string{"-s", "10.0.0.7", "-j", "DROP"}
	ours, err := exprsFromRulespec(spec...)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the iptables-nft encoding: same match exprs, but the counter
	// has accumulated non-zero totals (ours is zero-valued).
	theirs := make([]expr.Any, 0, len(ours))
	for _, e := range ours {
		if _, ok := e.(*expr.Counter); ok {
			theirs = append(theirs, &expr.Counter{Packets: 42, Bytes: 4096})
			continue
		}
		theirs = append(theirs, e)
	}
	fake := &fakeNFT{rules: []*nftables.Rule{{Handle: 7, Exprs: theirs}}}
	b := testNetlinkBackend(fake)

	ok, err := b.Exists("filter", "DOCKER-USER", spec...)
	if err != nil || !ok {
		t.Fatalf("Exists(exec-created) = %v, %v; want true", ok, err)
	}
	if err := b.Delete("filter", "DOCKER-USER", spec...); err != nil {
		t.Fatalf("Delete(exec-created): %v", err)
	}
	if len(fake.deleted) != 1 || fake.deleted[0].Handle != 7 {
		t.Fatalf("deleted = %+v, want handle 7", fake.deleted)
	}

	// Rules written by a pre-counter netlink build (no counter expr at all)
	// must also stay matchable across an upgrade.
	legacy := stripCounters(ours)
	fake = &fakeNFT{rules: []*nftables.Rule{{Handle: 8, Exprs: legacy}}}
	b = testNetlinkBackend(fake)
	ok, err = b.Exists("filter", "DOCKER-USER", spec...)
	if err != nil || !ok {
		t.Fatalf("Exists(legacy netlink) = %v, %v; want true", ok, err)
	}
	if err := b.Delete("filter", "DOCKER-USER", spec...); err != nil {
		t.Fatalf("Delete(legacy netlink): %v", err)
	}
}

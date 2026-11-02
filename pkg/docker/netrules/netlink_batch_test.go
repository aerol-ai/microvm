//go:build linux

package netrules

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// chainNFT is a chain-aware nftAPI fake: rules live per chain, a Flush
// applies the queued batch all-or-nothing (as an nft transaction does), and
// every listing and commit is counted.
type chainNFT struct {
	mu      sync.Mutex
	chains  map[string][]*nftables.Rule
	next    uint64
	queued  []func() error
	gets    map[string]int
	flushes int
	// staleFlushes makes the next n Flushes fail with ENOENT, applying
	// nothing (a rule the batch named left the chain after the listing).
	staleFlushes int
	getErr       error
	flushErr     error
	delErr       error
}

func newChainNFT() *chainNFT {
	return &chainNFT{chains: map[string][]*nftables.Rule{}, gets: map[string]int{}}
}

func (f *chainNFT) add(chain string, spec ...string) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	exprs, err := exprsFromRulespec(spec...)
	if err != nil {
		panic(err)
	}
	f.next++
	tbl := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"}
	f.chains[chain] = append(f.chains[chain], &nftables.Rule{Table: tbl, Chain: &nftables.Chain{Name: chain, Table: tbl},
		Handle: f.next, Exprs: append(exprs, &expr.Counter{})})
	return f.next
}

func (f *chainNFT) count(chain string, spec ...string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	want, _ := exprsFromRulespec(spec...)
	n := 0
	for _, r := range f.chains[chain] {
		if exprsEqualIgnoringCounters(want, r.Exprs) {
			n++
		}
	}
	return n
}

func (f *chainNFT) indexOf(chain string, spec ...string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	want, _ := exprsFromRulespec(spec...)
	for i, r := range f.chains[chain] {
		if exprsEqualIgnoringCounters(want, r.Exprs) {
			return i
		}
	}
	return -1
}

func (f *chainNFT) GetRules(_ *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets[c.Name]++
	if f.getErr != nil {
		return nil, f.getErr
	}
	return slices.Clone(f.chains[c.Name]), nil
}

func (f *chainNFT) InsertRule(r *nftables.Rule) *nftables.Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queued = append(f.queued, func() error {
		rules := f.chains[r.Chain.Name]
		at := 0
		if r.Position != 0 {
			at = slices.IndexFunc(rules, func(x *nftables.Rule) bool { return x.Handle == r.Position })
			if at < 0 {
				return syscall.ENOENT
			}
		}
		f.next++
		cp := *r
		cp.Handle = f.next
		f.chains[r.Chain.Name] = slices.Insert(rules, at, &cp)
		return nil
	})
	return r
}

func (f *chainNFT) AddRule(r *nftables.Rule) *nftables.Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queued = append(f.queued, func() error {
		f.next++
		cp := *r
		cp.Handle = f.next
		f.chains[r.Chain.Name] = append(f.chains[r.Chain.Name], &cp)
		return nil
	})
	return r
}

func (f *chainNFT) DelRule(r *nftables.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delErr != nil {
		return f.delErr
	}
	f.queued = append(f.queued, func() error {
		rules := f.chains[r.Chain.Name]
		i := slices.IndexFunc(rules, func(x *nftables.Rule) bool { return x.Handle == r.Handle })
		if i < 0 {
			return syscall.ENOENT
		}
		f.chains[r.Chain.Name] = slices.Delete(rules, i, i+1)
		return nil
	})
	return nil
}

func (f *chainNFT) Flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushes++
	q := f.queued
	f.queued = nil
	if f.flushErr != nil {
		return f.flushErr
	}
	if f.staleFlushes > 0 {
		f.staleFlushes--
		return fmt.Errorf("conn.Receive: %w", syscall.ENOENT)
	}
	// All or nothing: apply to a copy, keep it only if every op landed.
	saved := map[string][]*nftables.Rule{}
	for k, v := range f.chains {
		saved[k] = slices.Clone(v)
	}
	next := f.next
	for _, op := range q {
		if err := op(); err != nil {
			f.chains, f.next = saved, next
			return fmt.Errorf("conn.Receive: %w", err)
		}
	}
	return nil
}

func (f *chainNFT) ListChains() ([]*nftables.Chain, error)     { return nil, nil }
func (f *chainNFT) AddChain(c *nftables.Chain) *nftables.Chain { return c }
func (f *chainNFT) FlushChain(*nftables.Chain)                 {}

func netlinkChainBackend(f *chainNFT) *netlinkBackend {
	return &netlinkBackend{newConn: func() (nftAPI, error) { return f, nil }}
}

func dropSpec(ip string) []string { return []string{"-s", ip, "-j", "DROP"} }

// TestNetlinkDeleteAllOneListingOneCommit: the clear of a block-all lists
// each chain once and commits once, removes duplicates (the sweep the
// per-rule path loops for), and leaves every other rule alone.
func TestNetlinkDeleteAllOneListingOneCommit(t *testing.T) {
	f := newChainNFT()
	f.add(ChainAerolvmUser, dropSpec("10.0.0.9")...)
	f.add(ChainAerolvmUser, dropSpec("10.0.0.2")...)
	f.add(ChainAerolvmUser, dropSpec("10.0.0.2")...) // a duplicate a past race left
	f.add(ChainAerolvmInput, inputBlockSpec("10.0.0.2")...)
	f.add(ChainAerolvmInput, inputBlockSpec("10.0.0.9")...)
	f.add(ChainAerolvmInput, inputPolicyDropSpec("10.0.0.2")...) // the allowlist's, not the block's
	b := netlinkChainBackend(f)
	err := b.DeleteAll(
		RuleRef{Table: "filter", Chain: ChainAerolvmUser, Spec: dropSpec("10.0.0.2")},
		RuleRef{Table: "filter", Chain: ChainAerolvmInput, Spec: inputBlockSpec("10.0.0.2")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if f.gets[ChainAerolvmUser] != 1 || f.gets[ChainAerolvmInput] != 1 || f.flushes != 1 {
		t.Fatalf("listings %v, commits %d; want one listing per chain and one commit", f.gets, f.flushes)
	}
	for _, tc := range []struct {
		chain string
		spec  []string
		want  int
	}{
		{ChainAerolvmUser, dropSpec("10.0.0.2"), 0},
		{ChainAerolvmUser, dropSpec("10.0.0.9"), 1},
		{ChainAerolvmInput, inputBlockSpec("10.0.0.2"), 0},
		{ChainAerolvmInput, inputBlockSpec("10.0.0.9"), 1},
		{ChainAerolvmInput, inputPolicyDropSpec("10.0.0.2"), 1},
	} {
		if got := f.count(tc.chain, tc.spec...); got != tc.want {
			t.Errorf("%s %v: %d left, want %d", tc.chain, tc.spec, got, tc.want)
		}
	}
	// Nothing left to delete: listings only, no empty commit.
	if err := b.DeleteAll(RuleRef{Table: "filter", Chain: ChainAerolvmUser, Spec: dropSpec("10.0.0.2")}); err != nil {
		t.Fatal(err)
	}
	if f.flushes != 1 {
		t.Fatalf("a delete with nothing to remove committed (%d commits)", f.flushes)
	}
}

// TestNetlinkDeleteAllRetriesStaleBatch: a commit that hit a rule gone
// since the listing applied nothing (all or nothing), and the batch is
// redone from a fresh listing; three in a row are an error.
func TestNetlinkDeleteAllRetriesStaleBatch(t *testing.T) {
	f := newChainNFT()
	f.add(ChainAerolvmUser, dropSpec("10.0.0.2")...)
	f.staleFlushes = 1
	b := netlinkChainBackend(f)
	ref := RuleRef{Table: "filter", Chain: ChainAerolvmUser, Spec: dropSpec("10.0.0.2")}
	if err := b.DeleteAll(ref); err != nil {
		t.Fatal(err)
	}
	if f.gets[ChainAerolvmUser] != 2 || f.count(ChainAerolvmUser, dropSpec("10.0.0.2")...) != 0 {
		t.Fatalf("retry: listings %v, left %d", f.gets, f.count(ChainAerolvmUser, dropSpec("10.0.0.2")...))
	}
	f.add(ChainAerolvmUser, dropSpec("10.0.0.2")...)
	f.staleFlushes = batchAttempts
	if err := b.DeleteAll(ref); !errors.Is(err, errBatchStale) {
		t.Fatalf("err = %v, want the stale error after %d attempts", err, batchAttempts)
	}
	if f.count(ChainAerolvmUser, dropSpec("10.0.0.2")...) != 1 {
		t.Fatal("a failed batch must change nothing")
	}
}

func TestNetlinkBatchErrors(t *testing.T) {
	ref := RuleRef{Table: "filter", Chain: ChainAerolvmUser, Spec: dropSpec("10.0.0.2")}
	ins := RuleInsert{RuleRef: ref, Pos: 1}
	boom := errors.New("boom")
	for _, tc := range []struct {
		name string
		prep func(*chainNFT)
		run  func(*netlinkBackend) error
	}{
		{"delete listing", func(f *chainNFT) { f.getErr = boom }, func(b *netlinkBackend) error { return b.DeleteAll(ref) }},
		{"delete queue", func(f *chainNFT) { f.add(ChainAerolvmUser, ref.Spec...); f.delErr = boom }, func(b *netlinkBackend) error { return b.DeleteAll(ref) }},
		{"delete commit", func(f *chainNFT) { f.add(ChainAerolvmUser, ref.Spec...); f.flushErr = boom }, func(b *netlinkBackend) error { return b.DeleteAll(ref) }},
		{"delete bad spec", nil, func(b *netlinkBackend) error {
			return b.DeleteAll(RuleRef{Table: "filter", Chain: ChainAerolvmUser, Spec: []string{"-x"}})
		}},
		{"delete bad table", nil, func(b *netlinkBackend) error {
			return b.DeleteAll(RuleRef{Table: "nat", Chain: "X", Spec: ref.Spec})
		}},
		{"ensure listing", func(f *chainNFT) { f.getErr = boom }, func(b *netlinkBackend) error { _, err := b.EnsureAll(ins); return err }},
		{"ensure commit", func(f *chainNFT) { f.flushErr = boom }, func(b *netlinkBackend) error { _, err := b.EnsureAll(ins); return err }},
		{"ensure bad spec", nil, func(b *netlinkBackend) error {
			_, err := b.EnsureAll(RuleInsert{RuleRef: RuleRef{Table: "filter", Chain: ChainAerolvmUser, Spec: []string{"-x"}}})
			return err
		}},
		{"ensure bad table", nil, func(b *netlinkBackend) error {
			_, err := b.EnsureAll(RuleInsert{RuleRef: RuleRef{Table: "nat", Chain: "X", Spec: ref.Spec}})
			return err
		}},
		{"ensure two in one chain", nil, func(b *netlinkBackend) error { _, err := b.EnsureAll(ins, ins); return err }},
		{"conn", nil, func(*netlinkBackend) error {
			nb := &netlinkBackend{newConn: func() (nftAPI, error) { return nil, boom }}
			if _, err := nb.EnsureAll(ins); err == nil {
				return nil
			}
			return nb.DeleteAll(ref)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newChainNFT()
			if tc.prep != nil {
				tc.prep(f)
			}
			if err := tc.run(netlinkChainBackend(f)); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

// TestNetlinkEnsureAllPositions: each missing rule goes where the per-rule
// Insert would put it (top, before the rule at the position, or appended),
// present ones are left, and it is one listing per chain and one commit.
func TestNetlinkEnsureAllPositions(t *testing.T) {
	f := newChainNFT()
	f.add(ChainAerolvmUser, dropSpec("10.0.0.9")...)
	f.add(ChainAerolvmInput, "-s", "10.0.0.8", "-j", "RETURN") // stands in for the established-return
	f.add(ChainAerolvmInput, inputBlockSpec("10.0.0.9")...)
	b := netlinkChainBackend(f)
	got, err := b.EnsureAll(
		RuleInsert{RuleRef: RuleRef{Table: "filter", Chain: ChainAerolvmUser, Spec: dropSpec("10.0.0.2")}, Pos: 1},
		RuleInsert{RuleRef: RuleRef{Table: "filter", Chain: ChainAerolvmInput, Spec: inputBlockSpec("10.0.0.2")}, Pos: 2},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []bool{true, true}) || f.flushes != 1 || f.gets[ChainAerolvmUser] != 1 || f.gets[ChainAerolvmInput] != 1 {
		t.Fatalf("inserted %v, commits %d, listings %v", got, f.flushes, f.gets)
	}
	if i := f.indexOf(ChainAerolvmUser, dropSpec("10.0.0.2")...); i != 0 {
		t.Fatalf("user DROP at %d, want the top", i)
	}
	if i := f.indexOf(ChainAerolvmInput, inputBlockSpec("10.0.0.2")...); i != 1 {
		t.Fatalf("input drop at %d, want position 2 (below the return)", i)
	}
	// Again: both present, nothing inserted, no commit.
	got, err = b.EnsureAll(
		RuleInsert{RuleRef: RuleRef{Table: "filter", Chain: ChainAerolvmUser, Spec: dropSpec("10.0.0.2")}, Pos: 1},
		RuleInsert{RuleRef: RuleRef{Table: "filter", Chain: ChainAerolvmInput, Spec: inputBlockSpec("10.0.0.2")}, Pos: 2},
	)
	if err != nil || !slices.Equal(got, []bool{false, false}) || f.flushes != 1 {
		t.Fatalf("second ensure: %v %v, %d commits", got, err, f.flushes)
	}
	// A position past the end appends.
	got, err = b.EnsureAll(RuleInsert{RuleRef: RuleRef{Table: "filter", Chain: "EMPTY", Spec: dropSpec("10.0.0.3")}, Pos: 5})
	if err != nil || !got[0] || f.indexOf("EMPTY", dropSpec("10.0.0.3")...) != 0 {
		t.Fatalf("append: %v %v", got, err)
	}
}

// TestNetlinkEnsureAllRetriesStalePosition: the rule a position named left
// the chain before the commit; the redo lists again and lands it.
func TestNetlinkEnsureAllRetriesStalePosition(t *testing.T) {
	f := newChainNFT()
	f.add(ChainAerolvmInput, "-s", "10.0.0.8", "-j", "RETURN")
	f.add(ChainAerolvmInput, inputBlockSpec("10.0.0.9")...)
	f.staleFlushes = 1
	b := netlinkChainBackend(f)
	got, err := b.EnsureAll(RuleInsert{RuleRef: RuleRef{Table: "filter", Chain: ChainAerolvmInput, Spec: inputBlockSpec("10.0.0.2")}, Pos: 2})
	if err != nil || !got[0] || f.gets[ChainAerolvmInput] != 2 || f.count(ChainAerolvmInput, inputBlockSpec("10.0.0.2")...) != 1 {
		t.Fatalf("got %v err %v listings %v", got, err, f.gets)
	}
	f.staleFlushes = batchAttempts
	if _, err := b.EnsureAll(RuleInsert{RuleRef: RuleRef{Table: "filter", Chain: ChainAerolvmInput, Spec: inputBlockSpec("10.0.0.3")}, Pos: 2}); !errors.Is(err, errBatchStale) {
		t.Fatalf("err = %v, want stale after %d attempts", err, batchAttempts)
	}
}

// TestNetlinkManagerBatchMatchesPerRule drives the Manager over the batch
// backend and over the same backend with the batch hidden (the per-rule
// path), from the same starting chains, and requires the same rules after
// every step: the batch changes the cost, never the result.
func TestNetlinkManagerBatchMatchesPerRule(t *testing.T) {
	type step struct {
		name string
		run  func(*Manager) (bool, error)
	}
	steps := []step{
		{"block", func(m *Manager) (bool, error) { return m.BlockAllEgressReport("10.0.0.2") }},
		{"block again", func(m *Manager) (bool, error) { return m.BlockAllEgressReport("10.0.0.2") }},
		{"block other", func(m *Manager) (bool, error) { return m.BlockAllEgressReport("10.0.0.3") }},
		{"clear", func(m *Manager) (bool, error) { return false, m.ClearBlockAllEgress("10.0.0.2") }},
		{"clear again", func(m *Manager) (bool, error) { return false, m.ClearBlockAllEgress("10.0.0.2") }},
		{"clear unknown", func(m *Manager) (bool, error) { return false, m.ClearBlockAllEgress("10.0.0.77") }},
	}
	run := func(batch bool) []string {
		f := newChainNFT()
		f.add(ChainAerolvmInput, "-s", "10.0.0.8", "-j", "RETURN")
		f.add(ChainAerolvmUser, dropSpec("10.0.0.2")...) // a leftover the clear must sweep with the new one
		var be RuleBackend = netlinkChainBackend(f)
		if !batch {
			be = struct{ RuleBackend }{be} // hides DeleteAll/EnsureAll
		}
		m := &Manager{enabled: true, ipt: be, userChain: ChainAerolvmUser}
		m.inputReady.Store(true)
		var trace []string
		for _, s := range steps {
			ins, err := s.run(m)
			trace = append(trace, fmt.Sprintf("%s: inserted=%v err=%v user=%d/%d input=%d/%d", s.name, ins, err != nil,
				f.count(ChainAerolvmUser, dropSpec("10.0.0.2")...), f.count(ChainAerolvmUser, dropSpec("10.0.0.3")...),
				f.count(ChainAerolvmInput, inputBlockSpec("10.0.0.2")...), f.count(ChainAerolvmInput, inputBlockSpec("10.0.0.3")...)))
		}
		return trace
	}
	per, batch := run(false), run(true)
	if !slices.Equal(per, batch) {
		t.Fatalf("batch diverges from the per-rule path:\nper-rule %q\nbatch    %q", per, batch)
	}
}

// TestNetlinkBlockClearCost: through the Manager, the block-all install and
// its lift each read AEROLVM-USER and AEROLVM-INPUT once and commit once,
// however many other sandboxes' rules the chains hold. (The per-rule path
// read them four and six times, and committed twice.)
func TestNetlinkBlockClearCost(t *testing.T) {
	f := newChainNFT()
	f.add(ChainAerolvmInput, "-s", "10.0.0.8", "-j", "RETURN")
	for i := 0; i < 50; i++ {
		f.add(ChainAerolvmUser, dropSpec(fmt.Sprintf("10.0.1.%d", i+2))...)
		f.add(ChainAerolvmInput, inputBlockSpec(fmt.Sprintf("10.0.1.%d", i+2))...)
	}
	m := &Manager{enabled: true, ipt: netlinkChainBackend(f), userChain: ChainAerolvmUser}
	m.inputReady.Store(true)
	for _, step := range []struct {
		name string
		run  func() error
	}{
		{"block", func() error { _, err := m.BlockAllEgressReport("10.0.0.2"); return err }},
		{"clear", func() error { return m.ClearBlockAllEgress("10.0.0.2") }},
	} {
		f.gets, f.flushes = map[string]int{}, 0
		if err := step.run(); err != nil {
			t.Fatal(err)
		}
		if f.gets[ChainAerolvmUser] != 1 || f.gets[ChainAerolvmInput] != 1 || f.flushes != 1 {
			t.Fatalf("%s: listings %v, commits %d; want each chain read once and one commit", step.name, f.gets, f.flushes)
		}
	}
}

// TestNetlinkBatchConnAndListingEdges: a connection that fails after the
// listing fails the batch with nothing applied, and two refs in one chain
// share one listing.
func TestNetlinkBatchConnAndListingEdges(t *testing.T) {
	f := newChainNFT()
	f.add(ChainAerolvmUser, dropSpec("10.0.0.2")...)
	f.add(ChainAerolvmUser, dropSpec("10.0.0.3")...)
	calls := 0
	boom := errors.New("conn boom")
	failSecond := &netlinkBackend{newConn: func() (nftAPI, error) {
		calls++
		if calls > 1 {
			return nil, boom
		}
		return f, nil
	}}
	ref := RuleRef{Table: "filter", Chain: ChainAerolvmUser, Spec: dropSpec("10.0.0.2")}
	if err := failSecond.DeleteAll(ref); !errors.Is(err, boom) {
		t.Fatalf("delete: %v", err)
	}
	calls = 0
	if _, err := failSecond.EnsureAll(RuleInsert{RuleRef: RuleRef{Table: "filter", Chain: ChainAerolvmUser, Spec: dropSpec("10.0.0.9")}, Pos: 1}); !errors.Is(err, boom) {
		t.Fatalf("ensure: %v", err)
	}
	if f.count(ChainAerolvmUser, dropSpec("10.0.0.2")...) != 1 || f.flushes != 0 {
		t.Fatal("a failed batch must apply nothing")
	}
	f.gets = map[string]int{}
	if err := netlinkChainBackend(f).DeleteAll(ref, RuleRef{Table: "filter", Chain: ChainAerolvmUser, Spec: dropSpec("10.0.0.3")}); err != nil {
		t.Fatal(err)
	}
	if f.gets[ChainAerolvmUser] != 1 || f.count(ChainAerolvmUser, dropSpec("10.0.0.2")...) != 0 || f.count(ChainAerolvmUser, dropSpec("10.0.0.3")...) != 0 {
		t.Fatalf("listings %v; both rules must go from one listing", f.gets)
	}
}

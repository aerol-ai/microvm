//go:build linux

package netrules

import (
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// setKernel is nftables as the block sets see it; every conn queues and its
// Flush applies the queue all or nothing.
type setKernel struct {
	mu      sync.Mutex
	exists  bool
	sets    map[string]map[string]bool
	rules   map[string][]*nftables.Rule
	flushes int
	// injected failures
	addSetErr, getRulesErr, getElemsErr error
	flushErrs                           []error // consumed one per Flush
}

func newSetKernel() *setKernel {
	return &setKernel{sets: map[string]map[string]bool{}, rules: map[string][]*nftables.Rule{}}
}

type setConn struct {
	k     *setKernel
	queue []func(k *setKernel) error
}

func (c *setConn) AddTable(t *nftables.Table) *nftables.Table {
	c.queue = append(c.queue, func(k *setKernel) error { k.exists = true; return nil })
	return t
}

func (c *setConn) AddSet(s *nftables.Set, _ []nftables.SetElement) error {
	if c.k.addSetErr != nil {
		return c.k.addSetErr
	}
	c.queue = append(c.queue, func(k *setKernel) error {
		if k.sets[s.Name] == nil {
			k.sets[s.Name] = map[string]bool{}
		}
		return nil
	})
	return nil
}

func (c *setConn) AddChain(ch *nftables.Chain) *nftables.Chain { return ch }

func (c *setConn) GetRules(_ *nftables.Table, ch *nftables.Chain) ([]*nftables.Rule, error) {
	c.k.mu.Lock()
	defer c.k.mu.Unlock()
	if c.k.getRulesErr != nil {
		return nil, c.k.getRulesErr
	}
	return slices.Clone(c.k.rules[ch.Name]), nil
}

func (c *setConn) AddRule(r *nftables.Rule) *nftables.Rule {
	c.queue = append(c.queue, func(k *setKernel) error {
		k.rules[r.Chain.Name] = append(k.rules[r.Chain.Name], r)
		return nil
	})
	return r
}

func (c *setConn) FlushChain(ch *nftables.Chain) {
	c.queue = append(c.queue, func(k *setKernel) error { delete(k.rules, ch.Name); return nil })
}

func (c *setConn) elements(s *nftables.Set, vals []nftables.SetElement, add bool) {
	c.queue = append(c.queue, func(k *setKernel) error {
		set := k.sets[s.Name]
		if !k.exists || set == nil {
			return syscall.ENOENT
		}
		for _, v := range vals {
			ip := net.IP(v.Key).String()
			if add {
				set[ip] = true
				continue
			}
			if !set[ip] {
				return syscall.ENOENT
			}
			delete(set, ip)
		}
		return nil
	})
}

func (c *setConn) SetAddElements(s *nftables.Set, vals []nftables.SetElement) error {
	c.elements(s, vals, true)
	return nil
}

func (c *setConn) SetDeleteElements(s *nftables.Set, vals []nftables.SetElement) error {
	c.elements(s, vals, false)
	return nil
}

func (c *setConn) GetSetElements(s *nftables.Set) ([]nftables.SetElement, error) {
	c.k.mu.Lock()
	defer c.k.mu.Unlock()
	if c.k.getElemsErr != nil {
		return nil, c.k.getElemsErr
	}
	set := c.k.sets[s.Name]
	if !c.k.exists || set == nil {
		return nil, syscall.ENOENT
	}
	var out []nftables.SetElement
	for ip := range set {
		out = append(out, nftables.SetElement{Key: net.ParseIP(ip).To4()})
	}
	out = append(out, nftables.SetElement{Key: []byte{1, 2}}) // not an address: skipped
	return out, nil
}

func (c *setConn) Flush() error {
	k := c.k
	k.mu.Lock()
	defer k.mu.Unlock()
	k.flushes++
	if len(k.flushErrs) > 0 {
		err := k.flushErrs[0]
		k.flushErrs = k.flushErrs[1:]
		if err != nil {
			c.queue = nil
			return err
		}
	}
	// All or nothing: apply on a copy.
	snap := &setKernel{exists: k.exists, sets: map[string]map[string]bool{}, rules: map[string][]*nftables.Rule{}}
	for n, s := range k.sets {
		snap.sets[n] = map[string]bool{}
		for ip := range s {
			snap.sets[n][ip] = true
		}
	}
	for n, r := range k.rules {
		snap.rules[n] = slices.Clone(r)
	}
	for _, op := range c.queue {
		if err := op(snap); err != nil {
			c.queue = nil
			return err
		}
	}
	c.queue = nil
	k.exists, k.sets, k.rules = snap.exists, snap.sets, snap.rules
	return nil
}

func setBackend(k *setKernel, rules *chainNFT) *netlinkBackend {
	b := &netlinkBackend{newSetConn: func() (nftSetAPI, error) { return &setConn{k: k}, nil }}
	if rules != nil {
		b.newConn = func() (nftAPI, error) { return rules, nil }
	}
	return b
}

func TestNetlinkEnsureBlockTable(t *testing.T) {
	k := newSetKernel()
	b := setBackend(k, nil)
	if err := b.EnsureBlockTable(); err != nil {
		t.Fatal(err)
	}
	if !k.exists || k.sets[BlockedSet] == nil || k.sets[ReleasedSet] == nil {
		t.Fatalf("table %v sets %v", k.exists, k.sets)
	}
	if !rulesMatch(k.rules["forward"], blockDropExprs()) || !rulesMatch(k.rules["input"], blockEstablishedExprs(), blockDropExprs()) {
		t.Fatalf("rules %v", k.rules)
	}
	// In place: nothing rewritten.
	n := k.flushes
	if err := b.EnsureBlockTable(); err != nil || k.flushes != n+1 {
		t.Fatalf("second ensure: err=%v flushes %d → %d (want only the idempotent create)", err, n, k.flushes)
	}
	// A rule changed under us: the chain is rewritten in one transaction.
	k.rules["input"] = k.rules["input"][1:]
	if err := b.EnsureBlockTable(); err != nil || !rulesMatch(k.rules["input"], blockEstablishedExprs(), blockDropExprs()) {
		t.Fatalf("repair: err=%v rules %v", err, k.rules["input"])
	}
	// Elements survive an ensure.
	k.sets[BlockedSet]["10.1.0.2"] = true
	if err := b.EnsureBlockTable(); err != nil || !k.sets[BlockedSet]["10.1.0.2"] {
		t.Fatal("ensure dropped an element")
	}
}

func TestNetlinkEnsureBlockTableErrors(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name string
		prep func(k *setKernel)
		want string
	}{
		{"add set", func(k *setKernel) { k.addSetErr = boom }, "nft add set"},
		{"create flush", func(k *setKernel) { k.flushErrs = []error{boom} }, "nft add aerolvm_block table"},
		{"rules read", func(k *setKernel) { k.getRulesErr = boom }, "nft get forward rules"},
		{"rules write", func(k *setKernel) { k.flushErrs = []error{nil, boom} }, "nft write aerolvm_block rules"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := newSetKernel()
			c.prep(k)
			if err := setBackend(k, nil).EnsureBlockTable(); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	nb := &netlinkBackend{}
	if err := nb.EnsureBlockTable(); !errors.Is(err, errNoSetConn) {
		t.Fatalf("no set conn: %v", err)
	}
	if _, _, err := nb.BlockSetElements(); !errors.Is(err, errNoSetConn) {
		t.Fatalf("no set conn: %v", err)
	}
	if err := nb.ApplyBlockSetOps([]blockSetOp{{Set: BlockedSet, Add: true, IP: "10.1.0.2"}}); !errors.Is(err, errNoSetConn) {
		t.Fatalf("no set conn: %v", err)
	}
}

func TestNetlinkBlockSetOps(t *testing.T) {
	k := newSetKernel()
	b := setBackend(k, nil)
	if _, _, err := b.BlockSetElements(); !errors.Is(err, errBlockTableMissing) {
		t.Fatalf("no table: %v", err)
	}
	if err := b.ApplyBlockSetOps([]blockSetOp{{Set: BlockedSet, Add: true, IP: "10.1.0.2"}}); !errors.Is(err, errBlockTableMissing) {
		t.Fatalf("no table: %v", err)
	}
	if err := b.EnsureBlockTable(); err != nil {
		t.Fatal(err)
	}
	if err := b.ApplyBlockSetOps(nil); err != nil {
		t.Fatal(err)
	}
	if err := b.ApplyBlockSetOps([]blockSetOp{
		{Set: BlockedSet, Add: true, IP: "10.1.0.2"},
		{Set: BlockedSet, Add: true, IP: "10.1.0.3"},
		{Set: ReleasedSet, Add: true, IP: "10.1.0.3"},
	}); err != nil {
		t.Fatal(err)
	}
	blocked, released, err := b.BlockSetElements()
	slices.Sort(blocked)
	if err != nil || !slices.Equal(blocked, []string{"10.1.0.2", "10.1.0.3"}) || !slices.Equal(released, []string{"10.1.0.3"}) {
		t.Fatalf("blocked %v released %v err %v", blocked, released, err)
	}
	// A delete of an absent element fails the whole transaction.
	if err := b.ApplyBlockSetOps([]blockSetOp{{Set: ReleasedSet, IP: "10.1.0.3"}, {Set: ReleasedSet, IP: "10.1.0.9"}}); !errors.Is(err, errBlockTableMissing) {
		t.Fatalf("absent delete: %v", err)
	}
	if !k.sets[ReleasedSet]["10.1.0.3"] {
		t.Fatal("a failed transaction applied part of itself")
	}
	if err := b.ApplyBlockSetOps([]blockSetOp{{Set: BlockedSet, Add: true, IP: "fd00::1"}}); err == nil {
		t.Fatal("IPv6 element accepted")
	}
	k.flushErrs = []error{errors.New("enobufs")}
	if err := b.ApplyBlockSetOps([]blockSetOp{{Set: BlockedSet, Add: true, IP: "10.1.0.4"}}); err == nil || errors.Is(err, errBlockTableMissing) {
		t.Fatalf("other flush error: %v", err)
	}
	k.getElemsErr = errors.New("dump boom")
	if _, _, err := b.BlockSetElements(); err == nil || errors.Is(err, errBlockTableMissing) {
		t.Fatalf("other dump error: %v", err)
	}
	k.getElemsErr = nil
	k.sets[ReleasedSet] = nil
	if _, _, err := b.BlockSetElements(); !errors.Is(err, errBlockTableMissing) {
		t.Fatalf("missing released set: %v", err)
	}
}

func TestNetlinkLegacyBlockIPs(t *testing.T) {
	f := newChainNFT()
	f.add(ChainAerolvmUser, egressDropSpec("10.1.1.2")...)
	f.add(ChainAerolvmUser, egressDropSpec("10.1.1.2")...) // a duplicate
	f.add(ChainAerolvmUser, holdSpec("10.1.1.3")...)
	f.add(ChainAerolvmUser, "-s", "10.1.1.4", "-d", "1.1.1.0/24", "-j", "ACCEPT")
	f.add(ChainAerolvmUser, "-d", "10.1.1.5", "-j", "DROP")
	f.add(ChainAerolvmUser, egressDropSpec("10.1.1.6")...)
	f.add(ChainAerolvmInput, inputBlockSpec("10.1.1.7")...)
	b := setBackend(newSetKernel(), f)
	got, err := b.LegacyBlockIPs(ChainAerolvmUser, egressDropSpec)
	if err != nil || !slices.Equal(got, []string{"10.1.1.2", "10.1.1.6"}) {
		t.Fatalf("user chain: %v %v", got, err)
	}
	if got, err := b.LegacyBlockIPs(ChainAerolvmInput, inputBlockSpec); err != nil || !slices.Equal(got, []string{"10.1.1.7"}) {
		t.Fatalf("input chain: %v %v", got, err)
	}
	f.getErr = syscall.ENOENT
	if got, err := b.LegacyBlockIPs(ChainAerolvmUser, egressDropSpec); err != nil || got != nil {
		t.Fatalf("missing chain: %v %v", got, err)
	}
	f.getErr = errors.New("boom")
	if _, err := b.LegacyBlockIPs(ChainAerolvmUser, egressDropSpec); err == nil {
		t.Fatal("read error hidden")
	}
	if _, err := b.LegacyBlockIPs("nat|x", egressDropSpec); err != nil {
		t.Logf("odd chain: %v", err)
	}
	bad := &netlinkBackend{newConn: func() (nftAPI, error) { return nil, errors.New("conn boom") }}
	if _, err := bad.LegacyBlockIPs(ChainAerolvmUser, egressDropSpec); err == nil {
		t.Fatal("conn error hidden")
	}
	if ip := ruleSourceIP([]expr.Any{&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, &expr.Counter{}}); ip != "" {
		t.Fatalf("payload without cmp: %q", ip)
	}
	if ip := ruleSourceIP(nil); ip != "" {
		t.Fatal("empty rule")
	}
}

// TestNetlinkBlockSetsThroughTheManager: the Manager on the netlink
// backend, end to end against the fake kernel, conversion included.
func TestNetlinkBlockSetsThroughTheManager(t *testing.T) {
	ResetBlockSetsForTest()
	t.Cleanup(ResetBlockSetsForTest)
	f := newChainNFT()
	f.add(ChainAerolvmUser, egressDropSpec("10.1.2.2")...)
	f.add(ChainAerolvmInput, inputBlockSpec("10.1.2.2")...)
	k := newSetKernel()
	b := setBackend(k, f)
	m := &Manager{enabled: true, ipt: b, userChain: ChainAerolvmUser}
	m.inputReady.Store(true)
	if err := m.PrepareBlockSets(); err != nil {
		t.Fatal(err)
	}
	if !k.sets[BlockedSet]["10.1.2.2"] || f.count(ChainAerolvmUser, egressDropSpec("10.1.2.2")...) != 0 || f.count(ChainAerolvmInput, inputBlockSpec("10.1.2.2")...) != 0 {
		t.Fatalf("conversion: sets %v user %d", k.sets, f.count(ChainAerolvmUser, egressDropSpec("10.1.2.2")...))
	}
	if err := m.LiftBlockAllEgress("10.1.2.2"); err != nil || !k.sets[ReleasedSet]["10.1.2.2"] {
		t.Fatalf("lift: %v", err)
	}
	if err := m.ClearBlockAllEgress("10.1.2.2"); err != nil || k.sets[ReleasedSet]["10.1.2.2"] || k.sets[BlockedSet]["10.1.2.2"] {
		t.Fatalf("let-go: %v %v", err, k.sets)
	}
}

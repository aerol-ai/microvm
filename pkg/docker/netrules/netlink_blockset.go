//go:build linux

package netrules

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// nftSetAPI is the Conn surface the block sets need; *nftables.Conn has it,
// and tests inject a fake.
type nftSetAPI interface {
	ListTableOfFamily(name string, family nftables.TableFamily) (*nftables.Table, error)
	GetSetByName(t *nftables.Table, name string) (*nftables.Set, error)
	ListChain(t *nftables.Table, chain string) (*nftables.Chain, error)
	AddTable(t *nftables.Table) *nftables.Table
	AddSet(s *nftables.Set, vals []nftables.SetElement) error
	AddChain(c *nftables.Chain) *nftables.Chain
	GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error)
	AddRule(r *nftables.Rule) *nftables.Rule
	FlushChain(c *nftables.Chain)
	SetAddElements(s *nftables.Set, vals []nftables.SetElement) error
	SetDeleteElements(s *nftables.Set, vals []nftables.SetElement) error
	GetSetElements(s *nftables.Set) ([]nftables.SetElement, error)
	Flush() error
}

var errNoSetConn = errors.New("netrules: backend has no nftables set connection")

// lastingConn is a set conn that keeps its netlink socket open across
// operations (*nftables.Conn made AsLasting).
type lastingConn interface{ CloseLasting() error }

// withSetConn runs fn on the backend's set conn, one socket kept open.
//
// Closing a netfilter netlink socket is not free. The kernel's release
// notifier (nft_rcv_nl_event) takes the nftables commit mutex and, when an
// earlier commit anywhere on the node left transactions to free (a delete,
// a chain update), waits an RCU grace period for them before it lets go:
// 5 to 10 ms on a 48-vCPU host, measured on kernel 6.8, and no commit on the
// node (another create's lift) runs meanwhile. A socket per operation paid
// that at its close after any delete on the node and held every other
// writer behind it. A socket that stays open never closes on these paths.
//
// fn's error drops the conn (it may hold queued messages or replies not
// read); the next operation dials a new one.
func (b *netlinkBackend) withSetConn(fn func(nftSetAPI) error) error {
	if b.newSetConn == nil {
		return errNoSetConn
	}
	b.setMu.Lock()
	defer b.setMu.Unlock()
	if b.setC == nil {
		c, err := b.newSetConn()
		if err != nil {
			return err
		}
		b.setC = c
	}
	err := fn(b.setC)
	if err != nil {
		if l, ok := b.setC.(lastingConn); ok {
			_ = l.CloseLasting()
		}
		b.setC = nil
	}
	return err
}

func blockTableRef() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyIPv4, Name: BlockTable}
}

func blockSetRef(t *nftables.Table, name string) *nftables.Set {
	return &nftables.Set{Table: t, Name: name, KeyType: nftables.TypeIPAddr}
}

// blockChainPriority runs the block chains just before the filter table's:
// a blocked packet is dropped before anything else spends time on it. A
// drop is final at any priority; an accept here ends only this chain.
const blockChainPriority = -5

// blockChains are the two base chains: forwarded traffic (to the world,
// to other sandboxes) and traffic to the node itself.
func blockChains(t *nftables.Table) (forward, input *nftables.Chain) {
	accept := nftables.ChainPolicyAccept
	mk := func(name string, hook *nftables.ChainHook) *nftables.Chain {
		return &nftables.Chain{
			Name: name, Table: t, Type: nftables.ChainTypeFilter, Hooknum: hook,
			Priority: nftables.ChainPriorityRef(blockChainPriority), Policy: &accept,
		}
	}
	return mk("forward", nftables.ChainHookForward), mk("input", nftables.ChainHookInput)
}

// blockDropExprs is `ip saddr @blocked ip saddr != @released counter drop`.
func blockDropExprs() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Lookup{SourceRegister: 1, SetName: BlockedSet},
		&expr.Lookup{SourceRegister: 1, SetName: ReleasedSet, Invert: true},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// blockEstablishedExprs is `ct state established,related accept`: replies
// to connections the node opened (sandboxd to toolboxd) still reach it, as
// AEROLVM-INPUT's established-return rule let them. Native ct, not the xt
// conntrack match, so nothing here waits on nft_compat destructors.
func blockEstablishedExprs() []expr.Any {
	zero := []byte{0, 0, 0, 0}
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: zero},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: zero},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

func rulesMatch(rules []*nftables.Rule, want ...[]expr.Any) bool {
	if len(rules) != len(want) {
		return false
	}
	for i, r := range rules {
		if !exprsEqualIgnoringCounters(want[i], r.Exprs) {
			return false
		}
	}
	return true
}

// EnsureBlockTable implements blockSetBackend: the table, both sets and the
// base chains in one transaction (each an idempotent create, so existing
// elements stay), then each chain's rules, rewritten in one transaction
// only if they aren't exactly the expected ones. It reads first and writes
// only what is missing or wrong: the re-assert runs it every interval, and
// even an idempotent create of a chain that is already there commits a
// chain update the kernel frees after an RCU grace period, which the next
// netfilter socket closed on the node waits for under the commit mutex.
func (b *netlinkBackend) EnsureBlockTable() error {
	return b.withSetConn(ensureBlockTable)
}

func ensureBlockTable(conn nftSetAPI) error {
	t := blockTableRef()
	fwd, in := blockChains(t)
	if !blockTableInPlace(conn, t, fwd, in) {
		conn.AddTable(t)
		for _, name := range []string{BlockedSet, ReleasedSet} {
			if err := conn.AddSet(blockSetRef(t, name), nil); err != nil {
				return fmt.Errorf("nft add set %s: %w", name, err)
			}
		}
		conn.AddChain(fwd)
		conn.AddChain(in)
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("nft add %s table: %w", BlockTable, err)
		}
	}
	type chainRules struct {
		ch   *nftables.Chain
		want [][]expr.Any
	}
	fix := false
	for _, c := range []chainRules{
		{fwd, [][]expr.Any{blockDropExprs()}},
		{in, [][]expr.Any{blockEstablishedExprs(), blockDropExprs()}},
	} {
		rules, err := conn.GetRules(t, c.ch)
		if err != nil {
			return fmt.Errorf("nft get %s rules: %w", c.ch.Name, err)
		}
		if rulesMatch(rules, c.want...) {
			continue
		}
		// Flush and refill in one transaction: never a moment without the
		// drop.
		conn.FlushChain(c.ch)
		for _, exprs := range c.want {
			conn.AddRule(&nftables.Rule{Table: t, Chain: c.ch, Exprs: exprs})
		}
		fix = true
	}
	if !fix {
		return nil
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nft write %s rules: %w", BlockTable, err)
	}
	return nil
}

// blockTableInPlace reports whether the table, both address sets and both
// base chains (hook, priority, type, accept policy) are there as
// EnsureBlockTable makes them. Any read error counts as not in place: the
// idempotent create that follows is always safe.
func blockTableInPlace(conn nftSetAPI, t *nftables.Table, chains ...*nftables.Chain) bool {
	if _, err := conn.ListTableOfFamily(t.Name, t.Family); err != nil {
		return false
	}
	for _, name := range []string{BlockedSet, ReleasedSet} {
		s, err := conn.GetSetByName(t, name)
		if err != nil || s == nil || s.KeyType.Name != nftables.TypeIPAddr.Name {
			return false
		}
	}
	for _, want := range chains {
		got, err := conn.ListChain(t, want.Name)
		if err != nil || got == nil || got.Type != want.Type ||
			got.Hooknum == nil || *got.Hooknum != *want.Hooknum ||
			got.Priority == nil || *got.Priority != *want.Priority ||
			got.Policy == nil || *got.Policy != *want.Policy {
			return false
		}
	}
	return true
}

// BlockSetElements implements blockSetBackend.
func (b *netlinkBackend) BlockSetElements() (blocked, released []string, err error) {
	err = b.withSetConn(func(conn nftSetAPI) error {
		blocked, released, err = blockSetElements(conn)
		return err
	})
	return blocked, released, err
}

func blockSetElements(conn nftSetAPI) (blocked, released []string, err error) {
	t := blockTableRef()
	read := func(name string) ([]string, error) {
		els, err := conn.GetSetElements(blockSetRef(t, name))
		if err != nil {
			if isNetlinkNotExist(err) {
				return nil, fmt.Errorf("%w: %v", errBlockTableMissing, err)
			}
			return nil, fmt.Errorf("nft get %s elements: %w", name, err)
		}
		out := make([]string, 0, len(els))
		for _, e := range els {
			if len(e.Key) == 4 {
				out = append(out, net.IP(e.Key).String())
			}
		}
		return out, nil
	}
	if blocked, err = read(BlockedSet); err != nil {
		return nil, nil, err
	}
	if released, err = read(ReleasedSet); err != nil {
		return nil, nil, err
	}
	return blocked, released, nil
}

// ApplyBlockSetOps implements blockSetBackend: one transaction, in order.
func (b *netlinkBackend) ApplyBlockSetOps(ops []blockSetOp) error {
	if len(ops) == 0 {
		return nil
	}
	return b.withSetConn(func(conn nftSetAPI) error { return applyBlockSetOps(conn, ops) })
}

func applyBlockSetOps(conn nftSetAPI, ops []blockSetOp) (err error) {
	t := blockTableRef()
	for _, op := range ops {
		ip := net.ParseIP(op.IP).To4()
		if ip == nil {
			return fmt.Errorf("netrules: block set element %q is not an IPv4 address", op.IP)
		}
		el := []nftables.SetElement{{Key: ip}}
		set := blockSetRef(t, op.Set)
		if op.Add {
			err = conn.SetAddElements(set, el)
		} else {
			err = conn.SetDeleteElements(set, el)
		}
		if err != nil {
			return fmt.Errorf("nft %s element: %w", op.Set, err)
		}
	}
	if err := conn.Flush(); err != nil {
		if isNetlinkNotExist(err) {
			return fmt.Errorf("%w: %v", errBlockTableMissing, err)
		}
		return fmt.Errorf("nft flush block sets: %w", err)
	}
	return nil
}

// LegacyBlockIPs implements legacyBlockLister: the addresses whose
// spec(ip) rule an older daemon left in chain. A chain that isn't there
// holds none.
func (b *netlinkBackend) LegacyBlockIPs(chain string, spec func(ip string) []string) ([]string, error) {
	tbl, ch, err := lookupTableChain("filter", chain)
	if err != nil {
		return nil, err
	}
	conn, err := b.newConn()
	if err != nil {
		return nil, err
	}
	rules, err := conn.GetRules(tbl, ch)
	if err != nil {
		if isNetlinkNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("nft get %s rules: %w", chain, err)
	}
	var out []string
	seen := map[string]bool{}
	for _, r := range rules {
		ip := ruleSourceIP(r.Exprs)
		if ip == "" || seen[ip] {
			continue
		}
		want, err := exprsFromRulespec(spec(ip)...)
		if err != nil || !exprsEqualIgnoringCounters(want, r.Exprs) {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out, nil
}

// ruleSourceIP is the /32 source a rule matches first, or "".
func ruleSourceIP(exprs []expr.Any) string {
	for i := 0; i+1 < len(exprs); i++ {
		p, ok := exprs[i].(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseNetworkHeader || p.Offset != 12 || p.Len != 4 {
			continue
		}
		if c, ok := exprs[i+1].(*expr.Cmp); ok && c.Op == expr.CmpOpEq && len(c.Data) == 4 {
			return net.IP(c.Data).String()
		}
		return ""
	}
	return ""
}

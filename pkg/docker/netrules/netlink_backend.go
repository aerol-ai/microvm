//go:build linux

package netrules

import (
	"fmt"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// nftAPI is the Conn surface netlinkBackend needs. *nftables.Conn satisfies
// it; tests inject a fake so Exists/Insert/Delete/bootstrap are covered without
// CAP_NET_ADMIN or a live nftables socket.
type nftAPI interface {
	GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error)
	InsertRule(r *nftables.Rule) *nftables.Rule
	DelRule(r *nftables.Rule) error
	ListChains() ([]*nftables.Chain, error)
	AddChain(c *nftables.Chain) *nftables.Chain
	Flush() error
}

// netlinkBackend drives DOCKER-USER via google/nftables (netlink), translating
// the Manager's iptables-shaped argv into nft expressions. Rules land in the
// iptables-nft compat filter/DOCKER-USER chain so iptables -L still lists them.
//
// Every operation runs on its own Conn: nftables.Conn buffers messages until
// Flush, so a shared instance would need a backend-wide mutex — which would
// re-serialize all container IPs behind one lock and undo the Manager's
// per-IP sharding. Per-op conns are cheap in non-lasting mode (the netlink
// socket opens per Flush/GetRules, not per New), and same-IP mutual exclusion
// is already the Manager's job via lockIP.
type netlinkBackend struct {
	newConn func() (nftAPI, error)
}

// NewNetlinkBackend wires the per-operation nftables connection factory.
// Callers must be on linux; non-linux builds use the stub that always errors.
func NewNetlinkBackend() (RuleBackend, error) {
	return &netlinkBackend{newConn: func() (nftAPI, error) {
		c, err := nftables.New()
		if err != nil {
			return nil, fmt.Errorf("nftables conn: %w", err)
		}
		return c, nil
	}}, nil
}

func (b *netlinkBackend) Exists(table, chain string, rulespec ...string) (bool, error) {
	want, err := exprsFromRulespec(rulespec...)
	if err != nil {
		return false, err
	}
	tbl, ch, err := lookupTableChain(table, chain)
	if err != nil {
		return false, err
	}
	conn, err := b.newConn()
	if err != nil {
		return false, err
	}
	rules, err := conn.GetRules(tbl, ch)
	if err != nil {
		return false, fmt.Errorf("nft get rules: %w", err)
	}
	for _, r := range rules {
		if exprsEqualIgnoringCounters(want, r.Exprs) {
			return true, nil
		}
	}
	return false, nil
}

func (b *netlinkBackend) Insert(table, chain string, pos int, rulespec ...string) error {
	exprs, err := exprsFromRulespec(rulespec...)
	if err != nil {
		return err
	}
	tbl, ch, err := lookupTableChain(table, chain)
	if err != nil {
		return err
	}
	conn, err := b.newConn()
	if err != nil {
		return err
	}
	rule := &nftables.Rule{Table: tbl, Chain: ch, Exprs: exprs}
	// Manager always Inserts at position 1 (top). nftables InsertRule without
	// Position inserts at the beginning of the chain — same semantics.
	if pos > 1 {
		rules, gerr := conn.GetRules(tbl, ch)
		if gerr != nil {
			return fmt.Errorf("nft get rules for insert pos: %w", gerr)
		}
		idx := pos - 1
		if idx < len(rules) {
			rule.Position = rules[idx].Handle
		}
	}
	conn.InsertRule(rule)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nft insert: %w", err)
	}
	return nil
}

func (b *netlinkBackend) Delete(table, chain string, rulespec ...string) error {
	want, err := exprsFromRulespec(rulespec...)
	if err != nil {
		return err
	}
	tbl, ch, err := lookupTableChain(table, chain)
	if err != nil {
		return err
	}
	conn, err := b.newConn()
	if err != nil {
		return err
	}
	rules, err := conn.GetRules(tbl, ch)
	if err != nil {
		return fmt.Errorf("nft get rules: %w", err)
	}
	for _, r := range rules {
		if !exprsEqualIgnoringCounters(want, r.Exprs) {
			continue
		}
		if err := conn.DelRule(r); err != nil {
			return fmt.Errorf("nft del rule: %w", err)
		}
		if err := conn.Flush(); err != nil {
			// ENOENT mid-flush means a concurrent clear already removed it.
			if isNetlinkNotExist(err) {
				return err
			}
			return fmt.Errorf("nft flush del: %w", err)
		}
		return nil
	}
	return syscall.ENOENT
}

// EnsureUserChain creates the regular filter chain (e.g. AEROLVM-USER) if it is
// absent, in the iptables-nft compat `ip filter` table so `iptables -L` lists
// it and the Manager's per-IP DROP/ACCEPT rules land there. Idempotent: an
// existing chain (including a docker-created DOCKER-USER) is a no-op.
//
// NOTE: exercised offline only against the fake nftAPI (chain-exists idempotency
// + AddChain-on-absent). Live nftables realization requires CAP_NET_ADMIN and is
// covered by the containerd integration suite, not `make test`.
func (b *netlinkBackend) EnsureUserChain(chain string) error {
	tbl, _, err := lookupTableChain("filter", chain)
	if err != nil {
		return err
	}
	if chain == "" {
		return fmt.Errorf("ensure user chain: empty chain name")
	}
	conn, err := b.newConn()
	if err != nil {
		return err
	}
	chains, err := conn.ListChains()
	if err != nil {
		return fmt.Errorf("nft list chains: %w", err)
	}
	for _, c := range chains {
		if c != nil && c.Name == chain && c.Table != nil &&
			c.Table.Name == tbl.Name && c.Table.Family == tbl.Family {
			return nil
		}
	}
	conn.AddChain(&nftables.Chain{Name: chain, Table: tbl})
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nft add chain %s: %w", chain, err)
	}
	return nil
}

// EnsureForwardJump inserts a `-j <userChain>` verdict at the top of the FORWARD
// base chain if absent, so bridged sandbox↔sandbox and egress traffic traverses
// our chain. Idempotent: an existing jump to userChain is a no-op. Re-runnable
// (see Manager.ReassertChain) because a dockerd restart can flush/reorder
// FORWARD and drop the jump.
//
// NOTE: same offline-coverage caveat as EnsureUserChain.
func (b *netlinkBackend) EnsureForwardJump(userChain string) error {
	tbl, _, err := lookupTableChain("filter", userChain)
	if err != nil {
		return err
	}
	if userChain == "" {
		return fmt.Errorf("ensure forward jump: empty chain name")
	}
	fwd := &nftables.Chain{Name: "FORWARD", Table: tbl}
	conn, err := b.newConn()
	if err != nil {
		return err
	}
	rules, err := conn.GetRules(tbl, fwd)
	if err != nil {
		return fmt.Errorf("nft get FORWARD rules: %w", err)
	}
	for _, r := range rules {
		for _, e := range r.Exprs {
			if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictJump && v.Chain == userChain {
				return nil
			}
		}
	}
	// Counter before verdict mirrors iptables-nft's rule shape (see translator).
	conn.InsertRule(&nftables.Rule{
		Table: tbl,
		Chain: fwd,
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictJump, Chain: userChain},
		},
	})
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nft insert FORWARD jump to %s: %w", userChain, err)
	}
	return nil
}

func lookupTableChain(table, chain string) (*nftables.Table, *nftables.Chain, error) {
	if table != "filter" {
		return nil, nil, fmt.Errorf("netlink backend: unsupported table %q (want filter)", table)
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: table}
	ch := &nftables.Chain{Name: chain, Table: tbl}
	return tbl, ch, nil
}

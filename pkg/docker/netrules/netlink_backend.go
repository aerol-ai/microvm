//go:build linux

package netrules

import (
	"fmt"
	"syscall"

	"github.com/google/nftables"
)

// nftAPI is the Conn surface netlinkBackend needs. *nftables.Conn satisfies
// it; tests inject a fake so Exists/Insert/Delete are covered without
// CAP_NET_ADMIN or a live nftables socket.
type nftAPI interface {
	GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error)
	InsertRule(r *nftables.Rule) *nftables.Rule
	DelRule(r *nftables.Rule) error
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

func lookupTableChain(table, chain string) (*nftables.Table, *nftables.Chain, error) {
	if table != "filter" {
		return nil, nil, fmt.Errorf("netlink backend: unsupported table %q (want filter)", table)
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: table}
	ch := &nftables.Chain{Name: chain, Table: tbl}
	return tbl, ch, nil
}

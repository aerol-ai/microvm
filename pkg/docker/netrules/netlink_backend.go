//go:build linux

package netrules

import (
	"errors"
	"fmt"
	"sync"
	"syscall"

	"github.com/google/nftables"
)

// netlinkBackend drives DOCKER-USER via google/nftables (netlink), translating
// the Manager's iptables-shaped argv into nft expressions. Rules land in the
// iptables-nft compat filter/DOCKER-USER chain so iptables -L still lists them.
type netlinkBackend struct {
	mu   sync.Mutex
	conn *nftables.Conn
}

// NewNetlinkBackend opens a netlink connection to the host nftables. Callers
// must be on linux; non-linux builds use the stub that always errors.
func NewNetlinkBackend() (RuleBackend, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables conn: %w", err)
	}
	return &netlinkBackend{conn: c}, nil
}

func (b *netlinkBackend) Exists(table, chain string, rulespec ...string) (bool, error) {
	want, err := exprsFromRulespec(rulespec...)
	if err != nil {
		return false, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	tbl, ch, err := b.lookup(table, chain)
	if err != nil {
		return false, err
	}
	rules, err := b.conn.GetRules(tbl, ch)
	if err != nil {
		return false, fmt.Errorf("nft get rules: %w", err)
	}
	for _, r := range rules {
		if exprsEqual(want, r.Exprs) {
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
	b.mu.Lock()
	defer b.mu.Unlock()
	tbl, ch, err := b.lookup(table, chain)
	if err != nil {
		return err
	}
	rule := &nftables.Rule{Table: tbl, Chain: ch, Exprs: exprs}
	// Manager always Inserts at position 1 (top). nftables InsertRule without
	// Position inserts at the beginning of the chain — same semantics.
	if pos > 1 {
		rules, gerr := b.conn.GetRules(tbl, ch)
		if gerr != nil {
			return fmt.Errorf("nft get rules for insert pos: %w", gerr)
		}
		idx := pos - 1
		if idx < len(rules) {
			rule.Position = rules[idx].Handle
		}
	}
	b.conn.InsertRule(rule)
	if err := b.conn.Flush(); err != nil {
		return fmt.Errorf("nft insert: %w", err)
	}
	return nil
}

func (b *netlinkBackend) Delete(table, chain string, rulespec ...string) error {
	want, err := exprsFromRulespec(rulespec...)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	tbl, ch, err := b.lookup(table, chain)
	if err != nil {
		return err
	}
	rules, err := b.conn.GetRules(tbl, ch)
	if err != nil {
		return fmt.Errorf("nft get rules: %w", err)
	}
	for _, r := range rules {
		if !exprsEqual(want, r.Exprs) {
			continue
		}
		if err := b.conn.DelRule(r); err != nil {
			return fmt.Errorf("nft del rule: %w", err)
		}
		if err := b.conn.Flush(); err != nil {
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

func (b *netlinkBackend) lookup(table, chain string) (*nftables.Table, *nftables.Chain, error) {
	if table != "filter" {
		return nil, nil, fmt.Errorf("netlink backend: unsupported table %q (want filter)", table)
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: table}
	ch := &nftables.Chain{Name: chain, Table: tbl}
	return tbl, ch, nil
}

func isNetlinkNotExist(err error) bool {
	return errors.Is(err, syscall.ENOENT) ||
		(err != nil && (containsFold(err.Error(), "no such file") ||
			containsFold(err.Error(), "no such file or directory")))
}

func containsFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if equalFoldASCII(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

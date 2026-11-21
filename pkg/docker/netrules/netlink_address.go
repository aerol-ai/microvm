//go:build linux

package netrules

import (
	"errors"
	"fmt"
	"github.com/google/nftables"
	"net"

	"github.com/google/nftables/expr"
)

// ClearAddressRules implements addressRuleClearer: one listing per chain,
// every rule keyed by ip deleted in one transaction, redone from a fresh
// listing if a rule left a chain in between.
func (b *netlinkBackend) ClearAddressRules(chains []string, ip string) error {
	var err error
	for range batchAttempts {
		if err = b.clearAddressOnce(chains, ip); !errors.Is(err, errBatchStale) {
			return err
		}
	}
	return err
}

func (b *netlinkBackend) clearAddressOnce(chains []string, ip string) error {
	var del []*nftables.Rule
	for _, chain := range chains {
		tbl, ch, err := lookupTableChain("filter", chain)
		if err != nil {
			return err
		}
		lc, err := b.newConn()
		if err != nil {
			return err
		}
		rules, err := lc.GetRules(tbl, ch)
		if err != nil {
			if isNetlinkNotExist(err) {
				continue
			}
			return fmt.Errorf("nft get %s rules: %w", chain, err)
		}
		for _, r := range rules {
			if ruleKeyedBy(r.Exprs, ip) {
				del = append(del, r)
			}
		}
	}
	return b.deleteRules(del)
}

// deleteRules deletes rules in transactions of at most netlinkChunk rules
// (one netlink message carries a few hundred; an address with a big
// policy has more). A rule gone since it was listed is errBatchStale, for
// the caller's retry from a fresh listing.
func (b *netlinkBackend) deleteRules(rules []*nftables.Rule) error {
	for start := 0; start < len(rules); start += netlinkChunk {
		conn, err := b.newConn()
		if err != nil {
			return err
		}
		for _, r := range rules[start:min(start+netlinkChunk, len(rules))] {
			if err := conn.DelRule(r); err != nil {
				return fmt.Errorf("nft del rule: %w", err)
			}
		}
		if err := conn.Flush(); err != nil {
			if isNetlinkNotExist(err) {
				return fmt.Errorf("%w: nft flush del: %v", errBatchStale, err)
			}
			return fmt.Errorf("nft flush del: %w", err)
		}
	}
	return nil
}

// netlinkChunk is how many rule changes one transaction carries.
const netlinkChunk = 128

// ruleKeyedBy reports whether a rule is keyed by ip: its source is ip (a
// /32), or it has no source and its destination is ip. A subnet source or
// destination (the floor, the node guard) is never an address's.
func ruleKeyedBy(exprs []expr.Any, ip string) bool {
	src, hasSrc := ruleHostAt(exprs, 12)
	if hasSrc {
		return src == ip
	}
	dst, hasDst := ruleHostAt(exprs, 16)
	return hasDst && dst == ip
}

// ruleHostAt finds the rule's match on the IPv4 header field at offset (12
// source, 16 destination): present reports a match on it at all, host is
// the address when it is a /32 match ("" for a subnet).
func ruleHostAt(exprs []expr.Any, offset uint32) (host string, present bool) {
	for i, e := range exprs {
		p, ok := e.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseNetworkHeader || p.Offset != offset || p.Len != 4 {
			continue
		}
		if i+1 < len(exprs) {
			if c, ok := exprs[i+1].(*expr.Cmp); ok && c.Op == expr.CmpOpEq && len(c.Data) == 4 {
				return net.IP(c.Data).String(), true
			}
		}
		return "", true
	}
	return "", false
}

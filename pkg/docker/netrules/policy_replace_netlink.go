//go:build linux

package netrules

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
)

// ClearCommented implements commentClearer: one listing per chain, every
// rule keyed by ip that carries the comment deleted (deleteRules).
func (b *netlinkBackend) ClearCommented(chains []string, ip, comment string) error {
	var err error
	for range batchAttempts {
		if err = b.clearCommentedOnce(chains, ip, comment); !errors.Is(err, errBatchStale) {
			return err
		}
	}
	return err
}

func (b *netlinkBackend) clearCommentedOnce(chains []string, ip, comment string) error {
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
			if ruleKeyedBy(r.Exprs, ip) && ruleHasComment(r.Exprs, comment) {
				del = append(del, r)
			}
		}
	}
	return b.deleteRules(del)
}

// ruleHasComment reports whether a rule carries the xt comment match.
func ruleHasComment(exprs []expr.Any, comment string) bool {
	for _, e := range exprs {
		m, ok := e.(*expr.Match)
		if !ok || m.Name != "comment" {
			continue
		}
		if c, ok := m.Info.(*xt.Comment); ok && string(*c) == comment {
			return true
		}
	}
	return false
}

// ReplaceBlock implements policyWriter, from one listing of chain. The
// address's rules with comment that are exactly specs, in order, stay as
// they are. Otherwise the new rules go in first and the old ones go after,
// each by its handle: so the address is never without a policy. The new
// rules go in bottom first, each right below the rule above pos (or at the
// top), netlinkChunk to a transaction with ctx checked before each: a
// write cut short leaves the last part of the new policy (its catch-all
// DROP first) above the whole old one, never something wider than both.
// A rule gone since the listing (another writer's change at pos) is
// errBatchStale; the retry lists again, and counts what this call already
// wrote as old.
func (b *netlinkBackend) ReplaceBlock(ctx context.Context, chain string, pos int, ip, comment string, specs [][]string) error {
	var err error
	for range batchAttempts {
		if err = b.replaceBlockOnce(ctx, chain, pos, ip, comment, specs); !errors.Is(err, errBatchStale) {
			return err
		}
	}
	return err
}

func (b *netlinkBackend) replaceBlockOnce(ctx context.Context, chain string, pos int, ip, comment string, specs [][]string) error {
	exprs := make([][]expr.Any, len(specs))
	for i, spec := range specs {
		e, err := exprsFromRulespec(spec...)
		if err != nil {
			return err
		}
		exprs[i] = e
	}
	tbl, ch, err := lookupTableChain("filter", chain)
	if err != nil {
		return err
	}
	conn, err := b.newConn()
	if err != nil {
		return err
	}
	rules, err := conn.GetRules(tbl, ch)
	if err != nil {
		return fmt.Errorf("nft get %s rules: %w", chain, err)
	}
	var old []*nftables.Rule
	for _, r := range rules {
		if ruleKeyedBy(r.Exprs, ip) && ruleHasComment(r.Exprs, comment) {
			old = append(old, r)
		}
	}
	if len(old) == len(exprs) && slices.EqualFunc(old, exprs, func(r *nftables.Rule, e []expr.Any) bool {
		return exprsEqualIgnoringCounters(e, r.Exprs)
	}) {
		return nil
	}
	var above *nftables.Rule
	if pos > 1 && len(rules) > 0 {
		above = rules[min(pos-2, len(rules)-1)]
	}
	n := 0
	for i := len(exprs) - 1; i >= 0; i-- {
		if n == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		r := &nftables.Rule{Table: tbl, Chain: ch, Exprs: exprs[i]}
		if above != nil {
			r.Position = above.Handle
			conn.AddRule(r)
		} else {
			conn.InsertRule(r)
		}
		if n++; n == netlinkChunk || i == 0 {
			if err := conn.Flush(); err != nil {
				if isNetlinkNotExist(err) {
					return fmt.Errorf("%w: nft insert into %s: %v", errBatchStale, chain, err)
				}
				return fmt.Errorf("nft insert %d rules into %s: %w", len(specs), chain, err)
			}
			n = 0
		}
	}
	return b.deleteRules(old)
}

// HasJump implements jumpBackend.
func (b *netlinkBackend) HasJump(parent, child string) (bool, error) {
	rules, err := b.jumpRules(parent, child)
	return len(rules) > 0, err
}

// DeleteJump implements jumpBackend: every rule of parent that jumps to
// child goes. None is no error.
func (b *netlinkBackend) DeleteJump(parent, child string) error {
	rules, err := b.jumpRules(parent, child)
	if err != nil {
		return err
	}
	if err := b.deleteRules(rules); err != nil {
		return fmt.Errorf("delete %s jump to %s: %w", parent, child, err)
	}
	return nil
}

// jumpRules lists parent's rules that jump to child (a bare jump is no
// rulespec the translator renders, so it goes by the verdict); a parent
// that does not exist has none.
func (b *netlinkBackend) jumpRules(parent, child string) ([]*nftables.Rule, error) {
	tbl, pch, err := lookupTableChain("filter", parent)
	if err != nil {
		return nil, err
	}
	conn, err := b.newConn()
	if err != nil {
		return nil, err
	}
	rules, err := conn.GetRules(tbl, pch)
	if err != nil {
		if isNetlinkNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("nft get %s rules: %w", parent, err)
	}
	var out []*nftables.Rule
	for _, r := range rules {
		for _, e := range r.Exprs {
			if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictJump && v.Chain == child {
				out = append(out, r)
				break
			}
		}
	}
	return out, nil
}

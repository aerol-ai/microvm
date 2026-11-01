//go:build linux

package netrules

import (
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/google/nftables"
)

var _ batchBackend = (*netlinkBackend)(nil)

// batchAttempts bounds the re-listings after a commit that hit a rule gone
// since its listing (another IP's writer changed the chain in between). An
// nft batch is atomic, so such a commit applied nothing, and a fresh listing
// is the whole retry.
const batchAttempts = 3

// errBatchStale marks a commit that failed only because a rule it named
// (a delete target, an insert position) left the chain after the listing.
var errBatchStale = errors.New("netrules: chain changed under the batch")

// chainListing holds one listing per chain for a batch. The chains are
// read concurrently, each on its own connection: a listing is the whole
// cost of a batch on a busy node (every other sandbox's rules are in it),
// and two of them side by side cost one.
type chainListing struct {
	rules  map[string][]*nftables.Rule
	chains map[string]*nftables.Chain
}

func chainKey(table, chain string) string { return table + "|" + chain }

// listChains reads every chain the refs name, once each.
func (b *netlinkBackend) listChains(refs []RuleRef) (*chainListing, error) {
	type job struct {
		key   string
		tbl   *nftables.Table
		ch    *nftables.Chain
		rules []*nftables.Rule
		err   error
	}
	var jobs []*job
	seen := map[string]bool{}
	for _, ref := range refs {
		k := chainKey(ref.Table, ref.Chain)
		if seen[k] {
			continue
		}
		seen[k] = true
		tbl, ch, err := lookupTableChain(ref.Table, ref.Chain)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, &job{key: k, tbl: tbl, ch: ch})
	}
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := b.newConn()
			if err != nil {
				j.err = err
				return
			}
			if j.rules, j.err = conn.GetRules(j.tbl, j.ch); j.err != nil {
				j.err = fmt.Errorf("nft get rules: %w", j.err)
			}
		}()
	}
	wg.Wait()
	l := &chainListing{rules: make(map[string][]*nftables.Rule, len(jobs)), chains: make(map[string]*nftables.Chain, len(jobs))}
	for _, j := range jobs {
		if j.err != nil {
			return nil, j.err
		}
		l.rules[j.key], l.chains[j.key] = j.rules, j.ch
	}
	return l, nil
}

// DeleteAll implements batchBackend.
func (b *netlinkBackend) DeleteAll(refs ...RuleRef) error {
	var err error
	for range batchAttempts {
		if err = b.deleteAllOnce(refs); !errors.Is(err, errBatchStale) {
			return err
		}
	}
	return err
}

func (b *netlinkBackend) deleteAllOnce(refs []RuleRef) error {
	l, err := b.listChains(refs)
	if err != nil {
		return err
	}
	conn, err := b.newConn()
	if err != nil {
		return err
	}
	type handle struct {
		chain string
		h     uint64
	}
	picked := map[handle]bool{}
	n := 0
	for _, ref := range refs {
		want, err := exprsFromRulespec(ref.Spec...)
		if err != nil {
			return err
		}
		for _, r := range l.rules[chainKey(ref.Table, ref.Chain)] {
			k := handle{chainKey(ref.Table, ref.Chain), r.Handle}
			if picked[k] || !exprsEqualIgnoringCounters(want, r.Exprs) {
				continue
			}
			picked[k] = true
			if err := conn.DelRule(r); err != nil {
				return fmt.Errorf("nft del rule: %w", err)
			}
			n++
		}
	}
	if n == 0 {
		return nil
	}
	if err := conn.Flush(); err != nil {
		if isNetlinkNotExist(err) {
			return fmt.Errorf("%w: nft flush del: %v", errBatchStale, err)
		}
		return fmt.Errorf("nft flush del: %w", err)
	}
	return nil
}

// EnsureAll implements batchBackend.
func (b *netlinkBackend) EnsureAll(ins ...RuleInsert) ([]bool, error) {
	var (
		inserted []bool
		err      error
	)
	for range batchAttempts {
		if inserted, err = b.ensureAllOnce(ins); !errors.Is(err, errBatchStale) {
			return inserted, err
		}
	}
	return nil, err
}

func (b *netlinkBackend) ensureAllOnce(ins []RuleInsert) ([]bool, error) {
	refs := make([]RuleRef, len(ins))
	chains := map[string]bool{}
	for i, in := range ins {
		k := chainKey(in.Table, in.Chain)
		if chains[k] {
			return nil, fmt.Errorf("netlink backend: two inserts into %s in one batch", k)
		}
		chains[k] = true
		refs[i] = in.RuleRef
	}
	l, err := b.listChains(refs)
	if err != nil {
		return nil, err
	}
	conn, err := b.newConn()
	if err != nil {
		return nil, err
	}
	inserted := make([]bool, len(ins))
	n := 0
	for i, in := range ins {
		exprs, err := exprsFromRulespec(in.Spec...)
		if err != nil {
			return nil, err
		}
		k := chainKey(in.Table, in.Chain)
		ch, rules := l.chains[k], l.rules[k]
		if slices.ContainsFunc(rules, func(r *nftables.Rule) bool { return exprsEqualIgnoringCounters(exprs, r.Exprs) }) {
			continue
		}
		// The Insert contract: position 1 is the top; a later position
		// goes before the rule now at that index; past the end appends.
		rule := &nftables.Rule{Table: ch.Table, Chain: ch, Exprs: exprs}
		switch idx := in.Pos - 1; {
		case in.Pos <= 1:
			conn.InsertRule(rule)
		case idx >= len(rules):
			conn.AddRule(rule)
		default:
			rule.Position = rules[idx].Handle
			conn.InsertRule(rule)
		}
		inserted[i] = true
		n++
	}
	if n == 0 {
		return inserted, nil
	}
	if err := conn.Flush(); err != nil {
		if isNetlinkNotExist(err) {
			return nil, fmt.Errorf("%w: nft insert: %v", errBatchStale, err)
		}
		return nil, fmt.Errorf("nft insert: %w", err)
	}
	return inserted, nil
}

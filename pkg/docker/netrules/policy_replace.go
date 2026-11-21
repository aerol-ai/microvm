package netrules

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// ReplaceEgressPolicy makes ip's egress policy exactly allow and deny (the
// root helper's, privilege mode split; PR 5 review). ApplyEgressPolicy
// adds the rules it is given to whatever the address has, so lists sent
// one after another pile up; here the policy replaces whatever the address
// has, an earlier helper process's rules included. The rules and their
// order are ApplyEgressPolicy's.
//
// A policy already in place (a reapply at start or by reconcile, the
// routine calls) writes nothing. A change never leaves the address without
// a policy, on either backend (ReplaceBlock): netlink writes the new rules
// above the old ones, bottom first, then removes the old ones by handle;
// exec swaps them in one iptables-restore transaction. The caller's
// context stops a write before it starts a step, never between removing
// the old policy and writing the new one. A fresh address (a create) costs
// one listing and at most one transaction per chain.
func (m *Manager) ReplaceEgressPolicy(ctx context.Context, ip string, allow, deny []string) error {
	if !m.Enabled() || strings.TrimSpace(ip) == "" {
		return nil
	}
	pw, ok := m.ipt.(policyWriter)
	if !ok {
		return fmt.Errorf("netrules: backend %T cannot replace a policy", m.ipt)
	}
	unlock := m.lockIP(ip)
	defer unlock()
	allow, deny = normalizeLists(allow, deny)
	fwd, input := policySpecs(ip, allow, deny)
	if err := pw.ReplaceBlock(ctx, m.filterChain(), m.topPos(), ip, egressPolicyComment, fwd); err != nil {
		return fmt.Errorf("egress policy: %w", err)
	}
	if err := m.ensureInputChain(); err != nil {
		return err
	}
	// Position 2: below the established-return rule.
	if err := pw.ReplaceBlock(ctx, ChainAerolvmInput, 2, ip, egressPolicyComment, input); err != nil {
		return fmt.Errorf("egress policy, host input: %w", err)
	}
	return nil
}

// ClearEgressPolicyOf removes every egress policy rule ip has, whatever
// lists made them.
func (m *Manager) ClearEgressPolicyOf(ip string) error {
	if !m.Enabled() || strings.TrimSpace(ip) == "" {
		return nil
	}
	cc, ok := m.ipt.(commentClearer)
	if !ok {
		return fmt.Errorf("netrules: backend %T cannot list a chain to clear a policy", m.ipt)
	}
	unlock := m.lockIP(ip)
	defer unlock()
	return m.clearPolicyLocked(cc, ip)
}

func (m *Manager) clearPolicyLocked(cc commentClearer, ip string) error {
	chains := []string{m.filterChain()}
	if m.ensureInputChain() == nil {
		chains = append(chains, ChainAerolvmInput)
	}
	if err := cc.ClearCommented(chains, ip, egressPolicyComment); err != nil {
		return fmt.Errorf("netrules: clear the egress policy of %s: %w", ip, err)
	}
	return nil
}

// commentClearer removes the rules keyed by an address that carry one
// comment, from one listing per chain.
type commentClearer interface {
	ClearCommented(chains []string, ip, comment string) error
}

// policyWriter replaces one address's rules with a comment in a chain
// with specs at pos, in place when they already are (ReplaceBlock).
type policyWriter interface {
	ReplaceBlock(ctx context.Context, chain string, pos int, ip, comment string, specs [][]string) error
}

// policySpecs are ApplyEgressPolicy's rules for ip, top first, in the
// order it leaves them (it inserts each at the top, so a list ends up
// last entry first): the user chain's, and AEROLVM-INPUT's for an
// allowlist.
func policySpecs(ip string, allow, deny []string) (fwd, input [][]string) {
	allow, deny = slices.Clone(allow), slices.Clone(deny)
	slices.Reverse(allow)
	slices.Reverse(deny)
	rule := func(cidr, verdict string) []string {
		if cidr == "" {
			return []string{"-s", ip, "-m", "comment", "--comment", egressPolicyComment, "-j", verdict}
		}
		return []string{"-s", ip, "-d", cidr, "-m", "comment", "--comment", egressPolicyComment, "-j", verdict}
	}
	for _, c := range allow {
		fwd = append(fwd, rule(c, "ACCEPT"))
	}
	switch {
	case len(allow) > 0 && len(deny) > 0:
		// Allow wins; default accept, so no catch-all and no host rules.
		for _, c := range deny {
			fwd = append(fwd, rule(c, "DROP"))
		}
	case len(allow) > 0:
		fwd = append(fwd, rule("", "DROP"))
		for _, c := range allow {
			input = append(input, inputPolicyReturnSpec(ip, c))
		}
		input = append(input, inputPolicyDropSpec(ip))
	default:
		for _, c := range deny {
			fwd = append(fwd, rule(c, "DROP"))
		}
	}
	return fwd, input
}

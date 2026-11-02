package netrules

import "fmt"

// RuleRef names one rule: its table, its chain and its iptables-shaped spec.
type RuleRef struct {
	Table string
	Chain string
	Spec  []string
}

// RuleInsert is a rule to ensure at an iptables-style position: 1 is the
// top, a position past the last rule appends (the RuleBackend.Insert
// contract).
type RuleInsert struct {
	RuleRef
	Pos int
}

// batchBackend is a RuleBackend that changes several chains in one
// transaction from one listing per chain. The netlink backend has it; the
// exec backend (one iptables process per rule) doesn't, and keeps the
// per-rule path.
//
// Why it exists: the per-rule path reads a whole chain for every Exists,
// every positioned Insert and every Delete, and a delete-until-gone sweep is
// three of them per rule. Lifting a sandbox's block-all (the last step of a
// hostname-filtered create, plans/egress-domain-filtering.md §8.2) was six
// listings of AEROLVM-USER/DOCKER-USER and AEROLVM-INPUT plus two commits,
// so its cost grew with every other restricted sandbox on the node: 8.4 ms
// at 200 neighbours, 42 ms at 1,000, in the kerneltest benchmark. The batch
// makes it two listings and one commit, and makes the pair atomic.
type batchBackend interface {
	// DeleteAll removes every rule matching any ref (duplicates included,
	// as the delete-until-gone sweep does) in one transaction, from one
	// listing per chain. Rules already gone are not an error.
	DeleteAll(refs ...RuleRef) error
	// EnsureAll inserts each missing rule at its position in one
	// transaction, from one listing per chain, and reports which it
	// inserted. At most one insert per chain: positions come from the
	// listing.
	EnsureAll(ins ...RuleInsert) (inserted []bool, err error)
}

// egressDropSpec is the per-IP block-all DROP in the user chain.
func egressDropSpec(ip string) []string { return []string{"-s", ip, "-j", "DROP"} }

// blockAllEgressBatch is BlockAllEgressReport on a batch backend: the user
// chain DROP and its host-INPUT drop go in together or not at all. Callers
// hold the IP lock.
func (m *Manager) blockAllEgressBatch(b batchBackend, ip string) (bool, error) {
	drop := RuleInsert{RuleRef: RuleRef{Table: "filter", Chain: m.filterChain(), Spec: egressDropSpec(ip)}, Pos: m.topPos()}
	if err := m.ensureInputChain(); err != nil {
		// As on the per-rule path: the forward DROP still goes in, so the
		// sandbox is shut even when host protection can't be bootstrapped,
		// and the error says the block is incomplete.
		ins, derr := b.EnsureAll(drop)
		if derr != nil {
			return false, fmt.Errorf("insert egress rule: %w", derr)
		}
		return ins[0], err
	}
	// Position 2: below the established-return rule, so replies to
	// host-initiated connections (sandboxd→toolboxd) still flow.
	input := RuleInsert{RuleRef: RuleRef{Table: "filter", Chain: ChainAerolvmInput, Spec: inputBlockSpec(ip)}, Pos: 2}
	ins, err := b.EnsureAll(drop, input)
	if err != nil {
		return false, fmt.Errorf("insert egress rules: %w", err)
	}
	return ins[0] || ins[1], nil
}

// clearBlockAllEgressBatch is ClearBlockAllEgress on a batch backend.
// Callers hold the IP lock.
func (m *Manager) clearBlockAllEgressBatch(b batchBackend, ip string) error {
	refs := []RuleRef{{Table: "filter", Chain: m.filterChain(), Spec: egressDropSpec(ip)}}
	// A chain that can't be bootstrapped holds no rule (deleteInputRules).
	if m.ensureInputChain() == nil {
		refs = append(refs, RuleRef{Table: "filter", Chain: ChainAerolvmInput, Spec: inputBlockSpec(ip)})
	}
	if err := b.DeleteAll(refs...); err != nil {
		return fmt.Errorf("delete egress rules: %w", err)
	}
	return nil
}

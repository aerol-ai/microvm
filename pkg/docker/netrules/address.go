package netrules

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Rules belong to an address, not to a sandbox: every per-address rule
// (block-all, ingress block, hold, a CIDR policy's accepts and drops, their
// AEROLVM-INPUT counterparts) is keyed by the sandbox's IP, and whoever holds
// that IP next would inherit what is left. So when an address's holder goes
// (a pause container, a container with its own address, a parked warm slot)
// everything keyed by the address goes with it, whether or not the caller
// still knows which rules a create installed: a create that died, an orphan
// with no row, a policy the row no longer names.

// addressRuleClearer is a backend that can list chains and remove every
// per-address rule of one address from them in one go.
type addressRuleClearer interface {
	// ClearAddressRules removes, from each chain of the filter table, every
	// rule whose source is ip, and every rule with no source whose
	// destination is ip (an ingress block). A rule with another source that
	// names ip as its destination is another sandbox's (its allowlist) and
	// stays. A chain that isn't there holds none.
	ClearAddressRules(chains []string, ip string) error
}

// ClearAddress removes every per-address rule keyed by ip from this
// manager's user chain and AEROLVM-INPUT. Call it when the address's
// holder is gone or about to be, never while a sandbox still uses the
// address. A backend that can't list a chain clears the specs the manager
// knows without their lists: block-all, the ingress block and the hold.
func (m *Manager) ClearAddress(ip string) error {
	if !m.Enabled() || strings.TrimSpace(ip) == "" {
		return nil
	}
	if a, err := netip.ParseAddr(ip); err != nil || !a.Is4() {
		return fmt.Errorf("netrules: clear address %q: not an IPv4 address", ip)
	}
	unlock := m.lockIP(ip)
	defer unlock()
	// The block sets hold the address's block-all (blockset.go): it goes
	// too, release first.
	if b := m.setsFor(ip); b != nil {
		if err := m.forgetElements(b, ip); err != nil {
			return fmt.Errorf("netrules: clear address %s: %w", ip, err)
		}
	}
	chains := []string{m.filterChain()}
	if m.ensureInputChain() == nil {
		chains = append(chains, ChainAerolvmInput)
	}
	if c, ok := m.ipt.(addressRuleClearer); ok {
		if err := c.ClearAddressRules(chains, ip); err != nil {
			return fmt.Errorf("netrules: clear address %s: %w", ip, err)
		}
		return nil
	}
	return errors.Join(
		m.deleteUntilGone("filter", m.filterChain(), egressDropSpec(ip)...),
		m.deleteInputRules(inputBlockSpec(ip)),
		m.deleteUntilGone("filter", m.filterChain(), "-d", ip, "-j", "DROP"),
		m.deletePolicyRule(holdSpec(ip)...),
	)
}

// addressRuleKeyed reports whether an iptables-shaped rule (the tokens
// after "-A CHAIN") is keyed by ip: its source is ip, or it has no source
// and its destination is ip.
func addressRuleKeyed(tokens []string, ip string) bool {
	var src, dst string
	for i := 0; i+1 < len(tokens); i++ {
		switch tokens[i] {
		case "-s", "--source":
			src = tokens[i+1]
		case "-d", "--destination":
			dst = tokens[i+1]
		}
	}
	host := func(v string) string { return strings.TrimSuffix(v, "/32") }
	if src != "" {
		return host(src) == ip
	}
	return dst != "" && host(dst) == ip
}

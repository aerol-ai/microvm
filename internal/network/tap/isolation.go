package tap

import (
	"fmt"
	"net/netip"
)

// IsolationChain holds the drops that keep Firecracker guests apart from
// each other and from every other sandbox on the node
// (`iptables -t mangle -S AEROLVM-FC-ISOLATE`).
const IsolationChain = "AEROLVM-FC-ISOLATE"

// isolationTable is where the chain lives. mangle, not filter: the mangle
// FORWARD hook runs before the filter one, and an ACCEPT in a filter chain
// ends only the filter traversal. Every per-sandbox and per-bridge ACCEPT on
// the node is in filter (DOCKER-USER, AEROLVM-USER's whole-bridge accepts,
// AEROLVM-FC's, an egress allowlist's), so none of them can let a packet
// past these drops, whatever order dockerd or anything else leaves FORWARD
// in. Nothing on the node manages mangle FORWARD, so the jump never has to
// fight for position.
const isolationTable = "mangle"

// isolationComment tags the chain's rules for operators.
const isolationComment = "aerolvm-fc-isolate"

// IsolationBackend is the iptables subset EnsureIsolation drives;
// *iptables.IPTables (coreos/go-iptables) satisfies it, as it does
// NATBackend.
type IsolationBackend interface {
	NATBackend
	Insert(table, chain string, pos int, rulespec ...string) error
	ChainExists(table, chain string) (bool, error)
	NewChain(table, chain string) error
}

// isolationRules are the chain's rules for the TAP subnet:
//
//   - nothing from one guest reaches another, in any protocol (ICMP
//     included) or state. A guest's traffic to its own gateway (the host end
//     of its /30, also in the subnet) is INPUT, not FORWARD, so DNS, the
//     egress gateway and the replies to the host's toolbox connections are
//     untouched;
//   - nothing forwarded opens anything into a guest: a container or gVisor
//     sandbox on a bridge, another host, the internet. Only replies to a
//     guest's own connections come in. The host reaches the agent from
//     sandboxd itself (OUTPUT), so the toolbox, SSH and exposed ports keep
//     working.
//
// Only -s/-d, conntrack and comment matches, which every iptables flavour
// the daemon supports can express.
func isolationRules(subnet string) [][]string {
	return [][]string{
		{"-s", subnet, "-d", subnet, "-m", "comment", "--comment", isolationComment, "-j", "DROP"},
		{"-d", subnet, "-m", "conntrack", "!", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", isolationComment, "-j", "DROP"},
	}
}

// isolationJump sends every forwarded packet through the chain.
var isolationJump = []string{"-j", IsolationChain}

// EnsureIsolation installs the guest isolation for the TAP subnet.
// Idempotent and cheap (one check per rule): it runs at every daemon start
// and on the chain reassert tick, which puts it back after anything flushes
// the mangle table. It runs whether or not per-guest network rules are
// enabled, as the masquerade does: isolation is not an egress policy a guest
// opts into.
func EnsureIsolation(be IsolationBackend, baseCIDR string) error {
	p, err := netip.ParsePrefix(baseCIDR)
	if err != nil || !p.Addr().Is4() {
		return fmt.Errorf("tap isolation: %q is not an IPv4 CIDR", baseCIDR)
	}
	subnet := p.Masked().String()
	exists, err := be.ChainExists(isolationTable, IsolationChain)
	if err != nil {
		return fmt.Errorf("tap isolation: check chain: %w", err)
	}
	if !exists {
		if err := be.NewChain(isolationTable, IsolationChain); err != nil {
			return fmt.Errorf("tap isolation: create chain: %w", err)
		}
	}
	// The rules go in before the jump, so a fresh jump never points at a
	// chain that drops less than it should.
	for _, spec := range isolationRules(subnet) {
		ok, err := be.Exists(isolationTable, IsolationChain, spec...)
		if err != nil {
			return fmt.Errorf("tap isolation: check rule: %w", err)
		}
		if ok {
			continue
		}
		if err := be.Append(isolationTable, IsolationChain, spec...); err != nil {
			return fmt.Errorf("tap isolation: add rule: %w", err)
		}
	}
	ok, err := be.Exists(isolationTable, "FORWARD", isolationJump...)
	if err != nil {
		return fmt.Errorf("tap isolation: check FORWARD jump: %w", err)
	}
	if ok {
		return nil
	}
	if err := be.Insert(isolationTable, "FORWARD", 1, isolationJump...); err != nil {
		return fmt.Errorf("tap isolation: add FORWARD jump: %w", err)
	}
	return nil
}

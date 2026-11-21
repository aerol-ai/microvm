package rootpolicy

import (
	"net/netip"
	"strings"
)

// The rules for the root helper's firewall calls (plans/security-gaps-m1-m4.md
// §3.3, "Firewall"; M1 PR 5). The agent sends typed values: an address, the
// CIDRs of a sandbox's egress policy, the node ports sandboxes may reach on
// the node, the node's extra deny floor. The helper renders every rule
// itself; nothing the agent sends becomes rule text without passing one of
// these checks first and being written back in its canonical form.

// Bounds on one request: root renders a rule per entry, so a request must
// not be able to grow the ruleset without end. Each is far above what the
// API lets a sandbox's policy, or the operator's file, hold.
const (
	MaxRuleCIDRs  = 4096
	MaxNodePorts  = 256
	MaxFloorCIDRs = 4096
	// MaxPolicyCIDRs bounds one address's egress policy, both lists
	// together (PR 5 review): the helper replaces a policy, so this is
	// also what one address can hold.
	MaxPolicyCIDRs = 1024
)

// TooManyPolicyCIDRs is the refusal of a policy past MaxPolicyCIDRs.
func TooManyPolicyCIDRs(n int) error {
	return violate(RuleCIDR, "%d CIDRs in one policy; at most %d", n, MaxPolicyCIDRs)
}

// CheckRuleCIDRs parses a sandbox's egress policy list: each entry a
// network or an address ("10.0.0.0/8", "1.2.3.4"), with no space, zone or
// anything else around it; hostnames never reach the host firewall (the
// egress gateway takes those). It answers each in canonical form (masked,
// with its prefix length), which is what the helper puts in a rule, so an
// entry written oddly can never become something else in the rule.
func CheckRuleCIDRs(list []string) ([]string, error) {
	if len(list) > MaxRuleCIDRs {
		return nil, violate(RuleCIDR, "%d CIDRs; at most %d", len(list), MaxRuleCIDRs)
	}
	out := make([]string, 0, len(list))
	for _, s := range list {
		p, err := parseCIDR(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p.String())
	}
	return out, nil
}

// CheckFloorCIDRs parses the node's extra deny floor: IPv4 or IPv6 networks
// or addresses, canonical as above. The helper adds the floor no setting
// can take off (the cloud metadata endpoints) itself, whatever this holds.
func CheckFloorCIDRs(list []string) ([]netip.Prefix, error) {
	if len(list) > MaxFloorCIDRs {
		return nil, violate(RuleCIDR, "%d floor CIDRs; at most %d", len(list), MaxFloorCIDRs)
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		p, err := parseCIDR(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func parseCIDR(s string) (netip.Prefix, error) {
	if s == "" || strings.TrimSpace(s) != s {
		return netip.Prefix{}, violate(RuleCIDR, "CIDR %q: want a bare network or address", s)
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, violate(RuleCIDR, "CIDR %q: %v", s, err)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, violate(RuleCIDR, "CIDR %q: want a network or an address with no zone", s)
	}
	if a.Is4In6() {
		return netip.Prefix{}, violate(RuleCIDR, "CIDR %q: an IPv4-mapped IPv6 address", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// NodePort is one entry of the node guard's allow list: a port on the node
// that sandboxes may reach, on every node address or one.
type NodePort struct {
	Proto string
	Port  uint32
	// Dst is "" (every address) or one IPv4 address.
	Dst string
}

// CheckNodePorts checks the node guard's allow list: tcp or udp, a port
// from 1 to 65535, and no address or a plain IPv4 one. The guard's
// default-deny of the node from the sandboxes' range is the helper's; this
// list only opens holes in it.
func CheckNodePorts(list []NodePort) ([]NodePort, error) {
	if len(list) > MaxNodePorts {
		return nil, violate(RuleNodePort, "%d node ports; at most %d", len(list), MaxNodePorts)
	}
	out := make([]NodePort, 0, len(list))
	for _, p := range list {
		if p.Proto != "tcp" && p.Proto != "udp" {
			return nil, violate(RuleNodePort, "node port protocol %q: want tcp or udp", p.Proto)
		}
		if p.Port == 0 || p.Port > 65535 {
			return nil, violate(RuleNodePort, "node port %d: want 1 to 65535", p.Port)
		}
		if p.Dst != "" {
			a, err := netip.ParseAddr(p.Dst)
			if err != nil || !a.Is4() || a.Zone() != "" || a.String() != p.Dst {
				return nil, violate(RuleNodePort, "node port address %q: want a plain IPv4 address", p.Dst)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// CheckNodePortsWithin: each entry of list is one of bound, the root
// helper's own list, or a narrowing of one (the same port and protocol,
// on one address where bound allows every address).
func CheckNodePortsWithin(list, bound []NodePort) error {
	for _, p := range list {
		covered := false
		for _, b := range bound {
			if b.Proto == p.Proto && b.Port == p.Port && (b.Dst == "" || b.Dst == p.Dst) {
				covered = true
				break
			}
		}
		if !covered {
			return violate(RuleNodePort, "node port %s/%d is not one the root helper's settings allow sandboxes to reach", p.Proto, p.Port)
		}
	}
	return nil
}

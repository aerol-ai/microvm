// Package ipv6fence keeps IPv6 off the node's sandbox networks.
//
// Sandboxes are IPv4-only, and every host rule that keeps one sandbox off
// another and off the node is IPv4: netrules' floor and node chains, the
// Firecracker isolation chain, the egress gateway. With IPv6 up inside two
// sandboxes on one bridge, one reached the other's listener at
// fe80::…%eth0 while the IPv4 address timed out (cluster-3-mixed-routing,
// containerd, pooled netns). The runtimes now start every sandbox with IPv6
// off (hostnet.SandboxIPv6Sysctls, netns.Host.Realize, the Firecracker
// ipv6.disable=1 boot argument, the TAP's host end). This package is the
// second layer, which holds whatever a sandbox does to its own stack: a
// gVisor sentry or a VM guest has a network stack of its own, and root in a
// guest owns its kernel.
//
// Two nftables tables named TableName, both independent of iptables,
// netrules and the operator's file:
//
//   - bridge family: drop every IPv6 frame (ethertype 0x86dd) forwarded
//     between two ports of a sandbox bridge, delivered from one to the host,
//     or sent by the host into one. The bridge family sees bridged frames
//     whether or not br_netfilter hands them to ip6tables.
//   - ip6 family: drop IPv6 into the host (input), through it (forward) and
//     out of it (output) on the sandbox bridges and the Firecracker TAPs
//     (routed, not bridged).
//
// Each Apply replaces both tables in one netlink transaction, so there is
// never a moment with half a fence; Check reads them back so a supervisor
// can put back a fence a firewall reload or a flush took away.
package ipv6fence

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// TableName names the fence's table in the bridge and ip6 families
// (`nft list table bridge aerolvm_ipv6`, `nft list table ip6 aerolvm_ipv6`).
const TableName = "aerolvm_ipv6"

// Families of the two tables.
const (
	FamilyBridge = "bridge"
	FamilyIP6    = "ip6"
)

// Chains of each table; each is a base chain on the hook of the same name.
const (
	ChainForward = "forward"
	ChainInput   = "input"
	ChainOutput  = "output"
)

// What a rule matches on: the bridge a frame came in on or goes out on
// (bridge family), or the interface a packet came in on or goes out on
// (ip6 family).
const (
	MatchInBridge  = "ibrname"
	MatchOutBridge = "obrname"
	MatchIn        = "iifname"
	MatchOut       = "oifname"
)

// ErrUnsupported means this platform has no nftables.
var ErrUnsupported = errors.New("ipv6 fence: nftables is not available on this platform")

// Spec is what the fence covers.
type Spec struct {
	// Bridges are the Linux bridges sandboxes are attached to: the
	// containerd CNI bridge, the docker sandbox network's bridge.
	Bridges []string
	// Links are routed sandbox interfaces on the host. A trailing "*"
	// matches every interface with that prefix, as in nft: "fctap*" is
	// every Firecracker TAP, including ones created after the fence.
	Links []string
}

// Merge returns the union of s and o (not normalized).
func (s Spec) Merge(o Spec) Spec {
	return Spec{
		Bridges: append(append([]string(nil), s.Bridges...), o.Bridges...),
		Links:   append(append([]string(nil), s.Links...), o.Links...),
	}
}

// Normalize validates every name and returns the spec sorted and without
// duplicates, so two equal specs have equal keys.
func (s Spec) Normalize() (Spec, error) {
	var out Spec
	var err error
	if out.Bridges, err = normalizeNames(s.Bridges, false); err != nil {
		return Spec{}, err
	}
	if out.Links, err = normalizeNames(s.Links, true); err != nil {
		return Spec{}, err
	}
	return out, nil
}

// Empty reports whether the spec covers nothing.
func (s Spec) Empty() bool { return len(s.Bridges) == 0 && len(s.Links) == 0 }

// Key is a stable string for a normalized spec, for logs and change checks.
func (s Spec) Key() string {
	return "bridges=" + strings.Join(s.Bridges, ",") + ";links=" + strings.Join(s.Links, ",")
}

func normalizeNames(names []string, allowPrefix bool) ([]string, error) {
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if !validName(n, allowPrefix) {
			return nil, fmt.Errorf("ipv6 fence: invalid interface name %q", n)
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// validName is a Linux interface name (1..15 bytes, no '/', whitespace or
// NUL), or with allowPrefix a non-empty prefix of one followed by '*'.
func validName(n string, allowPrefix bool) bool {
	if allowPrefix && strings.HasSuffix(n, "*") {
		n = strings.TrimSuffix(n, "*")
		if len(n) > 14 {
			return false
		}
	}
	if n == "" || len(n) > 15 || n == "." || n == ".." {
		return false
	}
	return !strings.ContainsAny(n, "/*\x00 \t\n")
}

// Rule is one drop of the fence, in the form the backend and the tests
// share.
type Rule struct {
	Family string
	Chain  string
	Match  string
	// Name is a bridge or interface name; a trailing "*" is a prefix.
	Name string
}

// Comment is what the rule carries in the kernel: the operator sees it in
// `nft list ruleset`, and Check compares it to find a rule that went
// missing or changed.
func (r Rule) Comment() string {
	return fmt.Sprintf("aerolvm ipv6 fence: %s/%s %s %s", r.Family, r.Chain, r.Match, r.Name)
}

// Plan is every rule the fence needs for spec (normalized first), grouped by
// table and chain in a fixed order.
func Plan(spec Spec) []Rule {
	var out []Rule
	for _, b := range spec.Bridges {
		out = append(out,
			Rule{FamilyBridge, ChainForward, MatchInBridge, b},
			Rule{FamilyBridge, ChainInput, MatchInBridge, b},
			Rule{FamilyBridge, ChainOutput, MatchOutBridge, b},
		)
	}
	for _, n := range append(append([]string(nil), spec.Bridges...), spec.Links...) {
		out = append(out,
			Rule{FamilyIP6, ChainInput, MatchIn, n},
			Rule{FamilyIP6, ChainForward, MatchIn, n},
			Rule{FamilyIP6, ChainForward, MatchOut, n},
			Rule{FamilyIP6, ChainOutput, MatchOut, n},
		)
	}
	order := func(r Rule) int {
		fam := 0
		if r.Family == FamilyIP6 {
			fam = 1
		}
		return fam*10 + slices.Index(chainOrder, r.Chain)
	}
	slices.SortStableFunc(out, func(a, b Rule) int { return order(a) - order(b) })
	return out
}

// chainOrder is the order the chains are created and checked in.
var chainOrder = []string{ChainForward, ChainInput, ChainOutput}

// Backend installs and reads back the fence.
type Backend interface {
	// Apply replaces both tables with exactly rules, in one transaction.
	Apply(rules []Rule) error
	// Check reports whether the kernel holds exactly rules: both tables,
	// every chain on its hook and priority, and each chain's rules in
	// order. A chain something else inserted a rule into reads as missing,
	// since an accept above a drop would let traffic past it.
	Check(rules []Rule) (bool, error)
}

// ChainRules groups rules by family/chain in plan order: what each chain
// must hold, including empty chains.
func ChainRules(rules []Rule) map[string][]Rule {
	out := map[string][]Rule{}
	for _, fam := range []string{FamilyBridge, FamilyIP6} {
		for _, ch := range chainOrder {
			out[fam+"/"+ch] = nil
		}
	}
	for _, r := range rules {
		k := r.Family + "/" + r.Chain
		out[k] = append(out[k], r)
	}
	return out
}

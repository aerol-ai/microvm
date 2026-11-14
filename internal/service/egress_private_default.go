package service

import (
	"net/netip"
	"slices"

	"github.com/aerol-ai/microvm/internal/runtime/resolvconf"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// privateDefaultDeny are the ranges SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT keeps
// a sandbox with no egress policy away from (plans/agent-sandbox-feature-
// parity.md T4): RFC 1918 and IPv4 link-local, as agent-sandbox's default
// NetworkPolicy does. Its IPv6 ranges (fc00::/7, fe80::/10) need no entry:
// container, gVisor and Firecracker sandboxes have no IPv6 at all (the IPv6
// fence), and the deny list is enforced by IPv4 host rules.
var privateDefaultDeny = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}

// privateDefault is the flag's state: the ranges it denies and the allow
// entries that keep the sandbox's DNS working (nil until the flag is turned
// on).
type privateDefault struct {
	deny  []string
	allow []string
}

// EnableBlockPrivateByDefault turns on SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT.
// The deny list is privateDefaultDeny plus the node's extra private ranges
// (SB_EGRESS_PRIVATE_DEFAULT_CIDRS: on Kubernetes the cluster's pod, Service
// and node ranges, C24), so a bank opens one of them with an egress profile
// like any private range. Only their IPv4 entries go in: the list is
// enforced by IPv4 host rules, and these sandboxes have no IPv6.
//
// It reads the resolvers sandboxes are handed (the same files the node guard
// reads) once, here at boot, so a create never touches the disk: a resolver
// inside a blocked range, such as an AWS VPC resolver at 10.x.0.2,
// 172.31.0.2 or a cluster's DNS Service address, gets a /32 allow entry, or
// every default sandbox would lose DNS. A resolver change on the host is
// picked up at the next restart.
func (s *Service) EnableBlockPrivateByDefault() {
	deny := slices.Clone(privateDefaultDeny)
	for _, p := range s.cfg.EgressPrivateDefaultCIDRs {
		if p.Addr().Is4() && !slices.Contains(deny, p.String()) {
			deny = append(deny, p.String())
		}
	}
	var resolvers []netip.Addr
	for _, path := range nodeGuardResolvConfs {
		resolvers = append(resolvers, resolvconf.Nameservers(path)...)
	}
	allow := privateDefaultResolverAllow(resolvers, deny)
	s.blockPrivateDefault.Store(&privateDefault{deny: deny, allow: allow})
	if s.logger != nil {
		s.logger.Info("egress: sandboxes with no egress policy get the private-range deny list (SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT)",
			"deny", deny, "dns_resolvers_allowed", allow)
	}
}

// privateDefaultResolverAllow returns a /32 allow entry for each IPv4
// resolver inside a range of deny, sorted and deduplicated. A resolver on
// the deny floor (GCP's resolver is the metadata address 169.254.169.254) is
// left out: the floor drops it whatever any list says, so naming it would
// only make GET show an allow that is not real.
func privateDefaultResolverAllow(resolvers []netip.Addr, deny []string) []string {
	floor := egresspolicy.WithFixedFloor(nil)
	var out []string
	for _, ip := range resolvers {
		ip = ip.Unmap()
		if !ip.Is4() || ip.IsLoopback() {
			continue
		}
		if slices.ContainsFunc(floor, func(p netip.Prefix) bool { return p.Contains(ip) }) {
			continue
		}
		if !slices.ContainsFunc(deny, func(c string) bool { return netip.MustParsePrefix(c).Contains(ip) }) {
			continue
		}
		out = append(out, netip.PrefixFrom(ip, 32).String())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// applyPrivateDefault writes the private-range default into a create that
// still says nothing about egress after the operator's default, so the
// stored spec carries it: GET shows it, failover replays it, and turning the
// flag off later never opens a running sandbox. A create that sets any
// policy keeps exactly what it set: the flag is a default, not a floor (the
// operator file's deny_cidrs and SB_EGRESS_DENY_FLOOR_CIDRS are the floor).
// WASM and isolate filter in their own mediators, which treat the extra
// private ranges as private too (egresspolicy.SetRanges), and are left
// alone; an omitted runtime resolves to the node's container default, which
// the flag covers.
func (s *Service) applyPrivateDefault(req *models.CreateSandboxRequest) {
	pd := s.blockPrivateDefault.Load()
	if pd == nil || hasEgressFields(req) || models.RuntimeMediatesEgress(req.Runtime) {
		return
	}
	req.NetworkDenyOut = slices.Clone(pd.deny)
	req.NetworkAllowOut = slices.Clone(pd.allow)
}

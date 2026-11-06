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

// privateDefault is the flag's state: the allow entries that keep the
// sandbox's DNS working (nil until the flag is turned on).
type privateDefault struct {
	allow []string
}

// EnableBlockPrivateByDefault turns on SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT.
// It reads the resolvers sandboxes are handed (the same files the node guard
// reads) once, here at boot, so a create never touches the disk: a resolver
// inside a blocked range, such as an AWS VPC resolver at 10.x.0.2 or
// 172.31.0.2, gets a /32 allow entry, or every default sandbox would lose DNS.
// A resolver change on the host is picked up at the next restart.
func (s *Service) EnableBlockPrivateByDefault() {
	var resolvers []netip.Addr
	for _, path := range nodeGuardResolvConfs {
		resolvers = append(resolvers, resolvconf.Nameservers(path)...)
	}
	allow := privateDefaultResolverAllow(resolvers)
	s.blockPrivateDefault.Store(&privateDefault{allow: allow})
	if s.logger != nil {
		s.logger.Info("egress: sandboxes with no egress policy get the private-range deny list (SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT)",
			"deny", privateDefaultDeny, "dns_resolvers_allowed", allow)
	}
}

// privateDefaultResolverAllow returns a /32 allow entry for each IPv4
// resolver inside a range the default denies, sorted and deduplicated. A
// resolver on a metadata address (GCP's 169.254.169.254) is left out: the
// deny floor drops it whatever any list says, so naming it would only make
// GET show an allow that is not real.
func privateDefaultResolverAllow(resolvers []netip.Addr) []string {
	floor := egresspolicy.WithMetadataFloor(nil)
	var out []string
	for _, ip := range resolvers {
		ip = ip.Unmap()
		if !ip.Is4() || ip.IsLoopback() {
			continue
		}
		if slices.ContainsFunc(floor, func(p netip.Prefix) bool { return p.Contains(ip) }) {
			continue
		}
		if !slices.ContainsFunc(privateDefaultDeny, func(c string) bool { return netip.MustParsePrefix(c).Contains(ip) }) {
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
// operator file's deny_cidrs is the floor). WASM and isolate filter in their
// own mediators and are left alone; an omitted runtime resolves to the
// node's container default, which the flag covers.
func (s *Service) applyPrivateDefault(req *models.CreateSandboxRequest) {
	pd := s.blockPrivateDefault.Load()
	if pd == nil || hasEgressFields(req) || models.RuntimeMediatesEgress(req.Runtime) {
		return
	}
	req.NetworkDenyOut = slices.Clone(privateDefaultDeny)
	req.NetworkAllowOut = slices.Clone(pd.allow)
}

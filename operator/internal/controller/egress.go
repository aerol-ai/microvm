package controller

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Keeping sandboxes away from the cluster itself (C24, Phase 2;
// plans/kubernetes-v2-architecture.md §8.4). Sandbox traffic leaves with the
// worker pod's address, so the cluster cannot tell a sandbox from AerolVM.
// The operator reads the cluster's own addresses and gives every new worker
// pod two lists, on top of what the chart's values already set:
//
//   - the deny floor (SB_EGRESS_DENY_FLOOR_CIDRS): the Kubernetes API
//     server, its Service address and the addresses behind it. No egress
//     profile can open these.
//   - the private default (SB_EGRESS_PRIVATE_DEFAULT_CIDRS): the pod and
//     Service ranges. Closed by default, like the private ranges; a profile
//     may open one on purpose.
//
// What the API does not say (node ranges; pod ranges under a CNI that takes
// addresses from the VPC, which the private ranges already cover) stays in
// the chart's worker.egressPrivateRanges. A worker gets the lists when it
// is made: the API server's Service address never changes, and a worker
// made later gets any new endpoint address.

// clusterAddresses is what the operator found; empty lists when it could
// read nothing.
type clusterAddresses struct {
	DenyFloor []string
	Private   []string
}

const (
	envDenyFloor = "SB_EGRESS_DENY_FLOOR_CIDRS"
	envPrivate   = "SB_EGRESS_PRIVATE_DEFAULT_CIDRS"
)

// readClusterAddresses reads them. reader goes past the manager's cache,
// which holds only AerolVM's two namespaces (the API server's objects live
// in default); nodes is the cache, which holds every Node already, so a
// worker made in a 2,000-node cluster does not list them all from the API
// server. A read that fails leaves its part out, logged; the in-pod
// private-range block and the egress NetworkPolicy still stand.
func readClusterAddresses(ctx context.Context, reader, nodes client.Reader) clusterAddresses {
	var out clusterAddresses
	logger := log.FromContext(ctx)
	var svc corev1.Service
	if err := reader.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubernetes"}, &svc); err == nil {
		for _, ip := range append([]string{svc.Spec.ClusterIP}, svc.Spec.ClusterIPs...) {
			out.DenyFloor = appendAddr(out.DenyFloor, ip)
		}
	} else {
		logger.Info("cannot read the API server's Service; sandboxes still cannot reach private ranges", "error", err.Error())
	}
	var slice discoveryv1.EndpointSlice
	if err := reader.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubernetes"}, &slice); err == nil {
		for _, ep := range slice.Endpoints {
			for _, a := range ep.Addresses {
				out.DenyFloor = appendAddr(out.DenyFloor, a)
			}
		}
	} else {
		logger.Info("cannot read the API server's addresses; sandboxes still cannot reach private ranges", "error", err.Error())
	}
	var nodeList corev1.NodeList
	if err := nodes.List(ctx, &nodeList); err != nil {
		logger.Info("cannot list the Nodes; their pod ranges stay to the chart's values", "error", err.Error())
	} else {
		for _, n := range nodeList.Items {
			for _, cidr := range append([]string{n.Spec.PodCIDR}, n.Spec.PodCIDRs...) {
				out.Private = appendAddr(out.Private, cidr)
			}
		}
	}
	// ServiceCIDR is GA from Kubernetes 1.33; older clusters do not serve
	// it, and their Service range stays in the chart's values.
	var cidrs networkingv1.ServiceCIDRList
	if err := reader.List(ctx, &cidrs); err != nil {
		logger.Info("cannot list the ServiceCIDRs (Kubernetes 1.33 and later); the Service range stays to the chart's values", "error", err.Error())
	} else {
		for _, sc := range cidrs.Items {
			for _, cidr := range sc.Spec.CIDRs {
				out.Private = appendAddr(out.Private, cidr)
			}
		}
	}
	return out
}

// appendAddr adds an address or CIDR once, in CIDR form, skipping what does
// not parse. A bare address is one host.
func appendAddr(list []string, s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "None") {
		return list
	}
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return list
		}
		p = p.Masked()
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return list
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if slices.Contains(list, p.String()) {
		return list
	}
	return append(list, p.String())
}

// sandboxdPrivateDefault is what sandboxd's private-range default already
// keeps sandboxes from (internal/service's privateDefaultDeny). A found range
// inside one adds nothing for a sandbox with no egress policy, and a
// sandbox with one does not use the default at all; so such a range is left
// out. Pod ranges are almost always in here, which keeps a 2,000-node
// cluster from putting 2,000 entries in every sandbox's rules.
var sandboxdPrivateDefault = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
}

// defaultSandboxSubnet is containerd's bridge range when the chart sets no
// SB_CONTAINERD_BRIDGE_SUBNET.
const defaultSandboxSubnet = "10.88.0.0/16"

// setEgressRanges adds the found lists to each container that reads them
// (the agent's firewall and the egress gateway), keeping what the chart's
// values set, within the rules sandboxd checks at start
// (internal/config's validateEgressRanges), so a found range can never stop
// a worker from starting:
//
//   - either list needs SB_ENABLE_NETWORK_RULES=true;
//   - the private list needs SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT=true;
//   - a range that overlaps the sandboxes' own subnet is left out: inside
//     the pod those addresses are sandboxes.
func setEgressRanges(spec *corev1.PodSpec, a clusterAddresses) {
	i := containerIndex(spec.Containers, AgentContainer)
	if i < 0 {
		return
	}
	// The last value wins, as Kubernetes resolves a repeated name.
	agentEnv := func(name string) string {
		v := ""
		for _, e := range spec.Containers[i].Env {
			if e.Name == name {
				v = e.Value
			}
		}
		return v
	}
	if agentEnv("SB_ENABLE_NETWORK_RULES") != "true" {
		return
	}
	subnet, err := netip.ParsePrefix(cmpOr(agentEnv("SB_CONTAINERD_BRIDGE_SUBNET"), defaultSandboxSubnet))
	if err != nil {
		subnet = netip.MustParsePrefix(defaultSandboxSubnet)
	}
	floor := aggregate(keep(a.DenyFloor, func(p netip.Prefix) bool { return !p.Overlaps(subnet) }))
	var private []string
	if agentEnv("SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT") == "true" {
		private = aggregate(keep(a.Private, func(p netip.Prefix) bool {
			return !p.Overlaps(subnet) && !slices.ContainsFunc(sandboxdPrivateDefault, func(d netip.Prefix) bool {
				return d.Addr().BitLen() == p.Addr().BitLen() && d.Bits() <= p.Bits() && d.Contains(p.Addr())
			})
		}))
	}
	for i := range spec.Containers {
		c := &spec.Containers[i]
		if c.Name != AgentContainer && c.Name != "egress" {
			continue
		}
		for _, kv := range []struct {
			name string
			add  []string
		}{{envDenyFloor, floor}, {envPrivate, private}} {
			if len(kv.add) == 0 {
				continue
			}
			var list []string
			at := -1
			for j, e := range c.Env {
				if e.Name == kv.name {
					at = j
					for _, s := range strings.Split(e.Value, ",") {
						list = appendAddr(list, s)
					}
				}
			}
			for _, s := range kv.add {
				list = appendAddr(list, s)
			}
			v := corev1.EnvVar{Name: kv.name, Value: strings.Join(list, ",")}
			if at >= 0 {
				c.Env[at] = v
			} else {
				c.Env = append(c.Env, v)
			}
		}
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// keep returns the CIDRs in list that parse and pass ok.
func keep(list []string, ok func(netip.Prefix) bool) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil && ok(p.Masked()) {
			out = append(out, p.Masked())
		}
	}
	return out
}

// aggregate merges prefixes into the fewest that cover exactly the same
// addresses: one inside another goes, and two halves of the same parent
// become the parent, until nothing changes.
func aggregate(in []netip.Prefix) []string {
	set := slices.Clone(in)
	for changed := true; changed; {
		changed = false
		slices.SortFunc(set, func(x, y netip.Prefix) int {
			if c := x.Addr().Compare(y.Addr()); c != 0 {
				return c
			}
			return x.Bits() - y.Bits()
		})
		var out []netip.Prefix
		for _, p := range set {
			if n := len(out); n > 0 {
				last := out[n-1]
				switch {
				case last.Overlaps(p) && last.Bits() <= p.Bits():
					changed = true
					continue // inside the previous one
				case last.Bits() == p.Bits() && last.Bits() > 0:
					parent, _ := last.Addr().Prefix(last.Bits() - 1)
					if q, _ := p.Addr().Prefix(p.Bits() - 1); parent == q {
						out[n-1] = parent
						changed = true
						continue
					}
				}
			}
			out = append(out, p)
		}
		set = out
	}
	strs := make([]string, len(set))
	for i, p := range set {
		strs[i] = p.String()
	}
	return strs
}

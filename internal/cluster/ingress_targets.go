package cluster

import (
	"net"
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// hasIngressRole reports whether a gossiped role string lets the node serve
// public ingress traffic. Mirrors the role parsing in placement.go but is
// scoped to "is this a target users point DNS at?" — workers without an
// ingress role are excluded (they have no Caddy listener bound to the public
// interface). Empty role is treated as mixed for rolling-upgrade
// compatibility with pre-role builds, same as CanOwnSandboxRole.
func hasIngressRole(role string) bool {
	trimmed := strings.TrimSpace(role)
	if trimmed == "" {
		return true
	}
	for _, raw := range strings.Split(trimmed, ",") {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case config.NodeRoleIngress, config.NodeRoleMixed:
			return true
		}
	}
	return false
}

// aggregateIngressTargets walks Members and returns the deduped, sorted
// public-address set as an IngressTarget. Only live ingress-capable nodes
// contribute. Hostnames vs IPs are partitioned via net.ParseIP. Empty
// PublicHost values are skipped so a mixed cluster where some nodes haven't
// been upgraded yet still yields a usable target from the upgraded ones.
// Stable output ordering keeps the HTTP/SDK response byte-identical across
// calls when membership is unchanged — easier to cache and assert against.
func aggregateIngressTargets(members []Member) models.IngressTarget {
	hostnameSet := make(map[string]struct{})
	ipSet := make(map[string]struct{})
	for _, m := range members {
		if !m.Alive || !hasIngressRole(m.Role) {
			continue
		}
		host := strings.TrimSpace(m.PublicHost)
		if host == "" {
			continue
		}
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if net.ParseIP(host) != nil {
			ipSet[host] = struct{}{}
		} else {
			hostnameSet[host] = struct{}{}
		}
	}
	hostnames := make([]string, 0, len(hostnameSet))
	for h := range hostnameSet {
		hostnames = append(hostnames, h)
	}
	sort.Strings(hostnames)
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	target := models.IngressTarget{IPs: ips}
	// When multiple ingress nodes gossip distinct hostnames we still only
	// surface one in the CNAME field — the SDK / API contract is "one
	// hostname target." Pick the lexically-first so the output is
	// deterministic; clusters with multiple ingress hostnames are unusual
	// (each operator hostname normally resolves to the same load balancer)
	// and the IPs list is the right answer when they truly differ.
	if len(hostnames) > 0 {
		target.Hostname = hostnames[0]
	}
	switch {
	case target.Hostname != "" && len(target.IPs) > 0:
		target.Source = models.IngressTargetSourceMixed
	case target.Hostname != "":
		target.Source = models.IngressTargetSourceHostname
	case len(target.IPs) > 0:
		target.Source = models.IngressTargetSourceIPs
	default:
		target.Source = models.IngressTargetSourceUnknown
	}
	return target
}

// composeIngressTarget is the single-publicHost short-cut Noop uses. Keeps
// the shape consistent with aggregateIngressTargets so the service layer
// doesn't branch on cluster vs single-node.
func composeIngressTarget(publicHosts []string) models.IngressTarget {
	members := make([]Member, 0, len(publicHosts))
	for _, h := range publicHosts {
		members = append(members, Member{Alive: true, Role: config.NodeRoleMixed, PublicHost: h})
	}
	return aggregateIngressTargets(members)
}

package service

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/egress"
)

// nodeControlEndpoints lists the AerolVM control endpoints the node-wide
// guard drops for sandboxes (plans/egress-domain-filtering.md §5.10 PC-2):
// every live member's API, Raft and cluster-internal endpoints as gossiped,
// its SSH-gateway and gossip ports by this node's config (the fleet runs one
// config), and the same ports on this host's own addresses. Ingress 80/443
// are never listed, so agents keep using the load-balanced URL. Only IPv4
// literals: members advertise addresses, and the guard is IPv4 like the
// rest of the table.
func (s *Service) nodeControlEndpoints() []netip.AddrPort {
	ports := s.controlPorts()
	seen := map[netip.AddrPort]struct{}{}
	add := func(ap netip.AddrPort) {
		if !ap.Addr().Is4() || ap.Port() == 0 || ap.Port() == 80 || ap.Port() == 443 {
			return
		}
		seen[ap] = struct{}{}
	}
	addHost := func(ip netip.Addr) {
		for _, p := range ports {
			add(netip.AddrPortFrom(ip, p))
		}
	}
	for _, ip := range localIPv4s() {
		addHost(ip)
	}
	if c := s.Cluster(); c != nil {
		members := c.LocalMembers()
		if len(members) == 0 {
			members = c.Members()
		}
		for _, m := range members {
			if !m.Alive {
				continue
			}
			for _, raw := range []string{m.APIURL, m.InternalURL, m.RaftAddr} {
				if ap, ok := endpointOf(raw); ok {
					add(ap)
					addHost(ap.Addr())
				}
			}
		}
	}
	out := make([]netip.AddrPort, 0, len(seen))
	for ap := range seen {
		out = append(out, ap)
	}
	return egress.SortedControl(out)
}

// controlPorts are this node's control listeners: API, SSH gateway, Raft,
// gossip and the cluster mTLS listener.
func (s *Service) controlPorts() []uint16 {
	var out []uint16
	if s.cfg.APIPort > 0 && s.cfg.APIPort < 65536 {
		out = append(out, uint16(s.cfg.APIPort))
	}
	for _, addr := range []string{s.cfg.SSHListenAddr, s.cfg.RaftBindAddr, s.cfg.GossipBindAddr, s.cfg.ClusterInternalListenAddr} {
		if _, p, err := net.SplitHostPort(strings.TrimSpace(addr)); err == nil {
			if n, err := strconv.ParseUint(p, 10, 16); err == nil && n > 0 {
				out = append(out, uint16(n))
			}
		}
	}
	return out
}

// endpointOf parses host:port or a URL with an explicit IPv4 host and port.
func endpointOf(raw string) (netip.AddrPort, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.AddrPort{}, false
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return netip.AddrPort{}, false
		}
		raw = u.Host
	}
	ap, err := netip.ParseAddrPort(raw)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// localIPv4s is this host's non-loopback IPv4 addresses (a seam for tests).
var localIPv4s = func() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				ip = ip.Unmap()
				if ip.Is4() && !ip.IsLoopback() {
					out = append(out, ip)
				}
			}
		}
	}
	return out
}

// syncNodeControl pushes the control endpoints when they changed (cluster
// membership moves, or a gateway restart cleared the record). The guard is
// part of the operator file (§5.10): without one, or with
// node_control_port_guard: false, the list is empty, which clears anything
// pushed earlier.
func (s *Service) syncNodeControl(ctx context.Context) {
	if !s.egressEnabled() || !s.egressReady.Load() {
		return
	}
	op := s.egressOperator()
	var eps []netip.AddrPort
	if op != nil && op.NodeControlPortGuard() {
		eps = s.nodeControlEndpoints()
	}
	key := controlKey(eps)
	if prev := s.egressControlPushed.Load(); prev != nil && *prev == key {
		return
	}
	if op == nil && s.egressControlPushed.Load() == nil {
		// Never pushed and no operator file: leave the gateway's set as the
		// kernel has it (empty on a fresh table).
		return
	}
	if err := s.egressGateway().SetNodeControl(ctx, eps); err != nil {
		s.logger.Warn("egress: node control-port guard not updated", "endpoints", len(eps), "error", err)
		return
	}
	s.egressControlPushed.Store(&key)
}

func controlKey(eps []netip.AddrPort) string {
	var b strings.Builder
	for _, ep := range eps {
		b.WriteString(ep.String())
		b.WriteByte(',')
	}
	return b.String()
}

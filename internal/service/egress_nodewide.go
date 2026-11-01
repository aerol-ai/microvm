package service

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
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

// controlPorts are this node's control listeners and host services
// (config.NodeControlPorts, which SB_SANDBOX_NODE_PORTS_ALLOW may never
// open, so the two guards agree).
func (s *Service) controlPorts() []uint16 {
	return s.cfg.NodeControlPorts()
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

// nodeControl is the guard as the gateway gets it: the Firecracker TAP
// pool guarded whole on the control ports, and every endpoint the pool
// doesn't cover one by one. Each guest's TAP holds a host address (the
// host side of its /30), so listing local addresses alone made the list
// change with every guest started or stopped, and each change rewrote the
// whole node_control set in the gateway: a commit that held the node's
// nftables commit mutex for 25 ms on a 48-vCPU host, which any create's
// lift landing then waited out (egress.ControlPool).
func (s *Service) nodeControl(all []netip.AddrPort) egress.NodeControl {
	nc := egress.NodeControl{Endpoints: all}
	subnet, on := s.tapPool()
	if !on || !subnet.Addr().Is4() {
		return nc
	}
	var ports []uint16
	for _, p := range s.controlPorts() {
		if p != 0 && p != 80 && p != 443 && !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return nc
	}
	pool := subnet.Masked()
	nc.Pools = []egress.ControlPool{{Prefix: pool, Ports: ports}}
	nc.Endpoints = nil
	for _, ep := range all {
		if !pool.Contains(ep.Addr()) || !slices.Contains(ports, ep.Port()) {
			nc.Endpoints = append(nc.Endpoints, ep)
		}
	}
	return nc
}

// syncNodeControl pushes the control endpoints when they changed (cluster
// membership moves, or a gateway restart cleared the record). The guard is
// on without an operator file; only node_control_port_guard: false in one
// turns it off, which clears anything pushed earlier.
//
// A gateway from before control pools answers the pools op "unknown op";
// it then gets every address listed, as before, and the list it got is
// what the next tick compares against.
func (s *Service) syncNodeControl(ctx context.Context) {
	if !s.egressEnabled() || !s.egressReady.Load() {
		return
	}
	op := s.egressOperator()
	var all []netip.AddrPort
	var nc egress.NodeControl
	if op.NodeControlPortGuard() {
		all = s.nodeControlEndpoints()
		nc = s.nodeControl(all)
	}
	key, listKey := poolsKey(nc), "list|"+controlKey(all)
	if prev := s.egressControlPushed.Load(); prev != nil && (*prev == key || *prev == listKey) {
		return
	}
	gw := s.egressGateway()
	err := gw.SetNodeControlPools(ctx, nc)
	if egress.IsUnknownOp(err) {
		key = listKey
		err = gw.SetNodeControl(ctx, all)
	}
	if err != nil {
		s.logger.Warn("egress: node control-port guard not updated", "endpoints", len(all), "error", err)
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

// poolsKey names a NodeControl push; a list push's key starts "list|", so
// the two never match each other.
func poolsKey(nc egress.NodeControl) string {
	var b strings.Builder
	b.WriteString("pools|")
	b.WriteString(controlKey(nc.Endpoints))
	for _, p := range nc.Pools {
		fmt.Fprintf(&b, "|%s:%v", p.Prefix, p.Ports)
	}
	return b.String()
}

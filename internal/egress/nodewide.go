package egress

import (
	"net/netip"
	"sort"
)

// NodeWide is the node-wide floor and control-port guard (plans/egress-
// domain-filtering.md §5.10 PC-2). Unlike everything else in the table it
// applies to every sandbox on the bridges, in every mode: the elements are
// keyed by bridge subnet, so a gateway-mode, CIDR-policy or no-policy
// sandbox all match. It adds no per-create work.
type NodeWide struct {
	// Subnets are the sandbox bridge subnets (from sandboxd's discovery).
	Subnets []netip.Prefix
	// Floor is the operator's deny_cidrs: always dropped, above every
	// accept.
	Floor []netip.Prefix
	// Control are the AerolVM control endpoints of every cluster member
	// (this node included): API, SSH gateway, cluster mTLS, Raft and gossip.
	// TCP to them is dropped; ingress 80/443 is never listed.
	Control []netip.AddrPort
	// ControlKnown is false until sandboxd has sent the endpoints since the
	// gateway started; until then the kernel set keeps what it had, rather
	// than being emptied while the table outlived the restart.
	ControlKnown bool
}

// elems expands the node-wide rules into set elements.
func (nw NodeWide) elems() (floor, control []Elem) {
	for _, sn := range nw.Subnets {
		if !sn.Addr().Is4() {
			continue
		}
		sn = sn.Masked()
		for _, f := range nw.Floor {
			if f.Addr().Is4() {
				f = f.Masked()
				floor = append(floor, Elem{Src: sn.Addr(), SrcEnd: lastAddr(sn), Dst: f.Addr(), DstEnd: lastAddr(f)})
			}
		}
		for _, c := range nw.Control {
			if c.Addr().Is4() && c.Port() != 0 {
				control = append(control, Elem{Src: sn.Addr(), SrcEnd: lastAddr(sn), Dst: c.Addr().Unmap(), Port: c.Port()})
			}
		}
	}
	return floor, control
}

// SetNodeWide replaces the node-wide sets in one transaction and remembers
// them, so a rebuilt table (CEO D17) gets them back.
func (g *Gateway) SetNodeWide(nw NodeWide) error {
	floor, control := nw.elems()
	sets := map[string][]Elem{SetDenyFloor: floor}
	if nw.ControlKnown {
		sets[SetNodeControl] = control
	}
	if err := g.be.Replace(sets); err != nil {
		return err
	}
	g.nwMu.Lock()
	g.nodeWide = nw
	g.nwMu.Unlock()
	return nil
}

// NodeWideState returns the last applied node-wide rules.
func (g *Gateway) NodeWideState() NodeWide {
	g.nwMu.Lock()
	defer g.nwMu.Unlock()
	return g.nodeWide
}

// reapplyNodeWide puts the remembered node-wide rules back after the layout
// was rebuilt.
func (g *Gateway) reapplyNodeWide() error {
	nw := g.NodeWideState()
	if len(nw.Subnets) == 0 {
		return nil
	}
	return g.SetNodeWide(nw)
}

// SortedControl returns endpoints in a stable order, so callers can tell a
// changed set from a reordered one.
func SortedControl(in []netip.AddrPort) []netip.AddrPort {
	out := append([]netip.AddrPort(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out
}

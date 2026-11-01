package egress

import (
	"net/netip"
	"slices"
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
	// ControlPools are blocks of host addresses guarded whole (ControlPool).
	ControlPools []ControlPool
	// ControlKnown is false until sandboxd has sent the endpoints since the
	// gateway started; until then the kernel set keeps what it had, rather
	// than being emptied while the table outlived the restart.
	ControlKnown bool
}

// ControlPool is a block of host addresses sandboxd hands out one per
// sandbox: the Firecracker TAP pool, where each guest's TAP holds the host
// side of its /30. Listing those addresses one by one made every guest's
// start and stop rewrite node_control, a full replace of the set (25 ms
// holding the node's nftables commit mutex on a 48-vCPU host, behind which
// every create's lift waited), and left a new guest's address unguarded
// until sandboxd's next push. A pool is guarded whole on Ports, held
// addresses or not, from the moment it is set.
//
// On the input chain a destination in the pool is one of the host's own
// TAP addresses, exactly. On the forward chain it is another guest, which
// the TAP isolation (FC-ISOLATE) already keeps every sandbox from opening a
// connection to, so the wider match drops nothing that was open.
type ControlPool struct {
	Prefix netip.Prefix `json:"prefix"`
	Ports  []uint16     `json:"ports"`
}

// NodeControl is what sandboxd sends the control-port guard
// (opNodeCtlPools): endpoints one by one, and pools whole.
type NodeControl struct {
	Endpoints []netip.AddrPort `json:"endpoints"`
	Pools     []ControlPool    `json:"pools,omitempty"`
}

// covers reports whether a pool guards ap: its address in the prefix and
// its port among the pool's.
func (p ControlPool) covers(ap netip.AddrPort) bool {
	return p.Prefix.IsValid() && p.Prefix.Masked().Contains(ap.Addr().Unmap()) && slices.Contains(p.Ports, ap.Port())
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
			// An endpoint a pool covers is left to the pool: an interval
			// set's elements may not overlap, and the kernel refuses an
			// element whose start or end lies inside another, failing the
			// whole transaction.
			if c.Addr().Is4() && c.Port() != 0 && !nw.pooled(c) {
				control = append(control, Elem{Src: sn.Addr(), SrcEnd: lastAddr(sn), Dst: c.Addr().Unmap(), Port: c.Port()})
			}
		}
		for _, p := range nw.ControlPools {
			if !p.Prefix.IsValid() || !p.Prefix.Addr().Is4() {
				continue
			}
			pool := p.Prefix.Masked()
			seen := map[uint16]bool{}
			for _, port := range p.Ports {
				if port == 0 || seen[port] {
					continue
				}
				seen[port] = true
				control = append(control, Elem{Src: sn.Addr(), SrcEnd: lastAddr(sn), Dst: pool.Addr(), DstEnd: lastAddr(pool), Port: port})
			}
		}
	}
	return floor, control
}

// pooled reports whether one of the pools guards ap.
func (nw NodeWide) pooled(ap netip.AddrPort) bool {
	for _, p := range nw.ControlPools {
		if p.covers(ap) {
			return true
		}
	}
	return false
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

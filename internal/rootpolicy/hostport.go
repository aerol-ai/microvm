package rootpolicy

import (
	"fmt"
	"net/netip"
)

// The rules for the root helper's raw-TCP host-port forwarding (M1 PR 5b;
// ingress proxy routing, plans/ingress-proxy-routing.md §3.5). A forward
// takes traffic to one of this node's ports and hands it on in the kernel,
// so what it may take and where it may hand it on is the helper's to
// bound, from its own settings: the host port is one of the node's
// host-port range (never a port the node's own services listen on), and
// each kind of target has its own rule. Whether a sandbox address is
// leased, and whether a peer address is the node's own, are the helper's
// to ask the kernel.

// HostPortBounds are the helper's host-port settings, under sandboxd's
// names: the range raw-TCP exposures are given ports from
// (SB_L4_PORT_RANGE_START, SB_L4_PORT_RANGE_END) and sandboxd's own
// listener that wake and mediated targets are redirected to
// (SB_HOSTPORT_REDIRECT_PORT).
type HostPortBounds struct {
	RangeStart, RangeEnd int
	RedirectPort         int
}

// Check checks the range as sandboxd's config does: unprivileged ports,
// start below end. The redirect port is checked when a forward uses it
// (CheckRedirectTarget), as sandboxd checks it only when routing is on.
func (b HostPortBounds) Check() error {
	if b.RangeStart < 1024 || b.RangeEnd > 65535 || b.RangeStart >= b.RangeEnd {
		return fmt.Errorf("host-port range %d-%d: want 1024 <= start < end <= 65535", b.RangeStart, b.RangeEnd)
	}
	return nil
}

// Size is how many host ports the range holds: the most forwards a node
// can have.
func (b HostPortBounds) Size() int { return b.RangeEnd - b.RangeStart + 1 }

func (b HostPortBounds) inRange(p uint32) bool {
	return int(p) >= b.RangeStart && int(p) <= b.RangeEnd
}

// CheckHostPort: the port taken is in the node's host-port range, so a
// forward never takes a port the node's own services listen on.
func CheckHostPort(b HostPortBounds, hp uint32) (int, error) {
	if !b.inRange(hp) {
		return 0, violate(RuleHostPort, "host port %d is outside the node's host-port range %d-%d", hp, b.RangeStart, b.RangeEnd)
	}
	return int(hp), nil
}

// CheckSandboxTarget: a forward to a sandbox on this node goes to a
// sandbox address in the helper's range (CheckSandboxAddress: not the
// bridge's own address, which is the node's), on any port. The helper
// also asks that its CNI leased the address to a slot.
func CheckSandboxTarget(subnet netip.Prefix, addr string, port uint32) (netip.AddrPort, error) {
	if port == 0 || port > 65535 {
		return netip.AddrPort{}, violate(RuleHostPort, "sandbox target port %d", port)
	}
	a, err := CheckSandboxAddress(subnet, addr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(a, uint16(port)), nil
}

// CheckPeerTarget: a forward to another node (an ingress node's hop to a
// sandbox's owner, masqueraded) goes to another node's host port: a plain
// unicast IPv4 address that is no sandbox's (outside the helper's range)
// and no special address (loopback, link-local, the cloud metadata
// endpoints among them, multicast, broadcast, unspecified), on a port of
// the host-port range. The helper also asks the kernel that the address is
// not one of this node's own.
func CheckPeerTarget(b HostPortBounds, subnet netip.Prefix, addr string, port uint32) (netip.AddrPort, error) {
	a, err := netip.ParseAddr(addr)
	switch {
	case err != nil || !a.Is4() || a.Zone() != "" || a.String() != addr:
		return netip.AddrPort{}, violate(RuleHostPort, "peer address %q: want a plain IPv4 address", addr)
	case a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() ||
		a.IsInterfaceLocalMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return netip.AddrPort{}, violate(RuleHostPort, "peer address %s is not another node's", a)
	case subnet.IsValid() && subnet.Masked().Contains(a):
		return netip.AddrPort{}, violate(RuleHostPort, "peer address %s is in the sandboxes' range %s", a, subnet.Masked())
	case !b.inRange(port):
		return netip.AddrPort{}, violate(RuleHostPort, "peer port %d is outside the host-port range %d-%d", port, b.RangeStart, b.RangeEnd)
	}
	return netip.AddrPortFrom(a, uint16(port)), nil
}

// CheckRedirectTarget: a redirect goes to sandboxd's own listener, the
// port the helper's settings name, and to nothing else on the node.
func CheckRedirectTarget(b HostPortBounds, addr string, port uint32) (int, error) {
	switch {
	case addr != "":
		return 0, violate(RuleHostPort, "a redirect names no address (got %q)", addr)
	case b.RedirectPort <= 0 || b.RedirectPort > 65535 || b.inRange(uint32(b.RedirectPort)):
		return 0, violate(RuleHostPort, "the helper's redirect port %d is not usable (SB_HOSTPORT_REDIRECT_PORT: 1 to 65535, outside the host-port range)", b.RedirectPort)
	case int(port) != b.RedirectPort:
		return 0, violate(RuleHostPort, "redirect port %d: the helper's is %d", port, b.RedirectPort)
	}
	return b.RedirectPort, nil
}

// CheckHostPortCount: a node's whole set of forwards holds at most one
// per port of the range.
func CheckHostPortCount(b HostPortBounds, n int) error {
	if n > b.Size() {
		return violate(RuleHostPort, "%d forwards: the host-port range holds %d", n, b.Size())
	}
	return nil
}

// HostPortListedTwice is the refusal of a set that names hp twice.
func HostPortListedTwice(hp int) error {
	return violate(RuleHostPort, "host port %d listed twice", hp)
}

// PeerIsLocal is the refusal of a peer address the kernel lists as one of
// this node's own: a forward there would reach the node's own services.
func PeerIsLocal(a netip.Addr) error {
	return violate(RuleHostPort, "peer address %s is this node's own", a)
}

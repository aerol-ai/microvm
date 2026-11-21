package rootpolicy

import (
	"net/netip"
	"path"
)

// The rules for the root helper's network calls (plans/security-gaps-m1-m4.md
// §3.3, "Network"): the agent names a sandbox's network namespace by its
// netns-pool name and, on teardown, the address the pool recorded for it.
// The helper builds every path itself from a name these rules pass, and
// touches an address only inside the sandboxes' own range, which comes from
// its own configuration. Whose namespace a name is stays the agent's
// bookkeeping (the netns pool's store rows): the helper keeps no state, so a
// broken agent can still tear down one of its own sandboxes' namespaces,
// which it could already reach (R9). What these rules stop is reaching past
// the sandboxes: a path out of the netns folder, or an address on the host
// side of the bridge.

// NetnsPath is the namespace path for name: <NetnsDir>/<name>, where name
// is a sandbox, slot or warm-park ID (ValidateID's charset). A name with a
// slash, a dot or anything else that could leave the folder is refused.
func NetnsPath(p Policy, name string) (string, error) {
	if err := ValidateID(name); err != nil {
		return "", violate(RuleNetns, "network namespace name: %v", err)
	}
	return path.Join(p.NetnsDir, name), nil
}

// CheckSandboxAddress parses addr as one sandbox's IPv4 address inside
// subnet, the range the helper's own CNI config hands out. The subnet's
// network address, its broadcast address and its first host address (the
// bridge's own, host-local's default gateway) are not a sandbox's, and
// neither is anything outside the range, an IPv6 address, an IPv4-mapped
// one or one with a zone: the helper flushes connection tracking and NAT
// state by this address, so it must name a sandbox and nothing else.
func CheckSandboxAddress(subnet netip.Prefix, addr string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(addr)
	switch {
	case err != nil:
		return netip.Addr{}, violate(RuleAddress, "sandbox address %q: %v", addr, err)
	case !ip.Is4() || ip.Zone() != "":
		return netip.Addr{}, violate(RuleAddress, "sandbox address %q: want a plain IPv4 address", addr)
	case !subnet.IsValid() || !subnet.Addr().Is4():
		return netip.Addr{}, violate(RuleAddress, "no IPv4 sandbox range to check %s against", addr)
	}
	subnet = subnet.Masked()
	if !subnet.Contains(ip) {
		return netip.Addr{}, violate(RuleAddress, "sandbox address %s is outside the sandboxes' range %s", ip, subnet)
	}
	network := subnet.Addr()
	if ip == network || ip == network.Next() || ip == lastAddr(subnet) {
		return netip.Addr{}, violate(RuleAddress, "sandbox address %s is the range's network, bridge or broadcast address", ip)
	}
	return ip, nil
}

// lastAddr is the broadcast address of an IPv4 prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	host := uint32(0xffffffff) >> p.Bits()
	v := (uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

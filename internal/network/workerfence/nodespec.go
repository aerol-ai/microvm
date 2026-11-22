package workerfence

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// NodeInputs is what a node's fence is made from, read by its caller:
// sandboxd in privilege mode single, the root helper in split (M1 PR 9).
type NodeInputs struct {
	// UID is the workers' uid.
	UID int
	// AuditPort is the audit ingest's port on 127.0.0.1, where workers post
	// egress records; 0 for none.
	AuditPort uint16
	// ResolvConf is /etc/resolv.conf: workers resolve the names guests
	// dial at its name servers, on port 53.
	ResolvConf []byte
	// Upstream is the operator's upstream proxy, when the operator file
	// names one.
	Upstream *url.URL
	// Floor is the deny floor every dial guard holds (the operator's
	// deny_cidrs and the metadata endpoints, the node's extra floor, the
	// floor file).
	Floor []netip.Prefix
	// NodePorts are the ports guests may still reach on the node's own
	// addresses.
	NodePorts []uint16
	// Local are the node's own addresses (LocalAddrs).
	Local []netip.Prefix
}

// NodeSpec is the fence for in: what the worker uid may still reach (the
// audit ingest, the name servers, the upstream proxy), and the floor and
// node ports. Guest listeners need no exception: only sandboxd opens
// connections to them, and the fence lets the worker uid answer on those
// (the reply rule).
func NodeSpec(in NodeInputs) Spec {
	spec := Spec{UID: in.UID, NodePorts: in.NodePorts, Floor: in.Floor, Local: in.Local}
	if in.AuditPort > 0 {
		spec.Allow = append(spec.Allow, Allow{Proto: "tcp", Prefix: netip.MustParsePrefix("127.0.0.1/32"), PortLo: in.AuditPort, PortHi: in.AuditPort, Why: "audit ingest"})
	}
	for _, ns := range Nameservers(in.ResolvConf) {
		for _, proto := range []string{"udp", "tcp"} {
			spec.Allow = append(spec.Allow, Allow{Proto: proto, Prefix: netip.PrefixFrom(ns, ns.BitLen()), PortLo: 53, PortHi: 53, Why: "name server"})
		}
	}
	spec.Allow = append(spec.Allow, UpstreamAllows(in.Upstream)...)
	return spec
}

// UpstreamAllows lets the worker uid reach the operator's upstream proxy.
func UpstreamAllows(u *url.URL) []Allow {
	if u == nil {
		return nil
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		port = 80
		if strings.EqualFold(u.Scheme, "https") {
			port = 443
		}
	}
	var out []Allow
	for _, a := range HostAddrs(u.Hostname()) {
		out = append(out, Allow{Proto: "tcp", Prefix: netip.PrefixFrom(a, a.BitLen()), PortLo: uint16(port), PortHi: uint16(port), Why: "upstream proxy"})
	}
	return out
}

// LocalAddrs are the node's own addresses with their prefix lengths, which
// the fence lists itself (with each subnet's broadcast address) on a kernel
// without nft fib. A failed read lists none: the fib rules, where the
// kernel has them, need no list.
func LocalAddrs(read func() ([]net.Addr, error)) []netip.Prefix {
	addrs, err := read()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			ip, ok := netip.AddrFromSlice(n.IP)
			ones, _ := n.Mask.Size()
			if ok {
				ip = ip.Unmap()
				if ip.Is4() && ones > 32 {
					ones -= 96
				}
				out = append(out, netip.PrefixFrom(ip, ones))
			}
		}
	}
	return out
}

package egresspolicy

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The node guard for host-mediated sandboxes (WASM, isolate) and the egress
// gateway's own dials: a sandbox is default-denied from the node it runs
// on. Container and Firecracker sandboxes get the same rule from the host
// firewall (pkg/docker/netrules ChainAerolvmNode); these sandboxes dial
// from processes on the host, where a firewall rule keyed by source
// address cannot tell them from the host itself, so the dial guard holds
// it. Loopback, 0.0.0.0/8 and every address on the node's interfaces are
// refused, except a port the process was told the node serves to its
// sandboxes (SetNodeAllowedPorts) on a non-loopback address.

// DialReasonNode refuses a dial to one of the node's own addresses.
const DialReasonNode = "node"

// NodePortsEnv carries the allowed node ports from sandboxd to the WASM
// worker processes it starts, which run with an allowlisted environment.
const NodePortsEnv = "SB_NODE_GUARD_ALLOWED_PORTS"

// nodeAllowed is this process's allowed node ports; nil allows none, which
// is the posture of any process that was not told otherwise (the egress
// gateway: nothing on the node is a destination for a gateway-mode
// sandbox).
var nodeAllowed atomic.Pointer[[]uint16]

// SetNodeAllowedPorts sets the node ports host-mediated sandboxes in this
// process may still reach on the node's non-loopback addresses.
func SetNodeAllowedPorts(ports []uint16) {
	p := slices.Clone(ports)
	slices.Sort(p)
	p = slices.Compact(p)
	nodeAllowed.Store(&p)
}

// NodeAllowedPorts returns what SetNodeAllowedPorts installed.
func NodeAllowedPorts() []uint16 {
	if p := nodeAllowed.Load(); p != nil {
		return slices.Clone(*p)
	}
	return nil
}

// FormatNodePorts renders ports for NodePortsEnv.
func FormatNodePorts(ports []uint16) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(int(p)))
	}
	return strings.Join(parts, ",")
}

// ParseNodePorts reads NodePortsEnv. Anything that is not a port is
// dropped: the value comes from sandboxd, and a bad entry must close a
// port, never open one.
func ParseNodePorts(raw string) []uint16 {
	var out []uint16
	for _, f := range strings.Split(raw, ",") {
		if n, err := strconv.ParseUint(strings.TrimSpace(f), 10, 16); err == nil && n > 0 {
			out = append(out, uint16(n))
		}
	}
	return out
}

// interfaceAddrs lists the node's addresses (a seam for tests).
var interfaceAddrs = net.InterfaceAddrs

// SetNodeAddrsSource replaces how this process reads the node's addresses
// and returns a func that restores the previous source. It exists for tests
// in other packages whose test servers listen on the test host's own
// addresses, which the node guard would otherwise refuse; production code
// never calls it.
func SetNodeAddrsSource(f func() ([]net.Addr, error)) (restore func()) {
	nodeAddrsMu.Lock()
	defer nodeAddrsMu.Unlock()
	prev := interfaceAddrs
	interfaceAddrs = f
	nodeAddrs.Store(nil)
	return func() {
		nodeAddrsMu.Lock()
		defer nodeAddrsMu.Unlock()
		interfaceAddrs = prev
		nodeAddrs.Store(nil)
	}
}

// nodeAddrTTL bounds how stale the cached address list may be: a bridge or
// an address added at runtime is guarded within it.
const nodeAddrTTL = time.Second

type nodeAddrSet struct {
	at   time.Time
	addr map[netip.Addr]struct{}
}

var (
	nodeAddrs   atomic.Pointer[nodeAddrSet]
	nodeAddrsMu sync.Mutex
)

// isNodeAddr reports whether ip is one of this node's interface addresses.
// The list is read at most once per nodeAddrTTL; readers never wait on a
// refresh that another goroutine is doing. A failed read keeps the last
// list (it has always succeeded on Linux; the alternative, refusing every
// dial, would turn a transient netlink error into an outage).
func isNodeAddr(ip netip.Addr) bool {
	cur := nodeAddrs.Load()
	if cur == nil || time.Since(cur.at) > nodeAddrTTL {
		if cur == nil {
			nodeAddrsMu.Lock()
			cur = refreshNodeAddrs()
			nodeAddrsMu.Unlock()
		} else if nodeAddrsMu.TryLock() {
			cur = refreshNodeAddrs()
			nodeAddrsMu.Unlock()
		}
	}
	_, ok := cur.addr[ip]
	return ok
}

// refreshNodeAddrs re-reads the interface addresses. Callers hold
// nodeAddrsMu.
func refreshNodeAddrs() *nodeAddrSet {
	if cur := nodeAddrs.Load(); cur != nil && time.Since(cur.at) <= nodeAddrTTL {
		return cur
	}
	next := &nodeAddrSet{at: time.Now(), addr: map[netip.Addr]struct{}{}}
	addrs, err := interfaceAddrs()
	if err != nil {
		if cur := nodeAddrs.Load(); cur != nil {
			next.addr = cur.addr
		}
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				next.addr[ip.Unmap()] = struct{}{}
			}
		}
	}
	nodeAddrs.Store(next)
	return next
}

// CheckNode refuses ap when it is the node itself: loopback, 0.0.0.0/8
// (Linux connects it to the host) or any address on the node's
// interfaces, except an allowed port on a non-loopback address.
func CheckNode(ap netip.AddrPort) error {
	ip := ap.Addr().Unmap()
	switch {
	case !ip.IsValid():
		return &DialError{Addr: ap.String(), Reason: DialReasonInvalid}
	case ip.IsLoopback():
		return &DialError{Addr: ip.String(), Reason: DialReasonLoopback}
	case ip.IsUnspecified() || thisNetwork.Contains(ip):
		return &DialError{Addr: ip.String(), Reason: DialReasonUnspecified}
	}
	if !isNodeAddr(ip) || slices.Contains(NodeAllowedPorts(), ap.Port()) {
		return nil
	}
	return &DialError{Addr: ip.String(), Reason: DialReasonNode}
}

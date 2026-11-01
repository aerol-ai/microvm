package worker

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

func realNodeCheck(t *testing.T) {
	t.Helper()
	prev := nodeCheck
	nodeCheck = egresspolicy.CheckNode
	restore := egresspolicy.SetNodeAddrsSource(net.InterfaceAddrs)
	t.Cleanup(func() { nodeCheck = prev; restore() })
}

// TestMediatorRefusesTheNode: a WASM sandbox with no policy and no operator
// file used to dial anything, the node's own services on loopback and its
// addresses included. Now the node is refused in every posture, and the
// refusal is audited like any guard refusal.
func TestMediatorRefusesTheNode(t *testing.T) {
	realNodeCheck(t)
	target := echoServer(t) // 127.0.0.1: a node agent listening on loopback
	_, port, _ := net.SplitHostPort(target)
	for _, g := range []egresspolicy.DialGuard{{}, {DenyFloor: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}, {Strict: true}} {
		m := newNetMediator()
		var denials []string
		m.SetEgressDenialObserver(func(_, _, addr, reason string) { denials = append(denials, addr+" "+reason) })
		m.SetDialGuard(g)
		for _, addr := range []string{target, net.JoinHostPort("localhost", port), net.JoinHostPort("0.0.0.0", port)} {
			c, err := m.DialContext(context.Background(), "sb", "tcp", addr)
			if err == nil {
				c.Close()
				t.Fatalf("guard %+v: a no-policy sandbox reached the node at %s", g, addr)
			}
			assertDenied(t, "node dial", err, reasonBlockedIP)
		}
		if len(denials) != 3 {
			t.Fatalf("every refusal is audited: %v", denials)
		}
	}
	// The cloud metadata endpoint, which the hook-less open dial also
	// reached when no operator file was configured.
	m := newNetMediator()
	if _, _, err := m.openDial(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
		t.Fatal("the metadata endpoint must be refused with no operator file")
	} else {
		assertDenied(t, "metadata", err, reasonBlockedIP)
	}
	// A policy dial to the node's own address is refused even when its CIDR
	// allows that address.
	if ip, ok := firstLocalIPv4(); ok {
		pm := newNetMediator()
		pm.SetPolicy("sb", mustPolicy(t, []string{netip.PrefixFrom(ip, 32).String()}, nil))
		if c, err := pm.DialContext(context.Background(), "sb", "tcp", netip.AddrPortFrom(ip, 9).String()); err == nil {
			c.Close()
			t.Fatalf("a CIDR allow covering the node's address %s opened the node", ip)
		} else {
			assertDenied(t, "policy dial to the node", err, reasonBlockedIP)
		}
	}
	// A live connection the node guard would refuse is closed on
	// revalidation too (admits re-decides with openCheck).
	if admits(admission{}, connDest{host: "127.0.0.1", port: 22, addr: netip.MustParseAddrPort("127.0.0.1:22")}) {
		t.Fatal("revalidation must refuse the node")
	}
}

// TestWorkerNodeAllowedPorts: a worker takes the allowed node ports from
// the environment sandboxd starts it with, and the variable survives the
// worker's environment allowlist.
func TestWorkerNodeAllowedPorts(t *testing.T) {
	prev := egresspolicy.NodeAllowedPorts()
	t.Cleanup(func() { egresspolicy.SetNodeAllowedPorts(prev) })
	t.Setenv(egresspolicy.NodePortsEnv, "80,443")
	loadNodeAllowedPorts()
	if got := egresspolicy.NodeAllowedPorts(); !slices.Equal(got, []uint16{80, 443}) {
		t.Fatalf("allowed ports = %v", got)
	}
	if !slices.ContainsFunc(workerEnvironment(), func(e string) bool { return strings.HasPrefix(e, egresspolicy.NodePortsEnv+"=") }) {
		t.Fatal("the worker environment must carry the node ports")
	}
	t.Setenv(egresspolicy.NodePortsEnv, "")
	loadNodeAllowedPorts()
	if got := egresspolicy.NodeAllowedPorts(); len(got) != 0 {
		t.Fatalf("unset allows none: %v", got)
	}
}

func firstLocalIPv4() (netip.Addr, bool) {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				if ip = ip.Unmap(); ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
					return ip, true
				}
			}
		}
	}
	return netip.Addr{}, false
}

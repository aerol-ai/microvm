package worker

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

// TestWorkerEgressRanges (C24): a worker takes the node's extra deny floor
// and private ranges and the private-range default from the environment
// sandboxd starts it with (all survive the allowlist); its decisions then
// refuse them, for a sandbox with a policy and one with none; and a list it
// cannot read stops the worker before it serves.
func TestWorkerEgressRanges(t *testing.T) {
	prevFloor, prevPrivate := egresspolicy.ExtraDenyFloor(), egresspolicy.ExtraPrivateRanges()
	t.Cleanup(func() { egresspolicy.SetRanges(prevFloor, prevPrivate); blockPrivateNoPolicy.Store(false) })
	t.Setenv(egresspolicy.DenyFloorEnv, "10.96.0.1")
	t.Setenv(egresspolicy.PrivateRangesEnv, "198.18.0.0/15")
	t.Setenv(egresspolicy.BlockPrivateEnv, "true")
	env := workerEnvironment()
	for _, name := range []string{egresspolicy.DenyFloorEnv, egresspolicy.PrivateRangesEnv, egresspolicy.BlockPrivateEnv} {
		if !slices.ContainsFunc(env, func(e string) bool { return strings.HasPrefix(e, name+"=") }) {
			t.Fatalf("the worker environment must carry %s", name)
		}
	}
	if err := loadWorkerGuards(); err != nil {
		t.Fatal(err)
	}
	opened := mustPolicy(t, []string{"10.0.0.0/8", "198.18.4.0/24"}, nil)
	for _, tc := range []struct {
		name   string
		policy *egresspolicy.Policy
		addr   string
		reason string // "" = allowed
	}{
		{"the floor, under a policy that allows its range", opened, "10.96.0.1:443", egresspolicy.DialReasonDenyFloor},
		{"the floor, no policy", nil, "10.96.0.1:443", egresspolicy.DialReasonDenyFloor},
		{"the rest of the range stays shut", opened, "198.18.9.9:443", egresspolicy.DialReasonPrivate},
		{"the opened part", opened, "198.18.4.20:443", ""},
		{"an extra range, no policy", nil, "198.18.9.9:443", egresspolicy.DialReasonPrivate},
		{"RFC 1918, no policy", nil, "10.1.2.3:443", egresspolicy.DialReasonPrivate},
		{"the internet, no policy", nil, "1.1.1.1:443", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := admission{policy: tc.policy, guard: egresspolicy.DialGuard{}}
			d := connDest{host: netip.MustParseAddrPort(tc.addr).Addr().String(), port: netip.MustParseAddrPort(tc.addr).Port(), addr: netip.MustParseAddrPort(tc.addr)}
			if got := admits(a, d); got != (tc.reason == "") {
				t.Fatalf("admits = %v, want %v", got, tc.reason == "")
			}
			if tc.reason == "" {
				return
			}
			var err error
			if tc.policy == nil {
				err = openCheck(a.guard, "", d.addr)
			} else {
				err = a.guard.Check(tc.policy, egresspolicy.DialTarget{Addr: d.addr})
			}
			var de *egresspolicy.DialError
			if !errors.As(err, &de) || de.Reason != tc.reason {
				t.Fatalf("err = %v, want %s", err, tc.reason)
			}
		})
	}
	// With the default off, a no-policy sandbox stays open to private
	// ranges as before, the floor still shut.
	t.Setenv(egresspolicy.BlockPrivateEnv, "false")
	if err := loadWorkerGuards(); err != nil {
		t.Fatal(err)
	}
	if err := openCheck(egresspolicy.DialGuard{}, "", netip.MustParseAddrPort("198.18.9.9:443")); err != nil {
		t.Fatalf("default off: %v", err)
	}
	if err := openCheck(egresspolicy.DialGuard{}, "", netip.MustParseAddrPort("10.96.0.1:443")); err == nil {
		t.Fatal("default off opened the floor")
	}
	t.Setenv(egresspolicy.DenyFloorEnv, "10.96.0.1/12")
	if err := RunCLI([]string{filepath.Join(t.TempDir(), "w.sock")}); err == nil || !strings.Contains(err.Error(), egresspolicy.DenyFloorEnv) {
		t.Fatalf("a worker with an unreadable floor: %v", err)
	}
	if err := RunCLIResident([]string{filepath.Join(t.TempDir(), "r.sock")}); err == nil || !strings.Contains(err.Error(), egresspolicy.DenyFloorEnv) {
		t.Fatalf("a resident host with an unreadable floor: %v", err)
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

// TestWorkerFloorFile (review R4): a worker gets the deny-floor file's
// path, refuses what it holds, and follows a change while it runs.
func TestWorkerFloorFile(t *testing.T) {
	prevFloor, prevPrivate, prevFile := egresspolicy.ExtraDenyFloor(), egresspolicy.ExtraPrivateRanges(), egresspolicy.FileFloor()
	t.Cleanup(func() { egresspolicy.SetRanges(prevFloor, prevPrivate); egresspolicy.SetFileFloor(prevFile) })
	prevPoll := operatorPoll
	operatorPoll = 5 * time.Millisecond
	t.Cleanup(func() { operatorPoll = prevPoll })
	path := filepath.Join(t.TempDir(), "deny-floor")
	if err := os.WriteFile(path, []byte("172.18.0.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(egresspolicy.DenyFloorEnv, "")
	t.Setenv(egresspolicy.PrivateRangesEnv, "")
	t.Setenv(egresspolicy.FloorFileEnv, path)
	if !slices.Contains(workerEnvironment(), egresspolicy.FloorFileEnv+"="+path) {
		t.Fatal("the worker environment must carry the floor file")
	}
	if err := loadWorkerGuards(); err != nil {
		t.Fatal(err)
	}
	if err := openCheck(egresspolicy.DialGuard{}, "", netip.MustParseAddrPort("172.18.0.2:443")); err == nil {
		t.Fatal("an address in the floor file was dialed")
	}
	if err := os.WriteFile(path+".new", []byte("172.18.0.44\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for openCheck(egresspolicy.DialGuard{}, "", netip.MustParseAddrPort("172.18.0.44:443")) == nil {
		if time.Now().After(deadline) {
			t.Fatal("the worker still dials the API server's new address")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

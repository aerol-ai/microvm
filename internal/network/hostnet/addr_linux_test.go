//go:build linux

package hostnet

import (
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func stubIPv4AddrsIn(t *testing.T, fn func(netns.NsHandle) ([]netlink.Addr, error)) {
	t.Helper()
	orig := ipv4AddrsIn
	ipv4AddrsIn = fn
	t.Cleanup(func() { ipv4AddrsIn = orig })
}

func nlAddr(cidr string) netlink.Addr {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	n.IP = ip
	return netlink.Addr{IPNet: n}
}

// Only the IPv4 addresses a sandbox could be reached at come back: not
// loopback, not an IPv6 one a dump might carry, not an entry with no
// address.
func TestNetnsIPv4AddrsFiltersTheDump(t *testing.T) {
	f := &fakeNetns{}
	f.install(t)
	stubIPv4AddrsIn(t, func(netns.NsHandle) ([]netlink.Addr, error) {
		return []netlink.Addr{nlAddr("127.0.0.1/8"), nlAddr("10.88.0.2/16"), {}, nlAddr("fd00::2/64"), nlAddr("10.88.0.9/16")}, nil
	})
	got, err := NetnsIPv4Addrs("/run/netns/aerol-netns-0")
	if err != nil || strings.Join(got, ",") != "10.88.0.2,10.88.0.9" {
		t.Fatalf("addrs=%v err=%v", got, err)
	}
	if f.sets != 0 {
		t.Fatalf("setns calls = %d: the read enters no namespace on the caller's thread", f.sets)
	}
}

// A namespace with only loopback holds no address: an empty list, no error.
func TestNetnsIPv4AddrsEmpty(t *testing.T) {
	f := &fakeNetns{}
	f.install(t)
	stubIPv4AddrsIn(t, func(netns.NsHandle) ([]netlink.Addr, error) {
		return []netlink.Addr{nlAddr("127.0.0.1/8")}, nil
	})
	got, err := NetnsIPv4Addrs("/run/netns/x")
	if err != nil || len(got) != 0 || got == nil {
		t.Fatalf("addrs=%#v err=%v", got, err)
	}
}

func TestNetnsIPv4AddrsFailures(t *testing.T) {
	f := &fakeNetns{}
	f.install(t)
	if _, err := NetnsIPv4Addrs("/run/netns/missing"); err == nil || !strings.Contains(err.Error(), "open netns") {
		t.Fatalf("missing netns = %v", err)
	}
	stubIPv4AddrsIn(t, func(netns.NsHandle) ([]netlink.Addr, error) {
		return nil, errors.New("netlink: operation not permitted")
	})
	if _, err := NetnsIPv4Addrs("/run/netns/x"); err == nil || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("netlink refused = %v", err)
	}
}

// Unstubbed: a path that is not there fails at open, before any netlink.
func TestNetnsIPv4AddrsMissingPath(t *testing.T) {
	if _, err := NetnsIPv4Addrs(filepath.Join(t.TempDir(), "gone")); err == nil {
		t.Fatal("a netns path that does not exist must fail")
	}
}

// The real dump, in the caller's own namespace (netns.None() asks for no
// setns, so it needs no privilege): it returns raw addresses, loopback
// included, which netnsIPv4Addrs then filters out.
func TestIPv4AddrsInOwnNamespace(t *testing.T) {
	addrs, err := ipv4AddrsIn(netns.None())
	if err != nil {
		t.Fatalf("netlink dump in the caller's namespace: %v", err)
	}
	for _, a := range addrs {
		if a.IPNet != nil && a.IP.To4() == nil {
			t.Fatalf("an IPv4 dump returned %s", a.IP)
		}
		if a.IPNet != nil && a.IP.IsLoopback() {
			return
		}
	}
	t.Skipf("no IPv4 loopback in this namespace (%d addresses)", len(addrs))
}

package rootpolicy

import (
	"net/netip"
	"strconv"
	"testing"
)

var (
	hpBounds = HostPortBounds{RangeStart: 22000, RangeEnd: 23000, RedirectPort: 21215}
	hpSubnet = netip.MustParsePrefix("10.88.0.0/16")
)

func TestHostPortBounds(t *testing.T) {
	if err := hpBounds.Check(); err != nil || hpBounds.Size() != 1001 {
		t.Fatalf("defaults: %v, size %d", err, hpBounds.Size())
	}
	for _, b := range []HostPortBounds{{RangeStart: 80, RangeEnd: 90}, {RangeStart: 23000, RangeEnd: 22000}, {RangeStart: 22000, RangeEnd: 70000}, {RangeStart: 22000, RangeEnd: 22000}} {
		if b.Check() == nil {
			t.Errorf("%+v passed", b)
		}
	}
}

func TestCheckHostPort(t *testing.T) {
	for _, hp := range []uint32{22000, 22500, 23000} {
		if got, err := CheckHostPort(hpBounds, hp); err != nil || got != int(hp) {
			t.Errorf("%d: %v %v", hp, got, err)
		}
	}
	// The node's own services' ports, and the edges.
	for _, hp := range []uint32{0, 22, 443, 6443, 10250, 21215, 21999, 23001, 65535, 1 << 20} {
		if _, err := CheckHostPort(hpBounds, hp); RuleOf(err) != RuleHostPort {
			t.Errorf("%d: %v", hp, err)
		}
	}
}

func TestCheckSandboxTarget(t *testing.T) {
	if ap, err := CheckSandboxTarget(hpSubnet, "10.88.0.5", 5432); err != nil || ap.String() != "10.88.0.5:5432" {
		t.Fatalf("= %v %v", ap, err)
	}
	for _, bad := range []struct {
		addr string
		port uint32
		rule Rule
	}{
		{"10.88.0.5", 0, RuleHostPort},
		{"10.88.0.5", 70000, RuleHostPort},
		{"10.88.0.1", 80, RuleAddress}, // the bridge: the node's own
		{"10.88.255.255", 80, RuleAddress},
		{"10.89.0.5", 80, RuleAddress}, // another range
		{"127.0.0.1", 80, RuleAddress},
		{"169.254.169.254", 80, RuleAddress},
		{"10.88.0.5:80", 80, RuleAddress},
		{"", 80, RuleAddress},
	} {
		if _, err := CheckSandboxTarget(hpSubnet, bad.addr, bad.port); RuleOf(err) != bad.rule {
			t.Errorf("%s:%d = %v, want rule %s", bad.addr, bad.port, err, bad.rule)
		}
	}
}

func TestCheckPeerTarget(t *testing.T) {
	if ap, err := CheckPeerTarget(hpBounds, hpSubnet, "10.0.1.7", 22005); err != nil || ap.String() != "10.0.1.7:22005" {
		t.Fatalf("= %v %v", ap, err)
	}
	for _, bad := range []struct {
		addr string
		port uint32
	}{
		{"10.88.0.5", 22005},       // a sandbox's
		{"10.88.0.1", 22005},       // the bridge
		{"127.0.0.1", 22005},       // the node itself
		{"169.254.169.254", 22005}, // the metadata endpoint
		{"224.0.0.1", 22005},
		{"255.255.255.255", 22005},
		{"0.0.0.0", 22005},
		{"10.0.1.7", 22}, // the peer's own services
		{"10.0.1.7", 10250},
		{"10.0.1.7", 0},
		{"::1", 22005},
		{"10.000.1.7", 22005},
		{"fe80::1%eth0", 22005},
	} {
		if _, err := CheckPeerTarget(hpBounds, hpSubnet, bad.addr, bad.port); RuleOf(err) != RuleHostPort {
			t.Errorf("%s:%d = %v", bad.addr, bad.port, err)
		}
	}
}

func TestCheckRedirectTarget(t *testing.T) {
	if p, err := CheckRedirectTarget(hpBounds, "", 21215); err != nil || p != 21215 {
		t.Fatalf("= %v %v", p, err)
	}
	for _, bad := range []struct {
		b    HostPortBounds
		addr string
		port uint32
	}{
		{hpBounds, "", 22},   // the node's SSH
		{hpBounds, "", 6443}, // its API server
		{hpBounds, "", 0},
		{hpBounds, "127.0.0.1", 21215},
		{HostPortBounds{RangeStart: 22000, RangeEnd: 23000, RedirectPort: 22500}, "", 22500}, // in the range
		{HostPortBounds{RangeStart: 22000, RangeEnd: 23000}, "", 0},
	} {
		if _, err := CheckRedirectTarget(bad.b, bad.addr, bad.port); RuleOf(err) != RuleHostPort {
			t.Errorf("%+v %q %d = %v", bad.b, bad.addr, bad.port, err)
		}
	}
}

// FuzzCheckHostPortTargets: what passes takes a port of the range, and
// hands it to a sandbox address of the range (not the bridge's), to a
// unicast address outside the range on a port of the range, or to the
// helper's redirect port alone.
func FuzzCheckHostPortTargets(f *testing.F) {
	f.Add(uint32(22000), "10.88.0.5", uint32(80))
	f.Add(uint32(22), "10.88.0.1", uint32(22000))
	f.Add(uint32(23000), "169.254.169.254", uint32(21215))
	f.Fuzz(func(t *testing.T, hp uint32, addr string, port uint32) {
		if got, err := CheckHostPort(hpBounds, hp); err == nil && (got < 22000 || got > 23000) {
			t.Fatalf("host port %d passed", hp)
		}
		if ap, err := CheckSandboxTarget(hpSubnet, addr, port); err == nil {
			a := ap.Addr()
			if !hpSubnet.Contains(a) || a == netip.MustParseAddr("10.88.0.1") || a == netip.MustParseAddr("10.88.0.0") ||
				a == netip.MustParseAddr("10.88.255.255") || ap.Port() == 0 {
				t.Fatalf("sandbox target %v passed", ap)
			}
		}
		if ap, err := CheckPeerTarget(hpBounds, hpSubnet, addr, port); err == nil {
			a := ap.Addr()
			if hpSubnet.Contains(a) || !a.Is4() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() ||
				a.IsUnspecified() || ap.Port() < 22000 || ap.Port() > 23000 || a.String() != addr {
				t.Fatalf("peer target %v passed", ap)
			}
		}
		if p, err := CheckRedirectTarget(hpBounds, addr, port); err == nil && (p != 21215 || addr != "") {
			t.Fatalf("redirect to %q:%s passed", addr, strconv.Itoa(p))
		}
	})
}

func TestHostPortRefusals(t *testing.T) {
	if CheckHostPortCount(hpBounds, 1001) != nil || RuleOf(CheckHostPortCount(hpBounds, 1002)) != RuleHostPort {
		t.Fatal("count bound")
	}
	if RuleOf(HostPortListedTwice(22000)) != RuleHostPort || RuleOf(PeerIsLocal(netip.MustParseAddr("10.0.0.1"))) != RuleHostPort {
		t.Fatal("refusals")
	}
}

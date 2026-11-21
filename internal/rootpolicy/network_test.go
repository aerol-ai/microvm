package rootpolicy

import (
	"net/netip"
	"path"
	"strings"
	"testing"
)

// TestNetnsPath: the helper builds a namespace path only from a name in the
// ID charset, and only directly under the netns folder.
func TestNetnsPath(t *testing.T) {
	p := testPolicy()
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"sb-1", true},
		{"aerol-netns-12", true},
		{"park_0a1b", true},
		{strings.Repeat("a", 128), true},

		{"", false},
		{"..", false},
		{".", false},
		{"../etc", false},
		{"sb/1", false},
		{"/run/netns/sb-1", false},
		{"sb-1\x00", false},
		{"sb 1", false},
		{"sb.1", false},
		{strings.Repeat("a", 129), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NetnsPath(p, tc.name)
			if !tc.ok {
				wantRule(t, err, RuleNetns)
				if got != "" {
					t.Fatalf("a refused name gave the path %q", got)
				}
				return
			}
			if err != nil || got != p.NetnsDir+"/"+tc.name || path.Dir(got) != p.NetnsDir {
				t.Fatalf("NetnsPath(%q) = %q, %v", tc.name, got, err)
			}
		})
	}
}

// TestCheckSandboxAddress: an address the helper flushes state for must be
// one sandbox's, inside the helper's own range.
func TestCheckSandboxAddress(t *testing.T) {
	subnet := netip.MustParsePrefix("10.88.0.0/16")
	for _, tc := range []struct {
		addr string
		ok   bool
	}{
		{"10.88.0.2", true},
		{"10.88.7.200", true},
		{"10.88.255.254", true},

		{"10.88.0.0", false},     // the network
		{"10.88.0.1", false},     // the bridge, host-local's gateway
		{"10.88.255.255", false}, // broadcast
		{"10.89.0.2", false},
		{"192.168.1.10", false},
		{"127.0.0.1", false},
		{"0.0.0.0", false},
		{"::ffff:10.88.0.2", false},
		{"fe80::1%eth0", false},
		{"fd00::2", false},
		{"", false},
		{"10.88.0.2/16", false},
		{" 10.88.0.2", false},
		{"10.88.0.2\n", false},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			ip, err := CheckSandboxAddress(subnet, tc.addr)
			if !tc.ok {
				wantRule(t, err, RuleAddress)
				return
			}
			if err != nil || ip.String() != tc.addr {
				t.Fatalf("CheckSandboxAddress(%q) = %v, %v", tc.addr, ip, err)
			}
		})
	}
	t.Run("an unmasked range is read as its network", func(t *testing.T) {
		if _, err := CheckSandboxAddress(netip.MustParsePrefix("10.88.4.5/16"), "10.88.0.1"); RuleOf(err) != RuleAddress {
			t.Fatalf("the bridge address passed: %v", err)
		}
		if _, err := CheckSandboxAddress(netip.MustParsePrefix("10.88.4.5/16"), "10.88.4.5"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("no range refuses everything", func(t *testing.T) {
		for _, s := range []netip.Prefix{{}, netip.MustParsePrefix("fd00::/64")} {
			if _, err := CheckSandboxAddress(s, "10.88.0.2"); RuleOf(err) != RuleAddress {
				t.Fatalf("range %v: %v", s, err)
			}
		}
	})
	t.Run("a small range", func(t *testing.T) {
		s := netip.MustParsePrefix("192.168.10.0/30")
		for addr, ok := range map[string]bool{"192.168.10.0": false, "192.168.10.1": false, "192.168.10.2": true, "192.168.10.3": false} {
			if _, err := CheckSandboxAddress(s, addr); (err == nil) != ok {
				t.Fatalf("%s: %v, want ok=%v", addr, err, ok)
			}
		}
	})
}

// FuzzNetnsPath: whatever the name, a path it gives sits directly under the
// netns folder and names a valid ID.
func FuzzNetnsPath(f *testing.F) {
	for _, s := range []string{"sb-1", "..", "../x", "a/b", "", "aerol-netns-0"} {
		f.Add(s)
	}
	p := testPolicy()
	f.Fuzz(func(t *testing.T, name string) {
		got, err := NetnsPath(p, name)
		if err != nil {
			return
		}
		if path.Dir(got) != p.NetnsDir || path.Base(got) != name || ValidateID(name) != nil {
			t.Fatalf("NetnsPath(%q) = %q", name, got)
		}
	})
}

// FuzzCheckSandboxAddress: an address it passes is a plain IPv4 inside the
// range, never its first two or its last.
func FuzzCheckSandboxAddress(f *testing.F) {
	for _, s := range []string{"10.88.0.2", "10.88.0.1", "::1", "10.88.255.255", "x"} {
		f.Add(s)
	}
	subnet := netip.MustParsePrefix("10.88.0.0/16")
	f.Fuzz(func(t *testing.T, addr string) {
		ip, err := CheckSandboxAddress(subnet, addr)
		if err != nil {
			return
		}
		if !ip.Is4() || !subnet.Contains(ip) || ip == subnet.Addr() || ip == subnet.Addr().Next() || ip == netip.MustParseAddr("10.88.255.255") {
			t.Fatalf("passed %q as %v", addr, ip)
		}
	})
}

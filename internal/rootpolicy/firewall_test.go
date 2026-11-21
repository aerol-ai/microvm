package rootpolicy

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestCheckRuleCIDRs(t *testing.T) {
	got, err := CheckRuleCIDRs([]string{"10.0.0.0/8", "1.2.3.4", "10.1.2.3/16", "0.0.0.0/0", "fd00::/8", "2001:db8::1"})
	want := []string{"10.0.0.0/8", "1.2.3.4/32", "10.1.0.0/16", "0.0.0.0/0", "fd00::/8", "2001:db8::1/128"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("CheckRuleCIDRs = %v, %v; want %v", got, err, want)
	}
	if got, err := CheckRuleCIDRs(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	for _, bad := range []string{
		"", " 10.0.0.0/8", "10.0.0.0/8 ", "example.com", "*.example.com", "10.0.0.0/33", "10.0.0.0/8\n-j ACCEPT",
		"-j", "--comment", "10.0.0.0/8,1.2.3.4", "fe80::1%eth0", "::ffff:10.0.0.1", "10.0.0", "1.2.3.4:80",
	} {
		if _, err := CheckRuleCIDRs([]string{"10.0.0.0/8", bad}); RuleOf(err) != RuleCIDR {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := CheckRuleCIDRs(make([]string, MaxRuleCIDRs+1)); RuleOf(err) != RuleCIDR {
		t.Fatalf("too many: %v", err)
	}
}

func TestCheckFloorCIDRs(t *testing.T) {
	got, err := CheckFloorCIDRs([]string{"10.20.0.0/16", "169.254.169.254", "fd00:ec2::254"})
	want := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("169.254.169.254/32"), netip.MustParsePrefix("fd00:ec2::254/128")}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("CheckFloorCIDRs = %v, %v", got, err)
	}
	for _, bad := range []string{"", "x", "10.0.0.0/40", " 10.0.0.0/8"} {
		if _, err := CheckFloorCIDRs([]string{bad}); RuleOf(err) != RuleCIDR {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := CheckFloorCIDRs(make([]string, MaxFloorCIDRs+1)); RuleOf(err) != RuleCIDR {
		t.Fatalf("too many: %v", err)
	}
}

func TestCheckNodePorts(t *testing.T) {
	ok := []NodePort{{Proto: "tcp", Port: 15080}, {Proto: "udp", Port: 53, Dst: "10.0.1.5"}, {Proto: "tcp", Port: 65535}}
	if got, err := CheckNodePorts(ok); err != nil || !slices.Equal(got, ok) {
		t.Fatalf("CheckNodePorts = %v, %v", got, err)
	}
	for _, bad := range []NodePort{
		{Proto: "icmp", Port: 1}, {Proto: "TCP", Port: 1}, {Proto: "tcp", Port: 0}, {Proto: "tcp", Port: 65536},
		{Proto: "udp", Port: 53, Dst: "fd00::1"}, {Proto: "udp", Port: 53, Dst: "10.0.1.5/32"}, {Proto: "udp", Port: 53, Dst: "010.0.1.5"},
		{Proto: "udp", Port: 53, Dst: " 10.0.1.5"},
	} {
		if _, err := CheckNodePorts([]NodePort{bad}); RuleOf(err) != RuleNodePort {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if _, err := CheckNodePorts(make([]NodePort, MaxNodePorts+1)); RuleOf(err) != RuleNodePort {
		t.Fatalf("too many: %v", err)
	}
}

// FuzzCheckRuleCIDRs: whatever passes is written back as a canonical
// prefix that parses to itself and carries nothing but the prefix.
func FuzzCheckRuleCIDRs(f *testing.F) {
	for _, s := range []string{"10.0.0.0/8", "1.2.3.4", "x", "10.0.0.0/8 -j ACCEPT", "::/0", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := CheckRuleCIDRs([]string{s})
		if err != nil {
			return
		}
		p, perr := netip.ParsePrefix(got[0])
		if perr != nil || p.String() != got[0] || p.Masked() != p || strings.ContainsAny(got[0], " \t\n-,") && !strings.Contains(got[0], ":") {
			t.Fatalf("%q passed as %q", s, got[0])
		}
	})
}

// FuzzCheckNodePorts: what passes is tcp or udp, a real port, and no
// address or one plain IPv4 address.
func FuzzCheckNodePorts(f *testing.F) {
	f.Add("tcp", uint32(80), "")
	f.Add("udp", uint32(53), "10.0.0.1")
	f.Add("sctp", uint32(70000), "x")
	f.Fuzz(func(t *testing.T, proto string, port uint32, dst string) {
		got, err := CheckNodePorts([]NodePort{{Proto: proto, Port: port, Dst: dst}})
		if err != nil {
			return
		}
		p := got[0]
		if (p.Proto != "tcp" && p.Proto != "udp") || p.Port == 0 || p.Port > 65535 {
			t.Fatalf("passed %+v", p)
		}
		if p.Dst != "" {
			if a, err := netip.ParseAddr(p.Dst); err != nil || !a.Is4() || a.String() != p.Dst {
				t.Fatalf("passed address %q", p.Dst)
			}
		}
	})
}

// TestCheckNodePortsWithin (PR 5 review): the agent narrows the helper's
// list, never widens it.
func TestCheckNodePortsWithin(t *testing.T) {
	bound := []NodePort{{Proto: "udp", Port: 53}, {Proto: "tcp", Port: 15080}, {Proto: "tcp", Port: 9000, Dst: "10.0.1.5"}}
	for _, ok := range [][]NodePort{nil, {{Proto: "udp", Port: 53}}, {{Proto: "udp", Port: 53, Dst: "10.0.1.9"}}, {{Proto: "tcp", Port: 9000, Dst: "10.0.1.5"}}} {
		if err := CheckNodePortsWithin(ok, bound); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for _, bad := range [][]NodePort{{{Proto: "tcp", Port: 10250}}, {{Proto: "tcp", Port: 53}}, {{Proto: "tcp", Port: 9000}}, {{Proto: "tcp", Port: 9000, Dst: "10.0.1.6"}}} {
		if RuleOf(CheckNodePortsWithin(bad, bound)) != RuleNodePort {
			t.Errorf("%v passed", bad)
		}
	}
}

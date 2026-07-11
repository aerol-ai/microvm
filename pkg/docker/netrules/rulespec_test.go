package netrules

import "testing"

func TestParseRulespecShapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		spec []string
		src  string
		dst  string
		cmt  string
		ver  verdictKind
	}{
		{
			name: "egress_drop",
			spec: []string{"-s", "10.0.0.2", "-j", "DROP"},
			src:  "10.0.0.2/32",
			ver:  verdictDrop,
		},
		{
			name: "ingress_drop",
			spec: []string{"-d", "10.0.0.3", "-j", "DROP"},
			dst:  "10.0.0.3/32",
			ver:  verdictDrop,
		},
		{
			name: "allowlist_accept",
			spec: []string{"-s", "10.0.0.5", "-d", "1.1.1.1/32", "-m", "comment", "--comment", egressPolicyComment, "-j", "ACCEPT"},
			src:  "10.0.0.5/32",
			dst:  "1.1.1.1/32",
			cmt:  egressPolicyComment,
			ver:  verdictAccept,
		},
		{
			name: "allowlist_catchall",
			spec: []string{"-s", "10.0.0.5", "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP"},
			src:  "10.0.0.5/32",
			cmt:  egressPolicyComment,
			ver:  verdictDrop,
		},
		{
			name: "denylist_cidr",
			spec: []string{"-s", "10.0.0.6", "-d", "192.168.0.0/16", "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP"},
			src:  "10.0.0.6/32",
			dst:  "192.168.0.0/16",
			cmt:  egressPolicyComment,
			ver:  verdictDrop,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseRulespec(tc.spec...)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if p.verdict != tc.ver {
				t.Fatalf("verdict = %v, want %v", p.verdict, tc.ver)
			}
			if tc.src != "" {
				if p.src == nil || p.src.String() != tc.src {
					t.Fatalf("src = %v, want %s", p.src, tc.src)
				}
			}
			if tc.dst != "" {
				if p.dst == nil || p.dst.String() != tc.dst {
					t.Fatalf("dst = %v, want %s", p.dst, tc.dst)
				}
			}
			if p.comment != tc.cmt {
				t.Fatalf("comment = %q, want %q", p.comment, tc.cmt)
			}
		})
	}
}

func TestParseRulespecRejectsUnknown(t *testing.T) {
	t.Parallel()
	for _, spec := range [][]string{
		{"-p", "tcp", "-j", "DROP"},
		{"-s", "10.0.0.1"},
		{"-j", "REJECT"},
		{"-m", "state", "--state", "NEW", "-j", "DROP"},
		{"-s"},                            // missing -s value
		{"-d"},                            // missing -d value
		{"-m"},                            // missing module
		{"-m", "comment"},                 // missing --comment
		{"-m", "comment", "--comment"},    // missing comment value
		{"-j"},                            // missing verdict
		{"-s", "not-an-ip", "-j", "DROP"}, // bad address
		{"-d", "not-an-ip", "-j", "DROP"}, // bad -d
		{"-j", "DROP"},                    // no -s/-d
	} {
		if _, err := parseRulespec(spec...); err == nil {
			t.Fatalf("expected error for %v", spec)
		}
	}
}

func TestParseAddrOrCIDR(t *testing.T) {
	t.Parallel()
	n, err := parseAddrOrCIDR("10.1.2.3")
	if err != nil || n.String() != "10.1.2.3/32" {
		t.Fatalf("v4 = %v, %v", n, err)
	}
	n, err = parseAddrOrCIDR("10.0.0.0/8")
	if err != nil || n.String() != "10.0.0.0/8" || len(n.IP) != 4 || len(n.Mask) != 4 {
		t.Fatalf("v4 cidr = %v (ip=%d mask=%d bytes), %v; want 4-byte form", n, len(n.IP), len(n.Mask), err)
	}
	if _, err := parseAddrOrCIDR("nope"); err == nil {
		t.Fatal("want invalid address")
	}
	if _, err := parseAddrOrCIDR("10.0.0.0/33"); err == nil {
		t.Fatal("want bad CIDR")
	}
}

// User-supplied NetworkAllowOut/DenyOut entries can be IPv6. The netlink
// backend drives the IPv4 filter table only, and its translator indexes
// IP[0..3] — a 16-byte address slipping past parse was a daemon panic. Every
// IPv6 shape must fail closed at parse instead.
func TestParseAddrOrCIDRRejectsIPv6(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"2001:db8::1",         // bare address
		"2001:db8::/32",       // CIDR
		"::ffff:10.1.2.3/120", // v4-mapped CIDR (16-byte mask)
		"fe80::1",             // link-local
	} {
		if _, err := parseAddrOrCIDR(s); err == nil {
			t.Errorf("parseAddrOrCIDR(%q) = nil error, want IPv6 rejection", s)
		}
	}
	for _, spec := range [][]string{
		{"-s", "2001:db8::/32", "-j", "ACCEPT"},
		{"-d", "2001:db8::1", "-j", "DROP"},
	} {
		if _, err := parseRulespec(spec...); err == nil {
			t.Errorf("parseRulespec(%v) = nil error, want IPv6 rejection", spec)
		}
	}
}

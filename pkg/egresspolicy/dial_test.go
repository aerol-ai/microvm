package egresspolicy

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func mustZone(t *testing.T, suffixes, cidrs []string) *InternalZone {
	t.Helper()
	z, err := NewInternalZone(suffixes, cidrs)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

// TestDialGuardCheck covers EF-12 and EF-79 at the shared dial control.
func TestDialGuardCheck(t *testing.T) {
	zone := mustZone(t, []string{"corp.bank.internal", "*.lab.internal"}, []string{"10.0.0.0/8", "fd00::/8"})
	cidrAllow := mustCompile(t, Spec{AllowOut: []string{"10.0.0.0/8", "pypi.org"}})
	allowlist := mustCompile(t, Spec{AllowOut: []string{"pypi.org"}})
	mixed := mustCompile(t, Spec{AllowOut: []string{"api.example.com"}, DenyOut: []string{"203.0.113.0/24"}})
	blocked := mustCompile(t, Spec{BlockAll: true})

	tests := []struct {
		name   string
		guard  DialGuard
		policy *Policy
		target DialTarget
		reason string // "" = allowed
		rule   string
	}{
		// Always refused, whatever the policy says.
		{"loopback", DialGuard{}, cidrAllow, DialTarget{Name: "pypi.org", NameAllowed: true, Addr: ap("127.0.0.1:443")}, DialReasonLoopback, ""},
		{"loopback_v6", DialGuard{}, nil, DialTarget{Addr: ap("[::1]:443")}, DialReasonLoopback, ""},
		{"v4_mapped_loopback", DialGuard{}, nil, DialTarget{Addr: ap("[::ffff:127.0.0.1]:443")}, DialReasonLoopback, ""},
		{"metadata", DialGuard{}, cidrAllow, DialTarget{Name: "pypi.org", NameAllowed: true, Addr: ap("169.254.169.254:80")}, DialReasonLinkLocal, ""},
		{"link_local_v6", DialGuard{}, nil, DialTarget{Addr: ap("[fe80::1]:443")}, DialReasonLinkLocal, ""},
		{"link_local_multicast_v6", DialGuard{}, nil, DialTarget{Addr: ap("[ff02::1]:443")}, DialReasonLinkLocal, ""},
		{"unspecified", DialGuard{}, nil, DialTarget{Addr: ap("0.0.0.0:443")}, DialReasonUnspecified, ""},
		{"this_network", DialGuard{}, nil, DialTarget{Addr: ap("0.1.2.3:443")}, DialReasonUnspecified, ""},
		{"unspecified_v6", DialGuard{}, nil, DialTarget{Addr: ap("[::]:443")}, DialReasonUnspecified, ""},
		{"multicast", DialGuard{}, nil, DialTarget{Addr: ap("239.1.1.1:443")}, DialReasonMulticast, ""},
		{"broadcast", DialGuard{}, nil, DialTarget{Addr: ap("255.255.255.255:443")}, DialReasonMulticast, ""},
		{"multicast_v6", DialGuard{}, nil, DialTarget{Addr: ap("[ff05::1]:443")}, DialReasonMulticast, ""},
		{"invalid", DialGuard{}, nil, DialTarget{}, DialReasonInvalid, ""},

		// Private ranges: refused unless a policy CIDR allows them.
		{"rfc1918_no_policy", DialGuard{}, nil, DialTarget{Addr: ap("10.0.0.5:443")}, DialReasonPrivate, ""},
		{"rfc1918_rebinding", DialGuard{}, allowlist, DialTarget{Name: "pypi.org", NameAllowed: true, Addr: ap("192.168.1.1:443")}, DialReasonPrivate, ""},
		{"rfc1918_cidr_allowed", DialGuard{}, cidrAllow, DialTarget{Name: "pypi.org", NameAllowed: true, Addr: ap("10.1.2.3:443")}, "", ""},
		{"rfc1918_cidr_allowed_raw", DialGuard{}, cidrAllow, DialTarget{Addr: ap("10.1.2.3:5432")}, "", ""},
		{"cgnat_alibaba_metadata", DialGuard{}, nil, DialTarget{Addr: ap("100.100.100.200:80")}, DialReasonPrivate, ""},
		{"ula_aws_metadata_v6", DialGuard{}, nil, DialTarget{Addr: ap("[fd00:ec2::254]:80")}, DialReasonPrivate, ""},
		{"v4_mapped_private", DialGuard{}, nil, DialTarget{Addr: ap("[::ffff:10.0.0.1]:443")}, DialReasonPrivate, ""},
		{"public_no_policy", DialGuard{}, nil, DialTarget{Addr: ap("8.8.8.8:443")}, "", ""},

		// The policy, applied only when the name did not match an allow rule.
		{"allowlist_raw_ip_default_deny", DialGuard{}, allowlist, DialTarget{Addr: ap("8.8.8.8:443")}, DialReasonNotAllowed, ""},
		{"allowlist_name_matched", DialGuard{}, allowlist, DialTarget{Name: "pypi.org", NameAllowed: true, Addr: ap("151.101.0.223:443")}, "", ""},
		{"mixed_deny_cidr", DialGuard{}, mixed, DialTarget{Name: "other.com", Addr: ap("203.0.113.5:443")}, DialReasonDenyCIDR, "203.0.113.0/24"},
		{"mixed_allow_wins_over_deny_cidr", DialGuard{}, mixed, DialTarget{Name: "api.example.com", NameAllowed: true, Addr: ap("203.0.113.5:443")}, "", ""},
		{"mixed_default_accept", DialGuard{}, mixed, DialTarget{Name: "other.com", Addr: ap("198.51.100.1:443")}, "", ""},
		{"block_all", DialGuard{}, blocked, DialTarget{Addr: ap("8.8.8.8:443")}, DialReasonBlockAll, ""},

		// Strict (isolate, D15): private is refused even when CIDR-allowed.
		{"strict_private_despite_cidr", DialGuard{Strict: true}, cidrAllow, DialTarget{Name: "pypi.org", NameAllowed: true, Addr: ap("10.1.2.3:443")}, DialReasonPrivate, ""},
		{"strict_public", DialGuard{Strict: true}, nil, DialTarget{Addr: ap("8.8.8.8:443")}, "", ""},

		// Internal zone (PC-1): only names under the suffixes reach the zone.
		{"zone_name_reaches_zone_ip", DialGuard{Zone: zone}, allowlist, DialTarget{Name: "artifactory.corp.bank.internal", NameAllowed: true, Addr: ap("10.1.2.3:443")}, "", ""},
		{"zone_apex_suffix", DialGuard{Zone: zone}, nil, DialTarget{Name: "corp.bank.internal", Addr: ap("10.1.2.3:443")}, "", ""},
		{"zone_wildcard_suffix", DialGuard{Zone: zone}, nil, DialTarget{Name: "git.lab.internal", Addr: ap("[fd00::5]:22")}, "", ""},
		{"zone_wildcard_not_apex", DialGuard{Zone: zone}, nil, DialTarget{Name: "lab.internal", Addr: ap("10.1.2.3:443")}, DialReasonPrivate, ""},
		{"zone_rebinding_name_outside_suffixes", DialGuard{Zone: zone}, allowlist, DialTarget{Name: "evil.example", NameAllowed: true, Addr: ap("10.1.2.3:443")}, DialReasonPrivate, ""},
		{"zone_raw_ip", DialGuard{Zone: zone}, nil, DialTarget{Addr: ap("10.1.2.3:443")}, DialReasonPrivate, ""},
		{"zone_name_outside_zone_cidrs", DialGuard{Zone: zone}, nil, DialTarget{Name: "a.corp.bank.internal", Addr: ap("192.168.1.1:443")}, DialReasonPrivate, ""},
		{"zone_never_opens_metadata", DialGuard{Zone: zone}, nil, DialTarget{Name: "a.corp.bank.internal", Addr: ap("169.254.169.254:80")}, DialReasonLinkLocal, ""},
		{"zone_floor_wins", DialGuard{Zone: zone, DenyFloor: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")}}, nil, DialTarget{Name: "core.corp.bank.internal", Addr: ap("10.9.1.1:443")}, DialReasonDenyFloor, "10.9.0.0/16"},
		{"zone_policy_deny_still_applies_unmatched", DialGuard{Zone: zone}, mustCompile(t, Spec{DenyOut: []string{"10.0.0.0/8"}}), DialTarget{Name: "a.corp.bank.internal", Addr: ap("10.1.2.3:443")}, DialReasonDenyCIDR, "10.0.0.0/8"},
		{"strict_ignores_zone_by_default", DialGuard{Strict: true, Zone: zone}, nil, DialTarget{Name: "a.corp.bank.internal", Addr: ap("10.1.2.3:443")}, DialReasonPrivate, ""},
		{"strict_zone_opt_in", DialGuard{Strict: true, Zone: zone, ZoneInStrict: true}, nil, DialTarget{Name: "a.corp.bank.internal", Addr: ap("10.1.2.3:443")}, "", ""},

		// The operator floor beats a CIDR allow too.
		{"floor_beats_cidr_allow", DialGuard{DenyFloor: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}}, cidrAllow, DialTarget{Addr: ap("10.0.1.1:443")}, DialReasonDenyFloor, "10.0.0.0/16"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.guard.Check(tc.policy, tc.target)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			var de *DialError
			if !errors.As(err, &de) || de.Reason != tc.reason || de.Rule != tc.rule {
				t.Fatalf("err = %#v, want reason %q rule %q", err, tc.reason, tc.rule)
			}
			if !errors.Is(err, ErrDialRefused) || !strings.Contains(err.Error(), "blocked") {
				t.Fatalf("error %q must match ErrDialRefused and say blocked", err)
			}
			if tc.rule != "" && !strings.Contains(err.Error(), tc.rule) {
				t.Fatalf("error %q must name the rule %q", err, tc.rule)
			}
		})
	}
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestDialGuardControl(t *testing.T) {
	ctl := DialGuard{}.Control(mustCompile(t, Spec{AllowOut: []string{"pypi.org"}}), "pypi.org", true)
	if err := ctl("tcp4", "151.101.0.223:443", nil); err != nil {
		t.Fatalf("public resolved IP refused: %v", err)
	}
	for addr, reason := range map[string]string{
		"127.0.0.1:80":    DialReasonLoopback,
		"10.0.0.1":        DialReasonPrivate, // no port: still judged
		"[fe80::1%en0]:1": DialReasonLinkLocal,
		"not-an-address":  DialReasonInvalid,
	} {
		var de *DialError
		if err := ctl("tcp", addr, nil); !errors.As(err, &de) || de.Reason != reason {
			t.Errorf("Control(%q) = %v, want %s", addr, err, reason)
		}
	}
	if err := StrictDialControl("tcp", "10.0.0.1:443", nil); !errors.Is(err, ErrDialRefused) {
		t.Fatalf("strict control allowed a private address: %v", err)
	}
	if err := StrictDialControl("tcp", "8.8.8.8:443", nil); err != nil {
		t.Fatalf("strict control refused a public address: %v", err)
	}
}

func TestNewInternalZone(t *testing.T) {
	valid := []struct{ suffixes, cidrs []string }{
		{[]string{"corp.bank.internal"}, []string{"10.0.0.0/8"}},
		{[]string{"*.internal", "internal", "corp"}, []string{"172.20.0.0/16", "100.64.0.0/10", "fd00::/8", "192.168.0.0/16"}},
	}
	for _, v := range valid {
		if _, err := NewInternalZone(v.suffixes, v.cidrs); err != nil {
			t.Errorf("NewInternalZone(%v, %v): %v", v.suffixes, v.cidrs, err)
		}
	}
	invalid := []struct {
		name            string
		suffixes, cidrs []string
		want            string
	}{
		{"suffix_cidr", []string{"10.0.0.0/8"}, []string{"10.0.0.0/8"}, "hostname suffix"},
		{"suffix_port", []string{"corp.internal:22"}, []string{"10.0.0.0/8"}, "port"},
		{"suffix_icann", []string{"com"}, []string{"10.0.0.0/8"}, "public suffix"},
		{"suffix_icann_wildcard", []string{"*.co.uk"}, []string{"10.0.0.0/8"}, "public suffix"},
		{"suffix_bad", []string{"bad name"}, []string{"10.0.0.0/8"}, "invalid character"},
		{"cidr_bad", []string{"corp.internal"}, []string{"10.0.0.0/33"}, "not a valid CIDR"},
		{"cidr_public", []string{"corp.internal"}, []string{"8.8.8.0/24"}, "RFC 1918"},
		{"cidr_too_wide", []string{"corp.internal"}, []string{"10.0.0.0/7"}, "RFC 1918"},
		{"cidr_loopback", []string{"corp.internal"}, []string{"127.0.0.0/8"}, "RFC 1918"},
		{"cidr_link_local", []string{"corp.internal"}, []string{"169.254.0.0/16"}, "RFC 1918"},
		{"no_cidrs", []string{"corp.internal"}, nil, "at least one"},
		{"no_suffixes", nil, []string{"10.0.0.0/8"}, "at least one"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewInternalZone(tc.suffixes, tc.cidrs)
			if err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want ErrInvalid containing %q", err, tc.want)
			}
		})
	}
	var nilZone *InternalZone
	if nilZone.CoversName("a.corp.internal") || nilZone.Covers("a.corp.internal", netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("a nil zone covers nothing")
	}
	z := mustZone(t, []string{"corp.internal"}, []string{"10.0.0.0/8"})
	if z.CoversName("bad name.corp.internal") || z.CoversName("") || !z.CoversName("A.Corp.Internal.") {
		t.Fatal("CoversName normalization")
	}
}

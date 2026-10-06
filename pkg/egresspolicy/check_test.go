package egresspolicy

import (
	"errors"
	"testing"
)

// TestCheck mirrors the matcher table for the policy check endpoint (P2-9,
// EF-50).
func TestCheck(t *testing.T) {
	allowlist := mustCompile(t, Spec{AllowOut: []string{"*.github.com", "pypi.org", "git.example.com:22", "203.0.113.0/24"}})
	mixed := mustCompile(t, Spec{AllowOut: []string{"api.example.com"}, DenyOut: []string{"198.51.100.0/24"}})
	tests := []struct {
		name string
		p    *Policy
		dest string
		want CheckResult
	}{
		{"wildcard_subdomain", allowlist, "api.github.com", CheckResult{true, "*.github.com", VerdictDeny}},
		{"wildcard_not_apex", allowlist, "github.com", CheckResult{false, "", VerdictDeny}},
		{"bare_host_means_web_ports", allowlist, "pypi.org", CheckResult{true, "pypi.org", VerdictDeny}},
		{"bare_host_with_web_port", allowlist, "pypi.org:80", CheckResult{true, "pypi.org", VerdictDeny}},
		{"bare_host_other_port", allowlist, "pypi.org:8080", CheckResult{false, "", VerdictDeny}},
		{"port_rule_needs_its_port", allowlist, "git.example.com", CheckResult{false, "", VerdictDeny}},
		{"port_rule_with_port", allowlist, "git.example.com:22", CheckResult{true, "git.example.com:22", VerdictDeny}},
		{"ip", allowlist, "203.0.113.9", CheckResult{true, "203.0.113.0/24", VerdictDeny}},
		{"ip_port", allowlist, "203.0.113.9:5432", CheckResult{true, "203.0.113.0/24", VerdictDeny}},
		{"ipv6_bracketed_port", allowlist, "[2001:db8::1]:443", CheckResult{false, "", VerdictDeny}},
		{"ipv6_bare", allowlist, "2001:db8::1", CheckResult{false, "", VerdictDeny}},
		{"mixed_allow_wins", mixed, "api.example.com", CheckResult{true, "api.example.com", VerdictAllow}},
		{"mixed_deny_cidr", mixed, "198.51.100.4:443", CheckResult{false, "198.51.100.0/24", VerdictAllow}},
		{"mixed_default_accept", mixed, "other.example", CheckResult{true, "", VerdictAllow}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Check(tc.p, tc.dest)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("Check(%q) = %+v, want %+v", tc.dest, got, tc.want)
			}
		})
	}
}

func TestCheckInvalidDestination(t *testing.T) {
	p := mustCompile(t, Spec{AllowOut: []string{"pypi.org"}})
	for _, dest := range []string{"", "  ", "pypi.org:0", "pypi.org:abc", "pypi.org:", "1.2.3.4:0", "[::1]:0", "bad name!", "a..b"} {
		res, err := Check(p, dest)
		if err == nil || !errors.Is(err, ErrInvalid) {
			t.Errorf("Check(%q) err = %v, want ErrInvalid", dest, err)
		}
		if res.DefaultVerdict != VerdictDeny {
			t.Errorf("Check(%q) should still report the default verdict", dest)
		}
	}
}

func TestParseDestination(t *testing.T) {
	host, ip, port, err := ParseDestination("PyPI.org.:8080")
	if err != nil || host != "pypi.org" || ip.IsValid() || port != 8080 {
		t.Fatalf("got %q %v %d %v", host, ip, port, err)
	}
	host, ip, port, err = ParseDestination("::ffff:203.0.113.7")
	if err != nil || host != "" || ip.String() != "203.0.113.7" || port != 0 {
		t.Fatalf("got %q %v %d %v", host, ip, port, err)
	}
}

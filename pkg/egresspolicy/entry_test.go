package egresspolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestParseEntryValid(t *testing.T) {
	tests := []struct {
		raw   string
		kind  Kind
		canon string
		port  uint16
	}{
		{"10.0.0.0/8", KindCIDR, "10.0.0.0/8", 0},
		{" 10.1.2.3/8 ", KindCIDR, "10.0.0.0/8", 0}, // trimmed and masked
		{"203.0.113.7/32", KindCIDR, "203.0.113.7/32", 0},
		{"2001:db8::/32", KindCIDR, "2001:db8::/32", 0},
		{"::ffff:10.0.0.0/104", KindCIDR, "10.0.0.0/8", 0}, // v4-mapped stored as v4
		{"pypi.org", KindHost, "pypi.org", 0},
		{"PyPI.ORG.", KindHost, "pypi.org", 0}, // lowercase, trailing dot stripped
		{"*.pythonhosted.org", KindWildcard, "*.pythonhosted.org", 0},
		{".pythonhosted.org", KindWildcard, "*.pythonhosted.org", 0}, // legacy isolate alias
		{"github.com:22", KindHost, "github.com:22", 22},
		{"*.Example.com:8443", KindWildcard, "*.example.com:8443", 8443},
		{"example.com:065535", KindHost, "example.com:65535", 65535},
		{"bücher.example", KindHost, "xn--bcher-kva.example", 0}, // punycode
		{"xn--bcher-kva.example", KindHost, "xn--bcher-kva.example", 0},
		{"_sip._tcp.example.com", KindHost, "_sip._tcp.example.com", 0},
		{"r3---sn-abc.googlevideo.com", KindHost, "r3---sn-abc.googlevideo.com", 0},
		{"localhost", KindHost, "localhost", 0},
		{"github.io", KindHost, "github.io", 0}, // an exact public suffix host is one host
		{"*.foo.github.io", KindWildcard, "*.foo.github.io", 0},
		{"*.corp.bank.internal", KindWildcard, "*.corp.bank.internal", 0},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			e, err := ParseEntry(tc.raw)
			if err != nil {
				t.Fatalf("ParseEntry(%q) error: %v", tc.raw, err)
			}
			if e.Kind != tc.kind || e.String() != tc.canon || e.Port != tc.port {
				t.Fatalf("ParseEntry(%q) = %+v (%q), want kind %v canon %q port %d", tc.raw, e, e.String(), tc.kind, tc.canon, tc.port)
			}
			again, err := ParseEntry(e.String())
			if err != nil || again != e {
				t.Fatalf("canonical form %q does not round-trip: %+v, %v", e.String(), again, err)
			}
			if e.IsHostname() != (tc.kind != KindCIDR) {
				t.Fatalf("IsHostname = %v for %v", e.IsHostname(), tc.kind)
			}
		})
	}
}

func TestParseEntryInvalid(t *testing.T) {
	tests := []struct {
		raw    string
		reason string
	}{
		{"", "empty entry"},
		{"   ", "empty entry"},
		{strings.Repeat("a", maxRawEntryLength+1), "longer than"},
		{"10.0.0.0/33", "not a valid CIDR"},
		{"foo/bar", "not a valid CIDR"},
		{"10.0.0.1", "IP literals"},
		{"10.0.0.1:22", "IP literals"},
		{"10.0.0.1:junk", "IP literals"},
		{"::1", "IP literals"},
		{"fe80::1%eth0", "IP literals"},
		{"[::1]", "IP literals"},
		{"[::1]:443", "IP literals"},
		{"example.com:80", "redundant"},
		{"example.com:443", "redundant"},
		{"example.com:0", "1-65535"},
		{"example.com:65536", "1-65535"},
		{"example.com:+22", "1-65535"},
		{"example.com:", "empty port"},
		{"example.com:22:33", "not a hostname"},
		{"*", "leading"},
		{"*.*.example.com", "leading"},
		{"foo*.example.com", "leading"},
		{"*example.com", "leading"},
		{"*.com", "public suffix"},
		{"*.github.io", "public suffix"},
		{"*.co.uk", "public suffix"},
		{"*.internal", "public suffix"},
		{".com", "public suffix"},
		{"exa mple.com", "invalid character"},
		{"exa!mple.com", "invalid character"},
		{"-bad.example.com", "hyphen"},
		{"bad-.example.com", "hyphen"},
		{"a..b", "empty label"},
		{"127.1", "looks like an IP"},
		{"example.123", "looks like an IP"},
		{strings.Repeat("a", 64) + ".com", "label longer"},
		{strings.Repeat("abcdefghi.", 26) + "com", "hostname longer"},
		{".", "empty hostname"},
		{"*.", "empty hostname"},
		{"xn--a.com", "not a valid hostname"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%.40s", tc.raw), func(t *testing.T) {
			_, err := ParseEntry(tc.raw)
			if err == nil {
				t.Fatalf("ParseEntry(%q) accepted, want error containing %q", tc.raw, tc.reason)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("ParseEntry(%q) error %q, want it to contain %q", tc.raw, err, tc.reason)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error %v does not match ErrInvalid", err)
			}
			var ee *EntryError
			if !errors.As(err, &ee) || ee.Entry != tc.raw {
				t.Fatalf("error %v does not name the entry %q", err, tc.raw)
			}
		})
	}
}

func TestParseAllowList(t *testing.T) {
	t.Run("dedupes_aliases_and_keeps_order", func(t *testing.T) {
		got, err := ParseAllowList(FieldAllowOut, []string{"pypi.org", ".x.example.com", "10.0.0.0/8", "*.x.example.com", "PYPI.org."}, MaxInlineHostnames)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"pypi.org", "*.x.example.com", "10.0.0.0/8"}
		if s := entryStrings(got); strings.Join(s, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v, want %v", s, want)
		}
	})
	t.Run("empty_is_nil", func(t *testing.T) {
		got, err := ParseAllowList(FieldAllowOut, nil, 1)
		if err != nil || got != nil {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("hostname_cap_ignores_cidrs", func(t *testing.T) {
		var list []string
		for i := 0; i < MaxInlineHostnames; i++ {
			list = append(list, fmt.Sprintf("h%d.example.com", i))
		}
		list = append(list, "10.0.0.0/8", "192.168.0.0/16")
		if _, err := ParseAllowList(FieldAllowOut, list, MaxInlineHostnames); err != nil {
			t.Fatalf("at the cap: %v", err)
		}
		list = append(list, "one-more.example.com")
		_, err := ParseAllowList(FieldAllowOut, list, MaxInlineHostnames)
		if err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "65 hostname entries") {
			t.Fatalf("over the cap: %v", err)
		}
	})
	t.Run("error_names_field_and_entry", func(t *testing.T) {
		_, err := ParseAllowList("allow_out", []string{"pypi.org", "*.com"}, MaxProfileHostnames)
		if err == nil || !strings.HasPrefix(err.Error(), `allow_out entry "*.com"`) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestParseDenyListRejectsHostnames(t *testing.T) {
	for _, raw := range []string{"evil.com", "*.evil.com", ".evil.com", "evil.com:22"} {
		_, err := ParseDenyList(FieldDenyOut, []string{"10.0.0.0/8", raw})
		if err == nil || !errors.Is(err, ErrInvalid) {
			t.Fatalf("deny %q: err = %v, want ErrInvalid", raw, err)
		}
		want := fmt.Sprintf("network_deny_out entry %q: hostnames are not allowed in deny lists", raw)
		if !strings.HasPrefix(err.Error(), want) {
			t.Fatalf("deny %q: err = %q, want prefix %q", raw, err, want)
		}
	}
	got, err := ParseDenyList(FieldDenyOut, []string{"203.0.113.0/24", "203.0.113.0/24"})
	if err != nil || len(got) != 1 {
		t.Fatalf("CIDR deny list = %v, %v", got, err)
	}
}

func TestEntryAndKindStrings(t *testing.T) {
	if (Entry{}).String() != "" {
		t.Fatal("zero entry should print empty")
	}
	for k, want := range map[Kind]string{KindCIDR: "cidr", KindHost: "host", KindWildcard: "wildcard", Kind(99): "unknown"} {
		if k.String() != want {
			t.Fatalf("Kind(%d).String() = %q, want %q", k, k.String(), want)
		}
	}
	if (&EntryError{Entry: "x", Reason: "r"}).Error() != `egress entry "x": r` {
		t.Fatal("EntryError without field")
	}
	if (Entry{Kind: KindCIDR, Prefix: netip.MustParsePrefix("10.0.0.0/8")}).coversName("10.0.0.0") {
		t.Fatal("a CIDR entry never covers a name")
	}
}

func TestParseEntryRejectsInvalidUTF8(t *testing.T) {
	if _, err := ParseEntry("\xff\xfe.com"); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 host accepted: %v", err)
	}
}

func TestCanonicalName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"PyPI.org.", "pypi.org"},
		{" api.example.com ", "api.example.com"},
		{"r3---sn-abc.googlevideo.com", "r3---sn-abc.googlevideo.com"},
		{"-lenient.example.com", "-lenient.example.com"}, // matching is lenient on hyphens
		{"BÜCHER.example", "xn--bcher-kva.example"},
		{"", ""},
		{"evil.com\x00.pypi.org", ""},
		{"a..b", ""},
		{"1.2.3.4", ""},
		{strings.Repeat("abcdefghi.", 26) + "com", ""},
		{strings.Repeat("a", maxRawEntryLength+1), ""},
		{"\xff\xfe", ""},
	}
	for _, tc := range tests {
		if got := canonicalName(tc.in); got != tc.want {
			t.Errorf("canonicalName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

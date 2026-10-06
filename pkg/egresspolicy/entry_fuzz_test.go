package egresspolicy

import (
	"strings"
	"testing"
)

// FuzzParseEntry asserts the grammar's invariants (EF-71): no panics; any
// accepted entry has a canonical form that re-parses to the same Entry; an
// accepted hostname is lowercase LDH(+underscore) ASCII within the DNS
// length limit, and a wildcard is never on a public suffix.
func FuzzParseEntry(f *testing.F) {
	for _, s := range []string{
		"pypi.org", "*.pythonhosted.org", ".pythonhosted.org", "github.com:22", "10.0.0.0/8",
		"::ffff:10.0.0.0/104", "2001:db8::/32", "bücher.example", "*.com", "*.github.io", "10.0.0.1",
		"[::1]:443", "example.com:443", "example.com:0", "*.*.x.com", "127.1", "xn--a.com", "\xff\xfe.com",
		"r3---sn-abc.googlevideo.com", "_sip._tcp.example.com", "a..b", "", " ", "*", "evil.com\x00.pypi.org",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		e, err := ParseEntry(raw)
		if err != nil {
			return
		}
		canon := e.String()
		again, err := ParseEntry(canon)
		if err != nil || again != e {
			t.Fatalf("ParseEntry(%q) = %q, which re-parses to %+v, %v", raw, canon, again, err)
		}
		if !e.IsHostname() {
			if e.Kind != KindCIDR || e.Prefix != e.Prefix.Masked() {
				t.Fatalf("ParseEntry(%q) = unmasked or unknown %+v", raw, e)
			}
			return
		}
		if e.Port == 80 || e.Port == 443 {
			t.Fatalf("ParseEntry(%q) accepted redundant port %d", raw, e.Port)
		}
		if len(e.Host) > MaxHostnameLength || e.Host != strings.ToLower(e.Host) || validateLabels(e.Host, true) != "" {
			t.Fatalf("ParseEntry(%q) accepted malformed host %q", raw, e.Host)
		}
		if canonicalName(e.Host) != e.Host {
			t.Fatalf("matcher would normalize accepted host %q to %q", e.Host, canonicalName(e.Host))
		}
		if e.Kind == KindWildcard && isPublicSuffix(e.Host) {
			t.Fatalf("ParseEntry(%q) accepted a wildcard on public suffix %q", raw, e.Host)
		}
	})
}

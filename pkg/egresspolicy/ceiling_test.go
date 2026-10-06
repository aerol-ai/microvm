package egresspolicy

import (
	"errors"
	"strings"
	"testing"
)

// TestCeilingFits covers the PC-2 coverage rules (EF-80).
func TestCeilingFits(t *testing.T) {
	c, err := NewCeiling([]string{"*.corp.example.com", "pypi.org", "github.com:22", "10.0.0.0/8", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		spec    Spec
		outside string // "" = fits; "-" = shape error with no entry
	}{
		{"host_under_ceiling_wildcard", Spec{AllowOut: []string{"api.corp.example.com"}}, ""},
		{"deep_host_under_ceiling_wildcard", Spec{AllowOut: []string{"a.b.corp.example.com"}}, ""},
		{"apex_not_under_its_wildcard", Spec{AllowOut: []string{"corp.example.com"}}, "corp.example.com"},
		{"same_wildcard", Spec{AllowOut: []string{".corp.example.com"}}, ""},
		{"narrower_wildcard", Spec{AllowOut: []string{"*.eu.corp.example.com"}}, ""},
		{"broader_wildcard", Spec{AllowOut: []string{"*.example.com"}}, "*.example.com"},
		{"exact_host", Spec{AllowOut: []string{"pypi.org"}}, ""},
		{"host_port_covered_by_bare_host", Spec{AllowOut: []string{"pypi.org:8080"}}, ""},
		{"ceiling_port_does_not_cover_web_ports", Spec{AllowOut: []string{"github.com"}}, "github.com"},
		{"ceiling_port_covers_same_port", Spec{AllowOut: []string{"github.com:22"}}, ""},
		{"ceiling_port_not_other_port", Spec{AllowOut: []string{"github.com:2222"}}, "github.com:2222"},
		{"wildcard_host_port", Spec{AllowOut: []string{"*.corp.example.com:8443"}}, ""},
		{"cidr_subset", Spec{AllowOut: []string{"10.1.0.0/16"}}, ""},
		{"cidr_equal", Spec{AllowOut: []string{"10.0.0.0/8"}}, ""},
		{"cidr_superset", Spec{AllowOut: []string{"10.0.0.0/7"}}, "10.0.0.0/7"},
		{"cidr_disjoint", Spec{AllowOut: []string{"192.168.0.0/24"}}, "192.168.0.0/24"},
		{"cidr_v6_subset", Spec{AllowOut: []string{"2001:db8:1::/48"}}, ""},
		{"first_uncovered_in_input_order", Spec{AllowOut: []string{"pypi.org", "evil.com", "bad.org"}}, "evil.com"},
		{"allowlist_via_deny_all_fits", Spec{AllowOut: []string{"pypi.org"}, DenyOut: []string{"0.0.0.0/0"}}, ""},
		{"deny_list_only_never_fits", Spec{DenyOut: []string{"203.0.113.0/24"}}, "-"},
		{"mixed_default_accept_never_fits", Spec{AllowOut: []string{"pypi.org"}, DenyOut: []string{"203.0.113.0/24"}}, "-"},
		{"open_never_fits", Spec{}, "-"},
		{"block_all_fits", Spec{BlockAll: true, AllowOut: []string{"evil.com"}}, ""},
		{"learn_fits_ceiling_is_its_allowlist", Spec{Mode: ModeLearn}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Fits(mustCompile(t, tc.spec))
			if tc.outside == "" {
				if err != nil {
					t.Fatalf("does not fit: %v", err)
				}
				return
			}
			var ce *CeilingError
			if !errors.As(err, &ce) || !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want *CeilingError matching ErrInvalid", err)
			}
			want := tc.outside
			if want == "-" {
				want = ""
			}
			if ce.Entry != want {
				t.Fatalf("outside entry = %q, want %q (%v)", ce.Entry, want, err)
			}
			if want != "" && !strings.Contains(err.Error(), `"`+want+`"`) {
				t.Fatalf("error %q must name the entry", err)
			}
		})
	}
}

func TestNewCeilingEdges(t *testing.T) {
	c, err := NewCeiling(nil)
	if err != nil || c != nil {
		t.Fatalf("empty ceiling = %v, %v; want nil (no ceiling)", c, err)
	}
	if err := c.Fits(mustCompile(t, Spec{})); err != nil {
		t.Fatalf("no ceiling must fit everything: %v", err)
	}
	if _, err := NewCeiling([]string{"*.com"}); err == nil || !strings.Contains(err.Error(), "ceiling.allow_out") {
		t.Fatalf("invalid ceiling entry: %v", err)
	}
	if got := (&CeilingError{Reason: "r"}).Error(); got != "outside the operator egress ceiling: r" {
		t.Fatalf("shape error message = %q", got)
	}
	if (&Ceiling{}).covers(Entry{}) {
		t.Fatal("a zero entry is never covered")
	}
}

package models

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeCustomDomain(t *testing.T) {
	const base = "aerol.cloud"

	type want struct {
		out    string
		errSub string // substring expected in the error; "" means no error
	}

	cases := []struct {
		name string
		in   string
		want want
	}{
		{"plain subdomain", "api.acme.com", want{out: "api.acme.com"}},
		{"trailing dot stripped", "api.acme.com.", want{out: "api.acme.com"}},
		{"uppercase folded", "API.Acme.COM", want{out: "api.acme.com"}},
		{"leading/trailing whitespace", "  api.acme.com  ", want{out: "api.acme.com"}},
		{"apex (two labels)", "acme.com", want{out: "acme.com"}},

		{"empty rejected", "", want{errSub: "empty hostname"}},
		{"whitespace only rejected", "   ", want{errSub: "empty hostname"}},
		{"single label rejected", "localdev", want{errSub: "not a public hostname"}},
		{"localhost rejected", "localhost", want{errSub: "reserved local name"}},
		{"trailing .local rejected", "my-box.local", want{errSub: "reserved local name"}},
		{"ipv4 literal rejected", "192.168.1.1", want{errSub: "IP literal"}},
		{"ipv6 literal rejected", "::1", want{errSub: "IP literal"}},

		{"label with hyphen ok", "ap-i.acme.com", want{out: "ap-i.acme.com"}},
		{"label leading hyphen rejected", "-api.acme.com", want{errSub: "must not start or end with '-'"}},
		{"label trailing hyphen rejected", "api-.acme.com", want{errSub: "must not start or end with '-'"}},
		{"label invalid char rejected", "api_v2.acme.com", want{errSub: "invalid character"}},

		// Boundary: label exactly 63 / 64 chars
		{"label 63 chars ok", strings.Repeat("a", 63) + ".acme.com", want{out: strings.Repeat("a", 63) + ".acme.com"}},
		{"label 64 chars rejected", strings.Repeat("a", 64) + ".acme.com", want{errSub: "exceeds 63 characters"}},

		// Boundary: total 253 / 254
		{
			name: "total 253 chars ok",
			in:   strings.Repeat("a", 49) + "." + strings.Repeat("b", 49) + "." + strings.Repeat("c", 49) + "." + strings.Repeat("d", 49) + "." + strings.Repeat("e", 53),
			want: want{out: strings.Repeat("a", 49) + "." + strings.Repeat("b", 49) + "." + strings.Repeat("c", 49) + "." + strings.Repeat("d", 49) + "." + strings.Repeat("e", 53)},
		},
		{
			name: "total > 253 rejected",
			in:   strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + "." + strings.Repeat("e", 60),
			want: want{errSub: "exceeds 253 characters"},
		},

		// Base-domain rejection — both the apex and any child of it.
		{"base-domain apex rejected", "aerol.cloud", want{errSub: "under the deployment base domain"}},
		{"base-domain child rejected", "sb-xyz.aerol.cloud", want{errSub: "under the deployment base domain"}},
		{"base-domain trailing dot still rejected", "sb-xyz.aerol.cloud.", want{errSub: "under the deployment base domain"}},
		{"unrelated tld ok", "aerol.cloud.evil.com", want{out: "aerol.cloud.evil.com"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeCustomDomain(tc.in, base)
			if tc.want.errSub == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.want.out {
					t.Fatalf("got %q, want %q", got, tc.want.out)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil (out=%q)", tc.want.errSub, got)
			}
			if !errors.Is(err, ErrCustomDomainInvalid) {
				t.Fatalf("expected ErrCustomDomainInvalid, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want.errSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want.errSub)
			}
		})
	}
}

func TestNormalizeCustomDomain_EmptyBaseDomain(t *testing.T) {
	// IP-mode deployments pass baseDomain="". Validation still runs against
	// the hostname shape so the IP-mode 412 gate is not the only defense.
	got, err := NormalizeCustomDomain("api.acme.com", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "api.acme.com" {
		t.Fatalf("got %q, want %q", got, "api.acme.com")
	}
	// Base-domain rejection rule must not fire when base is empty.
	if _, err := NormalizeCustomDomain("anything.under.no.base", ""); err != nil {
		t.Fatalf("unexpected error with empty base: %v", err)
	}
}

func TestValidateCustomDomainList(t *testing.T) {
	const base = "aerol.cloud"

	t.Run("empty input is nil result", func(t *testing.T) {
		out, err := ValidateCustomDomainList(nil, base)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != nil {
			t.Fatalf("got %v, want nil", out)
		}
	})

	t.Run("canonicalizes and dedupes", func(t *testing.T) {
		out, err := ValidateCustomDomainList([]string{"api.ACME.com", "api.acme.com.", "other.acme.com"}, base)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(out) != 2 {
			t.Fatalf("got %v, want 2 entries after dedupe", out)
		}
		if out[0] != "api.acme.com" || out[1] != "other.acme.com" {
			t.Fatalf("got %v, want [api.acme.com other.acme.com]", out)
		}
	})

	t.Run("per-request cap rejected", func(t *testing.T) {
		over := []string{"a.x.com", "b.x.com", "c.x.com", "d.x.com", "e.x.com", "f.x.com"}
		_, err := ValidateCustomDomainList(over, base)
		if !errors.Is(err, ErrCustomDomainPerRequestCap) {
			t.Fatalf("got %v, want ErrCustomDomainPerRequestCap", err)
		}
	})

	t.Run("first invalid bubbles up", func(t *testing.T) {
		_, err := ValidateCustomDomainList([]string{"api.acme.com", "bad_label.acme.com"}, base)
		if !errors.Is(err, ErrCustomDomainInvalid) {
			t.Fatalf("got %v, want ErrCustomDomainInvalid", err)
		}
	})

	t.Run("base-domain entry rejected in list", func(t *testing.T) {
		_, err := ValidateCustomDomainList([]string{"sb-abc.aerol.cloud"}, base)
		if !errors.Is(err, ErrCustomDomainInvalid) {
			t.Fatalf("got %v, want ErrCustomDomainInvalid", err)
		}
	})
}

func TestValidateCustomDomainTargetPort(t *testing.T) {
	if err := ValidateCustomDomainTargetPort(0); err != nil {
		t.Errorf("port 0: %v", err)
	}
	if err := ValidateCustomDomainTargetPort(80); err != nil {
		t.Errorf("port 80: %v", err)
	}
	if err := ValidateCustomDomainTargetPort(65535); err != nil {
		t.Errorf("port 65535: %v", err)
	}
	if err := ValidateCustomDomainTargetPort(-1); err == nil {
		t.Error("port -1: want error")
	}
	if err := ValidateCustomDomainTargetPort(65536); err == nil {
		t.Error("port 65536: want error")
	}
}

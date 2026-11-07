package config

import (
	"strings"
	"testing"
)

// TestIdentityIssuerURL: SB_IDENTITY_ISSUER_URL is canonicalised, and one the
// clouds could not use (not HTTPS, or with a path) stops the daemon at boot
// instead of failing later as an AssumeRoleWithWebIdentity error in a
// customer's account (plans/sandbox-cloud-identity.md D1.1).
func TestIdentityIssuerURL(t *testing.T) {
	for _, tc := range []struct {
		name, value, want, wantErr string
	}{
		{name: "unset is off", value: ""},
		{name: "canonical", value: " https://API.example.com/ ", want: "https://api.example.com"},
		{name: "with a port", value: "https://api.example.com:8443", want: "https://api.example.com:8443"},
		{name: "http", value: "http://api.example.com", wantErr: "SB_IDENTITY_ISSUER_URL"},
		{name: "a path", value: "https://api.example.com/identity", wantErr: "no path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "pat-token")
			t.Setenv("SB_ENTERPRISE_MODE", "false")
			t.Setenv("SB_IDENTITY_ISSUER_URL", tc.value)
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || cfg.IdentityIssuerURL != tc.want {
				t.Fatalf("IdentityIssuerURL = %q, %v; want %q", cfg.IdentityIssuerURL, err, tc.want)
			}
		})
	}
}

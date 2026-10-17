package config

import (
	"strings"
	"testing"
)

// TestITestIdentityFileBootGuards is the D4 boot-guard table: the test-only
// static token file is refused next to sandboxd's own identity and in
// enterprise mode, and otherwise loads exactly as before (T3 deletes it).
func TestITestIdentityFileBootGuards(t *testing.T) {
	cases := []struct {
		name       string
		identity   string
		enterprise bool
		itestFile  string
		wantErr    string
	}{
		{name: "neither set", identity: ""},
		{name: "identity on alone", identity: "true"},
		{name: "itest file alone still works", itestFile: "/tmp/itest-identity"},
		{name: "identity off explicitly with itest file", identity: "false", itestFile: "/tmp/itest-identity"},
		{name: "identity on plus itest file", identity: "true", itestFile: "/tmp/itest-identity", wantErr: "cannot be combined with SB_IDENTITY_ENABLED=true"},
		{name: "enterprise plus itest file", enterprise: true, itestFile: "/tmp/itest-identity", wantErr: "refused when SB_ENTERPRISE_MODE=true"},
		{name: "enterprise plus identity plus itest file", enterprise: true, identity: "true", itestFile: "/tmp/itest-identity", wantErr: "SB_ITEST_IDENTITY_FILE is test-only"},
		{name: "blank itest file is unset", identity: "true", itestFile: "   "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_IDENTITY_ENABLED", tc.identity)
			t.Setenv("SB_ITEST_IDENTITY_FILE", tc.itestFile)
			if tc.enterprise {
				setSecureEnterpriseEnv(t)
			} else {
				t.Setenv("SB_ENTERPRISE_MODE", "false")
				t.Setenv("SB_PAT_TOKEN", "pat-token")
			}
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.IdentityEnabled != (tc.identity == "true") {
				t.Fatalf("IdentityEnabled = %v", cfg.IdentityEnabled)
			}
			if cfg.ITestIdentityFile != strings.TrimSpace(tc.itestFile) {
				t.Fatalf("ITestIdentityFile = %q", cfg.ITestIdentityFile)
			}
		})
	}
}

// Identity is off unless asked for (L8).
func TestIdentityDefaultsOff(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "pat-token")
	t.Setenv("SB_ENTERPRISE_MODE", "false")
	t.Setenv("SB_IDENTITY_ENABLED", "")
	t.Setenv("SB_ITEST_IDENTITY_FILE", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IdentityEnabled || cfg.ITestIdentityFile != "" {
		t.Fatalf("identity defaults: enabled=%v itest=%q", cfg.IdentityEnabled, cfg.ITestIdentityFile)
	}
}

// setSecureEnterpriseEnv is the smallest environment enterprise mode accepts.
func setSecureEnterpriseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SB_ENTERPRISE_MODE", "true")
	t.Setenv("SB_ENABLE_CLUSTER", "false")
	t.Setenv("SB_PAT_TOKEN", strings.Repeat("x", minEnterpriseCredentialBytes))
	t.Setenv("SB_SECRET_AUDIT_EXTERNAL_WITNESS", "true")
	t.Setenv("SB_SECRET_AUDIT_EXPORT_URL", "https://audit.example/export")
	t.Setenv("SB_SECRET_AUDIT_EXPORT_BEARER_TOKEN", strings.Repeat("e", minEnterpriseCredentialBytes))
}

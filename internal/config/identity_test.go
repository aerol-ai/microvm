package config

import (
	"strings"
	"testing"
	"time"
)

// Identity is off unless asked for (L8), and the token mirror and lifetime
// settings take the plan's defaults (setup/config-defaults.md).
func TestIdentityDefaults(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "pat-token")
	t.Setenv("SB_ENTERPRISE_MODE", "false")
	t.Setenv("SB_IDENTITY_ENABLED", "")
	t.Setenv("SB_IDENTITY_SYNC_INTERVAL", "")
	t.Setenv("SB_IDENTITY_MAX_STALE", "")
	t.Setenv("SB_TOKEN_MAX_TTL", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IdentityEnabled {
		t.Fatal("identity must default off")
	}
	if cfg.IdentitySyncInterval != 5*time.Second || cfg.IdentityMaxStale != 60*time.Second || cfg.TokenMaxTTL != 365*24*time.Hour {
		t.Fatalf("defaults: sync=%v stale=%v ttl=%v", cfg.IdentitySyncInterval, cfg.IdentityMaxStale, cfg.TokenMaxTTL)
	}
}

// TestIdentitySettings is the boot table for the T3 settings: a strict
// token lifetime (days allowed), the enterprise 90-day cap, and a mirror
// that gets at least one poll before it counts as stale.
func TestIdentitySettings(t *testing.T) {
	cases := []struct {
		name       string
		enterprise bool
		env        map[string]string
		wantTTL    time.Duration
		wantErr    string
	}{
		{name: "days", env: map[string]string{"SB_TOKEN_MAX_TTL": "30d"}, wantTTL: 30 * 24 * time.Hour},
		{name: "hours", env: map[string]string{"SB_TOKEN_MAX_TTL": "720h"}, wantTTL: 720 * time.Hour},
		{name: "garbage refused, not defaulted", env: map[string]string{"SB_TOKEN_MAX_TTL": "forever"}, wantErr: "SB_TOKEN_MAX_TTL"},
		{name: "zero refused", env: map[string]string{"SB_TOKEN_MAX_TTL": "0s"}, wantErr: "SB_TOKEN_MAX_TTL"},
		{name: "enterprise default is 90 days", enterprise: true, wantTTL: 90 * 24 * time.Hour},
		{name: "enterprise accepts a shorter cap", enterprise: true, env: map[string]string{"SB_TOKEN_MAX_TTL": "7d"}, wantTTL: 7 * 24 * time.Hour},
		{name: "enterprise refuses a longer cap", enterprise: true, env: map[string]string{"SB_TOKEN_MAX_TTL": "365d"}, wantErr: "at most 2160h0m0s"},
		{name: "sync interval must be positive", env: map[string]string{"SB_IDENTITY_SYNC_INTERVAL": "-1s"}, wantErr: "SB_IDENTITY_SYNC_INTERVAL"},
		{name: "stale shorter than a poll", env: map[string]string{"SB_IDENTITY_SYNC_INTERVAL": "10s", "SB_IDENTITY_MAX_STALE": "5s"}, wantErr: "SB_IDENTITY_MAX_STALE"},
		{name: "custom mirror timings", env: map[string]string{"SB_IDENTITY_SYNC_INTERVAL": "2s", "SB_IDENTITY_MAX_STALE": "20s"}, wantTTL: 365 * 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"SB_TOKEN_MAX_TTL", "SB_IDENTITY_SYNC_INTERVAL", "SB_IDENTITY_MAX_STALE"} {
				t.Setenv(k, "")
			}
			if tc.enterprise {
				setSecureEnterpriseEnv(t)
			} else {
				t.Setenv("SB_ENTERPRISE_MODE", "false")
				t.Setenv("SB_PAT_TOKEN", "pat-token")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
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
			if cfg.TokenMaxTTL != tc.wantTTL {
				t.Fatalf("TokenMaxTTL = %v, want %v", cfg.TokenMaxTTL, tc.wantTTL)
			}
		})
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

package config

import (
	"strings"
	"testing"
)

// SB_REMOTE_UPGRADE (plans/kubectl-style-cluster-ops.md D15, eng D4): on by
// default, off by default in enterprise mode, an explicit value always wins,
// and a typo is refused rather than read as either default.
func TestRemoteUpgradeConfig(t *testing.T) {
	cases := []struct {
		name       string
		enterprise bool
		value      string // "" leaves SB_REMOTE_UPGRADE unset
		want       bool
		wantErr    string
	}{
		{name: "default on", want: true},
		{name: "turned off", value: "false", want: false},
		{name: "turned on explicitly", value: "true", want: true},
		{name: "enterprise default off", enterprise: true, want: false},
		{name: "enterprise opts in", enterprise: true, value: "true", want: true},
		{name: "enterprise explicit off", enterprise: true, value: "0", want: false},
		{name: "whitespace around a value", value: " FALSE ", want: false},
		{name: "a typo is refused", value: "yes please", wantErr: "SB_REMOTE_UPGRADE must be true or false"},
		{name: "a typo is refused in enterprise mode too", enterprise: true, value: "off-ish", wantErr: "SB_REMOTE_UPGRADE must be true or false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_REMOTE_UPGRADE", tc.value)
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
			if cfg.RemoteUpgrade != tc.want || cfg.RemoteUpgradeEnabled() != tc.want {
				t.Fatalf("RemoteUpgrade = %v, RemoteUpgradeEnabled() = %v, want %v", cfg.RemoteUpgrade, cfg.RemoteUpgradeEnabled(), tc.want)
			}
		})
	}
}

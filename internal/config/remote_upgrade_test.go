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
			if cfg.UpgradeServeMBPS != DefaultUpgradeServeMBPS {
				t.Fatalf("UpgradeServeMBPS = %d, want the default %d", cfg.UpgradeServeMBPS, DefaultUpgradeServeMBPS)
			}
			if cfg.RemoteUpgrade != tc.want || cfg.RemoteUpgradeEnabled() != tc.want {
				t.Fatalf("RemoteUpgrade = %v, RemoteUpgradeEnabled() = %v, want %v", cfg.RemoteUpgrade, cfg.RemoteUpgradeEnabled(), tc.want)
			}
		})
	}
}

// SB_UPGRADE_SERVE_MBPS (CEO D15): 200 MB/s by default, a positive whole
// number otherwise, and a typo is refused.
func TestUpgradeServeMBPSConfig(t *testing.T) {
	for _, tc := range []struct {
		value   string
		want    int
		wantErr bool
	}{{"", DefaultUpgradeServeMBPS, false}, {"50", 50, false}, {" 1000 ", 1000, false}, {"0", 0, true}, {"-5", 0, true}, {"fast", 0, true}, {"100001", 0, true}} {
		t.Setenv("SB_UPGRADE_SERVE_MBPS", tc.value)
		t.Setenv("SB_ENTERPRISE_MODE", "false")
		t.Setenv("SB_PAT_TOKEN", "pat-token")
		cfg, err := Load()
		if tc.wantErr {
			if err == nil || !strings.Contains(err.Error(), "SB_UPGRADE_SERVE_MBPS") {
				t.Fatalf("%q: err = %v", tc.value, err)
			}
			continue
		}
		if err != nil || cfg.UpgradeServeMBPS != tc.want {
			t.Fatalf("%q: %d %v, want %d", tc.value, cfg.UpgradeServeMBPS, err, tc.want)
		}
	}
}

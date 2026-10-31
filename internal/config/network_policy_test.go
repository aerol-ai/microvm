package config

import "testing"

// SB_ALLOW_UNENFORCED_NETWORK_POLICY defaults to false, so a node whose host
// firewall is off refuses network policy unless the operator opts in.
func TestLoadAllowUnenforcedNetworkPolicy(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{name: "default fails closed", env: nil, want: false},
		{name: "default with rules off", env: map[string]string{"SB_ENABLE_NETWORK_RULES": "false"}, want: false},
		{name: "local development opt-in", env: map[string]string{"SB_ENABLE_NETWORK_RULES": "false", "SB_ALLOW_UNENFORCED_NETWORK_POLICY": "true"}, want: true},
		{name: "explicit off", env: map[string]string{"SB_ALLOW_UNENFORCED_NETWORK_POLICY": "false"}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			t.Setenv("SB_ALLOW_UNENFORCED_NETWORK_POLICY", "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.AllowUnenforcedNetworkPolicy != tc.want {
				t.Fatalf("AllowUnenforcedNetworkPolicy = %v, want %v", cfg.AllowUnenforcedNetworkPolicy, tc.want)
			}
		})
	}
}

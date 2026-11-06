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

// SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT is off unless set, and refuses to boot
// on a node whose host firewall is off: that firewall is what enforces it.
func TestLoadEgressBlockPrivateByDefault(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		want    bool
		wantErr bool
	}{
		{name: "default off", env: nil, want: false},
		{name: "on", env: map[string]string{"SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT": "true"}, want: true},
		{name: "on without the firewall", env: map[string]string{"SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT": "true", "SB_ENABLE_NETWORK_RULES": "false"}, wantErr: true},
		{name: "off without the firewall", env: map[string]string{"SB_ENABLE_NETWORK_RULES": "false"}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			t.Setenv("SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT", "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg, err := Load()
			if tc.wantErr {
				if err == nil {
					t.Fatal("want a boot error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.EgressBlockPrivateByDefault != tc.want {
				t.Fatalf("EgressBlockPrivateByDefault = %v, want %v", cfg.EgressBlockPrivateByDefault, tc.want)
			}
		})
	}
}

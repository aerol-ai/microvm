package config

import (
	"strings"
	"testing"
)

// C3: the containerd sandbox range is unset unless given, and a given range
// must be an IPv4 network address between /8 and /24.
func TestContainerdBridgeSubnetConfig(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "tok")
	t.Setenv("SB_PUBLIC_HOST", "127.0.0.1")
	t.Setenv("SB_DB_PATH", t.TempDir()+"/db.sqlite")
	t.Setenv("SB_CONTAINER_RUNTIME", "docker")
	t.Setenv("SB_TOOLBOX_BINARY_PATH", t.TempDir()+"/toolboxd")
	for _, tc := range []struct{ value, want, err string }{
		{value: ""},
		{value: "10.200.0.0/16", want: "10.200.0.0/16"},
		{value: " 172.31.0.0/20 ", want: "172.31.0.0/20"},
		{value: "10.0.0.0/8", want: "10.0.0.0/8"},
		{value: "192.168.7.0/24", want: "192.168.7.0/24"},
		{value: "10.200.3.4/16", err: "is not a network address; did you mean 10.200.0.0/16?"},
		{value: "10.200.0.0/25", err: "must be between /8 and /24"},
		{value: "10.0.0.0/7", err: "must be between /8 and /24"},
		{value: "fd00::/64", err: "must be an IPv4 range"},
		{value: "10.200.0.0", err: "must be an IPv4 range"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("SB_CONTAINERD_BRIDGE_SUBNET", tc.value)
			cfg, err := Load()
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("Load() error = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil || cfg.ContainerdBridgeSubnet != tc.want {
				t.Fatalf("= %q %v, want %q", cfg.ContainerdBridgeSubnet, err, tc.want)
			}
		})
	}
}

package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestEgressRangesLoad (C24): the deny floor and the extra private ranges
// load from their settings, and a node with a wrong list refuses to boot.
func TestEgressRangesLoad(t *testing.T) {
	t.Setenv("SB_ENABLE_CLUSTER", "false")
	t.Setenv("SB_PAT_TOKEN", "test-token")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EgressDenyFloorCIDRs != nil || cfg.EgressPrivateDefaultCIDRs != nil {
		t.Fatalf("defaults: %v %v", cfg.EgressDenyFloorCIDRs, cfg.EgressPrivateDefaultCIDRs)
	}

	t.Setenv("SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT", "true")
	t.Setenv("SB_EGRESS_DENY_FLOOR_CIDRS", "10.96.0.1, 172.18.0.2/32")
	t.Setenv("SB_EGRESS_PRIVATE_DEFAULT_CIDRS", "10.244.0.0/16,10.96.0.0/12, 198.18.0.0/15")
	if cfg, err = Load(); err != nil {
		t.Fatal(err)
	}
	pfx := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	if !slices.Equal(cfg.EgressDenyFloorCIDRs, pfx("10.96.0.1/32", "172.18.0.2/32")) {
		t.Fatalf("floor = %v", cfg.EgressDenyFloorCIDRs)
	}
	if !slices.Equal(cfg.EgressPrivateDefaultCIDRs, pfx("10.244.0.0/16", "10.96.0.0/12", "198.18.0.0/15")) {
		t.Fatalf("private = %v", cfg.EgressPrivateDefaultCIDRs)
	}

	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "a floor entry that is not an address", env: map[string]string{"SB_EGRESS_DENY_FLOOR_CIDRS": "kubernetes.default"}, want: "invalid SB_EGRESS_DENY_FLOOR_CIDRS entry"},
		{name: "a floor entry with host bits", env: map[string]string{"SB_EGRESS_DENY_FLOOR_CIDRS": "10.96.0.1/12"}, want: "did you mean 10.96.0.0/12"},
		{name: "a floor of everything", env: map[string]string{"SB_EGRESS_DENY_FLOOR_CIDRS": "0.0.0.0/0"}, want: "covers every address"},
		{name: "a private range that is not a CIDR", env: map[string]string{"SB_EGRESS_PRIVATE_DEFAULT_CIDRS": "10.244.0.0/40"}, want: "invalid SB_EGRESS_PRIVATE_DEFAULT_CIDRS entry"},
		{name: "private ranges without the default", env: map[string]string{"SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT": "false"}, want: "needs SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT=true"},
		{name: "the host firewall off", env: map[string]string{"SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT": "false", "SB_EGRESS_PRIVATE_DEFAULT_CIDRS": "", "SB_ENABLE_NETWORK_RULES": "false"}, want: "need SB_ENABLE_NETWORK_RULES=true"},
		{name: "a floor entry inside the sandbox range", env: map[string]string{"SB_CONTAINERD_BRIDGE_SUBNET": "10.96.0.0/16"}, want: "SB_EGRESS_DENY_FLOOR_CIDRS entry 10.96.0.1/32 overlaps the sandbox range 10.96.0.0/16 (SB_CONTAINERD_BRIDGE_SUBNET)"},
		{name: "a pod range over the sandbox range", env: map[string]string{"SB_CONTAINERD_BRIDGE_SUBNET": "10.244.8.0/24"}, want: "SB_EGRESS_PRIVATE_DEFAULT_CIDRS entry 10.244.0.0/16 overlaps the sandbox range 10.244.8.0/24"},
		{name: "a range over the Firecracker range", env: map[string]string{"SB_ENABLE_FIRECRACKER": "true", "SB_FIRECRACKER_TAP_BASE_CIDR": "198.18.0.0/20"}, want: "overlaps the sandbox range 198.18.0.0/20 (SB_FIRECRACKER_TAP_BASE_CIDR)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}

	// Sandbox ranges apart from the cluster's are fine, and a Firecracker
	// range on a node without Firecracker is not checked.
	t.Setenv("SB_CONTAINERD_BRIDGE_SUBNET", "10.200.0.0/16")
	t.Setenv("SB_FIRECRACKER_TAP_BASE_CIDR", "198.18.0.0/20")
	if _, err := Load(); err != nil {
		t.Fatalf("separate ranges: %v", err)
	}
	// The floor alone needs no private-range default.
	t.Setenv("SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT", "false")
	t.Setenv("SB_EGRESS_PRIVATE_DEFAULT_CIDRS", "")
	if cfg, err = Load(); err != nil || len(cfg.EgressDenyFloorCIDRs) != 2 {
		t.Fatalf("floor alone: %v %v", cfg.EgressDenyFloorCIDRs, err)
	}
}

// TestValidateEgressRangesBadSandboxRange: a sandbox range that does not
// parse is left to its own check, not reported as an overlap.
func TestValidateEgressRangesBadSandboxRange(t *testing.T) {
	cfg := Config{EnableNetworkRules: true, ContainerdBridgeSubnet: "nope", EgressDenyFloorCIDRs: []netip.Prefix{netip.MustParsePrefix("10.96.0.1/32")}}
	if err := validateEgressRanges(cfg); err != nil {
		t.Fatal(err)
	}
}

// TestEgressDenyFloorFile (review R4): the floor file is read at boot, a
// file that cannot be read or holds a bad entry stops the node, and it
// needs the host firewall like the other lists.
func TestEgressDenyFloorFile(t *testing.T) {
	t.Setenv("SB_ENABLE_CLUSTER", "false")
	t.Setenv("SB_PAT_TOKEN", "test-token")
	t.Setenv("SB_ENABLE_NETWORK_RULES", "true")
	dir := t.TempDir()
	path := filepath.Join(dir, "deny-floor")
	if err := os.WriteFile(path, []byte("172.18.0.44\nfd00:10:96::1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_EGRESS_DENY_FLOOR_FILE", path)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EgressDenyFloorFile != path || len(cfg.EgressDenyFloorFileCIDRs) != 2 || cfg.EgressDenyFloorFileCIDRs[0] != netip.MustParsePrefix("172.18.0.44/32") {
		t.Fatalf("file %q %v", cfg.EgressDenyFloorFile, cfg.EgressDenyFloorFileCIDRs)
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "a missing file", env: map[string]string{"SB_EGRESS_DENY_FLOOR_FILE": filepath.Join(dir, "missing")}, want: "SB_EGRESS_DENY_FLOOR_FILE"},
		{name: "a bad entry", env: map[string]string{"SB_EGRESS_DENY_FLOOR_FILE": bad}, want: "invalid SB_EGRESS_DENY_FLOOR_FILE " + bad + " entry"},
		{name: "the host firewall off", env: map[string]string{"SB_ENABLE_NETWORK_RULES": "false"}, want: "SB_EGRESS_DENY_FLOOR_FILE needs SB_ENABLE_NETWORK_RULES=true"},
		{name: "an entry inside the sandbox range", env: map[string]string{"SB_CONTAINERD_BRIDGE_SUBNET": "172.18.0.0/24"}, want: "SB_EGRESS_DENY_FLOOR_FILE entry 172.18.0.44/32 overlaps the sandbox range"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// loadEgressRanges reads the two lists that keep sandboxes off a cluster's
// own network (plans/kubernetes-v2-architecture.md C24):
// SB_EGRESS_DENY_FLOOR_CIDRS (never reachable; the Kubernetes API server)
// and SB_EGRESS_PRIVATE_DEFAULT_CIDRS (shut by default, opened only on
// purpose; the cluster's pod, Service and node ranges). Both are refused at
// boot when they are wrong, because a list a sandbox could slip past is
// worse than a node that does not start.
func loadEgressRanges(cfg *Config) error {
	floor, err := egresspolicy.ParseRanges(egresspolicy.DenyFloorEnv, os.Getenv(egresspolicy.DenyFloorEnv))
	if err != nil {
		return err
	}
	private, err := egresspolicy.ParseRanges(egresspolicy.PrivateRangesEnv, os.Getenv(egresspolicy.PrivateRangesEnv))
	if err != nil {
		return err
	}
	cfg.EgressDenyFloorCIDRs, cfg.EgressPrivateDefaultCIDRs = floor, private
	// The floor file (review R4): read now, so a node whose file it cannot
	// read does not start without the addresses in it.
	if path := strings.TrimSpace(os.Getenv(egresspolicy.FloorFileEnv)); path != "" {
		file, err := egresspolicy.ReadFloorFile(path)
		if err != nil {
			return err
		}
		cfg.EgressDenyFloorFile, cfg.EgressDenyFloorFileCIDRs = path, file
	}
	return validateEgressRanges(*cfg)
}

func validateEgressRanges(cfg Config) error {
	// Container, gVisor and Firecracker sandboxes get both lists from the
	// host firewall. With it off they would get neither while the WASM and
	// isolate guards held both: a rule one runtime ignores.
	if (len(cfg.EgressDenyFloorCIDRs) > 0 || len(cfg.EgressPrivateDefaultCIDRs) > 0) && !cfg.EnableNetworkRules {
		return fmt.Errorf("%s and %s need SB_ENABLE_NETWORK_RULES=true: container and Firecracker sandboxes get them from the host firewall", egresspolicy.DenyFloorEnv, egresspolicy.PrivateRangesEnv)
	}
	if cfg.EgressDenyFloorFile != "" && !cfg.EnableNetworkRules {
		return fmt.Errorf("%s needs SB_ENABLE_NETWORK_RULES=true: container and Firecracker sandboxes get the floor from the host firewall", egresspolicy.FloorFileEnv)
	}
	// The extra private ranges join the private-range default, which only
	// SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT turns on for container sandboxes.
	if len(cfg.EgressPrivateDefaultCIDRs) > 0 && !cfg.EgressBlockPrivateByDefault {
		return fmt.Errorf("%s needs SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT=true: the ranges join the private-range default, which is off", egresspolicy.PrivateRangesEnv)
	}
	// A cluster range that overlaps the sandboxes' own range is a clash, not
	// a rule: inside the pod those addresses are sandboxes, so the cluster's
	// hosts there are cut off from the worker, and a rule meant for them
	// would hit sandboxes instead. Refuse it with the reason rather than
	// start a node whose wall is aimed at the wrong addresses. Only a range
	// set here can be checked; one read from the CNI file at boot cannot.
	type named struct{ env, raw string }
	var sandboxRanges []named
	if cfg.ContainerdBridgeSubnet != "" {
		sandboxRanges = append(sandboxRanges, named{"SB_CONTAINERD_BRIDGE_SUBNET", cfg.ContainerdBridgeSubnet})
	}
	if cfg.EnableFirecracker && cfg.FirecrackerTapBaseCIDR != "" {
		sandboxRanges = append(sandboxRanges, named{"SB_FIRECRACKER_TAP_BASE_CIDR", cfg.FirecrackerTapBaseCIDR})
	}
	for _, sr := range sandboxRanges {
		r, err := netip.ParsePrefix(strings.TrimSpace(sr.raw))
		if err != nil {
			continue // its own check reports it
		}
		for i, list := range [][]netip.Prefix{cfg.EgressDenyFloorCIDRs, cfg.EgressPrivateDefaultCIDRs, cfg.EgressDenyFloorFileCIDRs} {
			for _, p := range list {
				if p.Overlaps(r) {
					return fmt.Errorf("%s entry %s overlaps the sandbox range %s (%s): inside the pod those addresses are sandboxes, not the cluster; pick a sandbox range the cluster does not use",
						[]string{egresspolicy.DenyFloorEnv, egresspolicy.PrivateRangesEnv, egresspolicy.FloorFileEnv}[i], p, r, sr.env)
				}
			}
		}
	}
	return nil
}

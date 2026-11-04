package daemon

import (
	"log/slog"
	goruntime "runtime"

	"github.com/aerol-ai/microvm/internal/config"
)

// logNetworkPolicyEnforcement tells the operator at boot what this node does
// with a container sandbox's network policy. firewallOn is the docker
// manager's Enabled(); the containerd and Firecracker managers are built
// from the same SB_ENABLE_NETWORK_RULES and host OS, so it speaks for them.
// With the firewall off the service refuses those policies (501
// network_policy_unenforced) unless SB_ALLOW_UNENFORCED_NETWORK_POLICY is
// set, and then every sandbox that gets one runs unfiltered: that is the
// warning an operator must not miss.
func logNetworkPolicyEnforcement(logger *slog.Logger, cfg config.Config, firewallOn bool) {
	switch {
	case firewallOn && cfg.AllowUnenforcedNetworkPolicy:
		logger.Info("SB_ALLOW_UNENFORCED_NETWORK_POLICY has no effect: the host firewall is on, so container network policy is enforced")
	case firewallOn:
	case cfg.AllowUnenforcedNetworkPolicy:
		logger.Warn("NETWORK POLICY NOT ENFORCED: the host firewall is off and SB_ALLOW_UNENFORCED_NETWORK_POLICY=true, "+
			"so docker and containerd sandboxes accept network_block_all, address lists, hostname rules and byte caps "+
			"that nothing enforces; their traffic is not filtered and GET shows egress_status \"unenforced\". "+
			"Local development only: never run a shared or production node like this",
			"enable_network_rules", cfg.EnableNetworkRules, "os", goruntime.GOOS)
	default:
		logger.Info("host firewall off: docker and containerd creates and updates that ask for network policy are refused (501 network_policy_unenforced); wasm and isolate sandboxes are unaffected",
			"enable_network_rules", cfg.EnableNetworkRules, "os", goruntime.GOOS)
	}
}

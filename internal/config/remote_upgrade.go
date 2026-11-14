package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// SB_REMOTE_UPGRADE says whether this node accepts an upgrade command over
// the API: the rollout leader's node route and the single-node upgrade
// route (plans/kubectl-style-cluster-ops.md §6.3, D15). Either one lets a
// fleet.admin caller run a new binary on the node, the power SSH root has
// today. Off, the node refuses those calls with remote_upgrade_disabled and
// is upgraded by hand with `sudo sandboxd upgrade node`, which this setting
// never blocks.
//
// The default is on, except in enterprise mode, where it is off unless set
// (eng D4): enterprise mode is the fail-safe profile banks run, and there a
// stolen admin token must not reach every node's binaries unless the bank
// opted in.

// loadRemoteUpgradeConfig reads SB_REMOTE_UPGRADE after SB_ENTERPRISE_MODE,
// and SB_UPGRADE_SERVE_MBPS.
// A value that does not parse is refused rather than defaulted: either
// default is the wrong one for somebody.
func (cfg *Config) loadRemoteUpgradeConfig() error {
	v, set, err := envBoolStrict("SB_REMOTE_UPGRADE")
	if err != nil {
		return err
	}
	if !set {
		v = !cfg.EnterpriseMode
	}
	cfg.RemoteUpgrade = v
	mbps := DefaultUpgradeServeMBPS
	if raw := strings.TrimSpace(os.Getenv("SB_UPGRADE_SERVE_MBPS")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > 100000 {
			return fmt.Errorf("SB_UPGRADE_SERVE_MBPS must be a whole number of MB/s from 1 to 100000, got %q", raw)
		}
		mbps = n
	}
	cfg.UpgradeServeMBPS = mbps
	switch d := strings.TrimSpace(os.Getenv("SB_UPGRADE_DRIVER")); d {
	case "", UpgradeDriverOperator:
		cfg.UpgradeDriver = d
	default:
		return fmt.Errorf("SB_UPGRADE_DRIVER must be empty or %q, got %q", UpgradeDriverOperator, d)
	}
	return nil
}

// UpgradeDriverOperator is SB_UPGRADE_DRIVER=operator: the Kubernetes
// operator upgrades this node by changing its pod's agent image (C13,
// plans/kubernetes-v2-architecture.md §13). The node answers the rollout's
// stage and apply steps with operator_driven, so the leader's walk marks its
// turn and waits for the operator instead of calling it. On a server it also
// marks the cluster Kubernetes-managed: `aerolvm upgrade apply` and
// `rollback` refuse there unless the operator sends them (eng review D6),
// so AerolCluster.spec.version stays the one place that sets the version.
// The operator sets it on every pod it makes.
const UpgradeDriverOperator = "operator"

// UpgradesByOperator reports whether the Kubernetes operator upgrades this
// node (SB_UPGRADE_DRIVER=operator).
func (c Config) UpgradesByOperator() bool { return c.UpgradeDriver == UpgradeDriverOperator }

// DefaultUpgradeServeMBPS caps one server's release-file copies at 200 MB/s
// (CEO D15): Raft keeps its 1-second heartbeat, so copies must never fill a
// server's link.
const DefaultUpgradeServeMBPS = 200

// RemoteUpgradeEnabled reports whether this node accepts upgrade commands
// over the API (SB_REMOTE_UPGRADE).
func (c Config) RemoteUpgradeEnabled() bool { return c.RemoteUpgrade }

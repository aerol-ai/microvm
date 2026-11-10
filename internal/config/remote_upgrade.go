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
	return nil
}

// DefaultUpgradeServeMBPS caps one server's release-file copies at 200 MB/s
// (CEO D15): Raft keeps its 1-second heartbeat, so copies must never fill a
// server's link.
const DefaultUpgradeServeMBPS = 200

// RemoteUpgradeEnabled reports whether this node accepts upgrade commands
// over the API (SB_REMOTE_UPGRADE).
func (c Config) RemoteUpgradeEnabled() bool { return c.RemoteUpgrade }

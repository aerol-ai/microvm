package service

import (
	"os"
	"sync"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/internal/version"
)

// nodeUpgradeState holds the single-node upgrade controller
// (plans/kubectl-style-cluster-ops.md §6.1). It is built on first use, so a
// node that never upgrades over the API pays nothing at boot.
type nodeUpgradeState struct {
	once  sync.Once
	local *nodeupgrade.Local
}

// NodeUpgrades is this node's single-node upgrade controller: uploads,
// starting `sandboxd upgrade node` in its own systemd unit, and reading the
// latest operation back. The routes call it only with cluster mode off.
func (s *Service) NodeUpgrades() *nodeupgrade.Local {
	s.nodeUpgrades.once.Do(func() {
		if s.nodeUpgrades.local == nil {
			s.nodeUpgrades.local = &nodeupgrade.Local{
				StateDir:       nodeupgrade.StateDirFor(s.cfg.DBPath),
				Host:           &nodeupgrade.SystemHost{},
				Binary:         os.Executable,
				RunningVersion: version.Version,
			}
		}
	})
	return s.nodeUpgrades.local
}

// AttachNodeUpgrades replaces the controller (tests). Call it before the
// first NodeUpgrades.
func (s *Service) AttachNodeUpgrades(l *nodeupgrade.Local) { s.nodeUpgrades.local = l }

// RemoteUpgradeEnabled reports SB_REMOTE_UPGRADE: whether this node accepts
// upgrade commands over the API at all.
func (s *Service) RemoteUpgradeEnabled() bool { return s.cfg.RemoteUpgradeEnabled() }

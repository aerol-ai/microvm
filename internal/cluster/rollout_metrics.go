package cluster

import (
	"expvar"
	"sync/atomic"

	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Rollout metrics (plans/kubectl-style-cluster-ops.md §10.1). The rollout
// gauges are read from the FSM at scrape time, so every server reports the
// same values and a follower that becomes leader needs no warm-up. expvar
// maps export positional labels: aerolvm_rollout_state{key=<state>} is 1 for
// the current state and 0 for the rest.
var (
	// rolloutMetricsSource is the FSM the rollout gauges read: the last
	// server to start in this process (one per process in production).
	rolloutMetricsSource atomic.Pointer[placementFSM]
	// activeVersionSource answers the members-below-active gauge.
	activeVersionSource atomic.Pointer[Cluster]

	rolloutStateGauge = func() *expvar.Map {
		m := expvar.NewMap("aerolvm_rollout_state")
		for _, s := range []string{
			upgradewire.StateStaging, upgradewire.StateRunning, upgradewire.StatePaused, upgradewire.StateDone,
			upgradewire.StateFailed, upgradewire.StateStopped, upgradewire.StateFinalizing, upgradewire.StateFinalized,
			upgradewire.StateRollingBack, upgradewire.StateRolledBack,
		} {
			m.Set(s, expvar.Func(func() any {
				r := rolloutOf(rolloutMetricsSource.Load())
				if r != nil && r.State == s {
					return 1
				}
				return 0
			}))
		}
		return m
	}()
	rolloutNodesGauge = func() *expvar.Map {
		m := expvar.NewMap("aerolvm_rollout_nodes")
		for _, s := range []string{
			upgradewire.NodePending, upgradewire.NodeStaged, upgradewire.NodeUpgrading, upgradewire.NodeDone,
			upgradewire.NodeFailed, upgradewire.NodeManual, upgradewire.NodeSkipped,
		} {
			m.Set(s, expvar.Func(func() any { return len(rolloutOf(rolloutMetricsSource.Load()).nodesIn(s)) }))
		}
		return m
	}()
	// rolloutStateSince is when the rollout entered its current state; the
	// "in one state for more than an hour" alert reads it. 0 with no
	// rollout.
	rolloutStateSince = expvar.NewInt("aerolvm_rollout_state_since_unix")
	// rolloutWaitingSince is when the oldest skipped or manual node
	// started waiting; the 24-hour alert reads it. 0 with none.
	rolloutWaitingSince = expvar.NewInt("aerolvm_rollout_waiting_node_since_unix")

	activeFSMOpsGauge   = expvar.NewInt("aerolvm_active_fsm_ops_version")
	membersBelowActive  = expvar.NewInt("aerolvm_members_below_active_version")
	nodeUpgradeSeconds  = expvar.NewFloat("aerolvm_node_upgrade_seconds_sum")
	nodeUpgradesTotal   = expvar.NewInt("aerolvm_node_upgrade_seconds_count")
	nodeUpgradeLast     = expvar.NewFloat("aerolvm_node_upgrade_last_seconds")
	upgradeServedBytes  = expvar.NewInt("aerolvm_upgrade_files_served_bytes_total")
	upgradeServeRefused = expvar.NewMap("aerolvm_upgrade_files_refused_total")
	upgradeFenceRefused = expvar.NewMap("aerolvm_upgrade_step_refused_total")
	// obsoleteServersRemoved counts servers taken out of Raft because they
	// run below the active version.
	obsoleteServersRemoved = expvar.NewInt("aerolvm_obsolete_servers_removed_total")
)

func init() {
	// Kept as package vars so a test can read them; referenced here so the
	// compiler keeps the registrations.
	_ = rolloutStateGauge
	_ = rolloutNodesGauge
}

func rolloutOf(f *placementFSM) *RolloutRecord {
	if f == nil {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.rollout
}

// refreshRolloutGauges updates the gauges that are not read at scrape
// time. The leader's rollout loop calls it every tick.
func (c *Cluster) refreshRolloutGauges() {
	r, active := c.fsm.rolloutView()
	activeFSMOpsGauge.Set(int64(active.FV))
	membersBelowActive.Set(int64(c.membersBelowActive()))
	if r == nil {
		rolloutStateSince.Set(0)
		rolloutWaitingSince.Set(0)
		return
	}
	rolloutStateSince.Set(r.StateUnixNano / 1e9)
	var oldest int64
	for _, n := range r.Nodes {
		if n == nil || (n.State != upgradewire.NodeSkipped && n.State != upgradewire.NodeManual) {
			continue
		}
		if oldest == 0 || n.UpdatedUnixNano < oldest {
			oldest = n.UpdatedUnixNano
		}
	}
	rolloutWaitingSince.Set(oldest / 1e9)
}

// recordNodeUpgrade counts one node step that ended done.
func recordNodeUpgrade(seconds float64) {
	if seconds < 0 {
		return
	}
	nodeUpgradeSeconds.Add(seconds)
	nodeUpgradesTotal.Add(1)
	nodeUpgradeLast.Set(seconds)
}

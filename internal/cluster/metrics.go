package cluster

import (
	"errors"
	"expvar"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/scaleobs"
)

var (
	raftApplyTotal        = expvar.NewInt("aerolvm_raft_apply_total")
	raftApplyInflight     = expvar.NewInt("aerolvm_raft_apply_inflight")
	raftApplyErrors       = expvar.NewMap("aerolvm_raft_apply_errors_total")
	raftApplyLastNanos    = expvar.NewInt("aerolvm_raft_apply_last_nanos")
	raftApplyLatency      = scaleobs.NewDurationBuckets("aerolvm_raft_apply_latency_seconds_bucket")
	raftLeaderForward     = expvar.NewInt("aerolvm_raft_leader_forward_total")
	raftLeaderForwardErrs = expvar.NewMap("aerolvm_raft_leader_forward_errors_total")
	raftLeaderForwardLast = expvar.NewInt("aerolvm_raft_leader_forward_last_nanos")
	raftLeaderForwardLat  = scaleobs.NewDurationBuckets("aerolvm_raft_leader_forward_latency_seconds_bucket")

	raftSnapshotTotal       = expvar.NewInt("aerolvm_raft_snapshot_total")
	raftSnapshotErrors      = expvar.NewMap("aerolvm_raft_snapshot_errors_total")
	raftSnapshotLastNanos   = expvar.NewInt("aerolvm_raft_snapshot_last_nanos")
	raftSnapshotLastBytes   = expvar.NewInt("aerolvm_raft_snapshot_last_bytes")
	raftSnapshotPlacements  = expvar.NewInt("aerolvm_raft_snapshot_placements_last")
	raftSnapshotLatency     = scaleobs.NewDurationBuckets("aerolvm_raft_snapshot_latency_seconds_bucket")
	raftSnapshotRestore     = expvar.NewInt("aerolvm_raft_snapshot_restore_total")
	raftSnapshotRestoreErrs = expvar.NewMap("aerolvm_raft_snapshot_restore_errors_total")
	raftSnapshotRestoreLast = expvar.NewInt("aerolvm_raft_snapshot_restore_last_nanos")

	gossipMembersTotal      = expvar.NewInt("aerolvm_gossip_members_total")
	gossipMembersAlive      = expvar.NewInt("aerolvm_gossip_members_alive")
	workerLeasesTotal       = expvar.NewInt("aerolvm_worker_leases_total")
	workerLeasesAlive       = expvar.NewInt("aerolvm_worker_leases_alive")
	workerLeaseLostTotal    = expvar.NewInt("aerolvm_worker_lease_lost_total")
	workerLeaseMaxAgeNanos  = expvar.NewInt("aerolvm_worker_lease_max_age_nanos")
	workerLeaseRefreshNanos = expvar.NewInt("aerolvm_worker_lease_refresh_unix_nanos")

	ownerForwardTotal        = expvar.NewInt("aerolvm_owner_forward_total")
	ownerForwardErrors       = expvar.NewMap("aerolvm_owner_forward_errors_total")
	ownerForwardLastNanos    = expvar.NewInt("aerolvm_owner_forward_last_nanos")
	ownerForwardLatency      = scaleobs.NewDurationBuckets("aerolvm_owner_forward_latency_seconds_bucket")
	ownerForwardStale421     = expvar.NewInt("aerolvm_owner_forward_stale_421_total")
	ownerForwardTargetMisses = expvar.NewMap("aerolvm_owner_forward_target_misses_total")

	clusterReservationsExpired = expvar.NewInt("aerolvm_cluster_reservations_expired_total")

	// Failover-recreate observability. Recreate outcome used to live only in
	// logs and the in-memory recreateFailureTracker, so operators had no time
	// series for "how often does failover fire across the fleet, and how often
	// does it fail". recreate_errors feeds the
	// maxRecreateFailuresBeforeReassign escalation, so a rising error rate is
	// the leading indicator of a reassign storm. reassign covers both paths
	// that hand a placement to a new owner: the stuck-placement escalation
	// (owner_watcher.go) and the dead-owner sweep (dead_owner.go).
	clusterFailoverRecreateTotal  = expvar.NewInt("aerolvm_cluster_failover_recreate_total")
	clusterFailoverRecreateErrors = expvar.NewMap("aerolvm_cluster_failover_recreate_errors_total")
	clusterFailoverReassignTotal  = expvar.NewInt("aerolvm_cluster_failover_reassign_total")

	schedulerDecisions        = expvar.NewMap("aerolvm_scheduler_decisions_total")
	schedulerCandidateRejects = expvar.NewMap("aerolvm_scheduler_candidate_rejects_total")
	schedulerCandidatesLast   = expvar.NewInt("aerolvm_scheduler_candidates_last")

	placementCacheRefreshTotal = expvar.NewInt("aerolvm_placement_cache_refresh_total")
	placementCacheRefreshErrs  = expvar.NewMap("aerolvm_placement_cache_refresh_errors_total")
	placementCacheLastNanos    = expvar.NewInt("aerolvm_placement_cache_refresh_last_nanos")
	placementCacheLatency      = scaleobs.NewDurationBuckets("aerolvm_placement_cache_refresh_latency_seconds_bucket")
	placementCacheSize         = expvar.NewInt("aerolvm_placement_cache_size")
	placementShardCacheEntries = expvar.NewInt("aerolvm_placement_shard_cache_entries")
)

func beginRaftApply() func(error) {
	raftApplyInflight.Add(1)
	start := time.Now()
	return func(err error) {
		raftApplyInflight.Add(-1)
		elapsed := time.Since(start)
		raftApplyTotal.Add(1)
		raftApplyLastNanos.Set(elapsed.Nanoseconds())
		raftApplyLatency.Observe(elapsed)
		if err != nil {
			scaleobs.Add(raftApplyErrors, classifyClusterMetricError(err), 1)
		}
	}
}

func beginLeaderForwardApply() func(error) {
	start := time.Now()
	return func(err error) {
		elapsed := time.Since(start)
		raftLeaderForward.Add(1)
		raftLeaderForwardLast.Set(elapsed.Nanoseconds())
		raftLeaderForwardLat.Observe(elapsed)
		if err != nil {
			scaleobs.Add(raftLeaderForwardErrs, classifyClusterMetricError(err), 1)
		}
	}
}

func recordSnapshotPersist(elapsed time.Duration, bytes int64, placements int, err error) {
	raftSnapshotTotal.Add(1)
	raftSnapshotLastNanos.Set(elapsed.Nanoseconds())
	raftSnapshotLastBytes.Set(bytes)
	raftSnapshotPlacements.Set(int64(placements))
	raftSnapshotLatency.Observe(elapsed)
	if err != nil {
		scaleobs.Add(raftSnapshotErrors, classifyClusterMetricError(err), 1)
	}
}

func recordSnapshotRestore(elapsed time.Duration, err error) {
	raftSnapshotRestore.Add(1)
	raftSnapshotRestoreLast.Set(elapsed.Nanoseconds())
	if err != nil {
		scaleobs.Add(raftSnapshotRestoreErrs, classifyClusterMetricError(err), 1)
	}
}

func beginOwnerForward() func(error) {
	start := time.Now()
	return func(err error) {
		elapsed := time.Since(start)
		ownerForwardTotal.Add(1)
		ownerForwardLastNanos.Set(elapsed.Nanoseconds())
		ownerForwardLatency.Observe(elapsed)
		if err != nil {
			scaleobs.Add(ownerForwardErrors, classifyClusterMetricError(err), 1)
		}
	}
}

func RecordOwnerForwardStale() {
	ownerForwardStale421.Add(1)
}

func recordOwnerForwardTargetMiss(reason string) {
	scaleobs.Add(ownerForwardTargetMisses, reason, 1)
}

func recordExpiredReservation() {
	clusterReservationsExpired.Add(1)
}

// recordFailoverRecreate counts one attempt to re-materialize an opted-in
// sandbox on a new owner. Successful steady-state watcher no-ops are excluded;
// a placement that genuinely fails four times before escalating contributes
// four attempts and four errors, which is the shape operators want when tuning
// maxRecreateFailuresBeforeReassign.
func recordFailoverRecreate(err error) {
	clusterFailoverRecreateTotal.Add(1)
	if err != nil {
		scaleobs.Add(clusterFailoverRecreateErrors, classifyClusterMetricError(err), 1)
	}
}

// recordFailoverReassign counts one placement handed to a different owner.
// Only the leader's apply wrapper calls this after the FSM reports a changed
// placement, so follower replication and successful no-ops do not overcount.
func recordFailoverReassign() {
	clusterFailoverReassignTotal.Add(1)
}

func recordSchedulerDecision(reason string, candidates int, rejects map[string]int64) {
	scaleobs.Add(schedulerDecisions, reason, 1)
	schedulerCandidatesLast.Set(int64(candidates))
	for reason, count := range rejects {
		scaleobs.Add(schedulerCandidateRejects, reason, count)
	}
}

func recordPlacementCacheRefresh(elapsed time.Duration, size int, shardEntries int, err error) {
	placementCacheRefreshTotal.Add(1)
	placementCacheLastNanos.Set(elapsed.Nanoseconds())
	placementCacheLatency.Observe(elapsed)
	placementCacheSize.Set(int64(size))
	placementShardCacheEntries.Set(int64(shardEntries))
	if err != nil {
		scaleobs.Add(placementCacheRefreshErrs, classifyClusterMetricError(err), 1)
	}
}

func classifyClusterMetricError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrNotLeader) {
		return "not_leader"
	}
	if errors.Is(err, ErrNoPlacementTarget) {
		return "no_placement_target"
	}
	if errors.Is(err, ErrReservationConflict) {
		return "reservation_conflict"
	}
	if errors.Is(err, ErrNameConflict) {
		return "name_conflict"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "context deadline exceeded"), strings.Contains(msg, "timeout"), strings.Contains(msg, "timed out"):
		return "timeout"
	case strings.Contains(msg, "forwarding loop"):
		return "stale_owner"
	case strings.Contains(msg, "peer api url unknown"), strings.Contains(msg, "url unknown"):
		return "target_unknown"
	case strings.Contains(msg, "encode"):
		return "encode"
	case strings.Contains(msg, "decode"):
		return "decode"
	default:
		return "error"
	}
}

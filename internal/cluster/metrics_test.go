package cluster

import (
	"expvar"
	"strconv"
	"testing"
	"time"
)

func TestRaftApplyMetricsRecordInflightLatencyAndErrors(t *testing.T) {
	beforeTotal := raftApplyTotal.Value()
	beforeErrors := expvarMapValue(raftApplyErrors, "not_leader")
	beforeLatency := raftApplyLatency.Count()

	done := beginRaftApply()
	if got := raftApplyInflight.Value(); got < 1 {
		t.Fatalf("raft apply inflight = %d, want >= 1", got)
	}
	done(ErrNotLeader)

	if got := raftApplyTotal.Value() - beforeTotal; got != 1 {
		t.Fatalf("raft apply total delta = %d, want 1", got)
	}
	if got := expvarMapValue(raftApplyErrors, "not_leader") - beforeErrors; got != 1 {
		t.Fatalf("not_leader error delta = %d, want 1", got)
	}
	if got := raftApplyLatency.Count() - beforeLatency; got != 1 {
		t.Fatalf("latency bucket delta = %d, want 1", got)
	}
}

func TestOwnerForwardStaleMetric(t *testing.T) {
	before := ownerForwardStale421.Value()
	RecordOwnerForwardStale()
	if got := ownerForwardStale421.Value() - before; got != 1 {
		t.Fatalf("stale owner delta = %d, want 1", got)
	}
}

func TestSchedulerAndPlacementCacheMetrics(t *testing.T) {
	beforeDecision := expvarMapValue(schedulerDecisions, "remote")
	beforeReject := expvarMapValue(schedulerCandidateRejects, "capacity")
	recordSchedulerDecision("remote", 2, map[string]int64{"capacity": 3})
	if got := expvarMapValue(schedulerDecisions, "remote") - beforeDecision; got != 1 {
		t.Fatalf("scheduler remote decision delta = %d, want 1", got)
	}
	if got := expvarMapValue(schedulerCandidateRejects, "capacity") - beforeReject; got != 3 {
		t.Fatalf("scheduler capacity reject delta = %d, want 3", got)
	}
	if got := schedulerCandidatesLast.Value(); got != 2 {
		t.Fatalf("scheduler candidates last = %d, want 2", got)
	}

	beforeRefresh := placementCacheRefreshTotal.Value()
	beforeLatency := placementCacheLatency.Count()
	recordPlacementCacheRefresh(5*time.Millisecond, 42, 7, ErrNoPlacementTarget)
	if got := placementCacheRefreshTotal.Value() - beforeRefresh; got != 1 {
		t.Fatalf("placement cache refresh delta = %d, want 1", got)
	}
	if got := placementCacheSize.Value(); got != 42 {
		t.Fatalf("placement cache size = %d, want 42", got)
	}
	if got := placementShardCacheEntries.Value(); got != 7 {
		t.Fatalf("placement shard cache entries = %d, want 7", got)
	}
	if got := placementCacheLatency.Count() - beforeLatency; got != 1 {
		t.Fatalf("placement cache latency bucket delta = %d, want 1", got)
	}
	if got := expvarMapValue(placementCacheRefreshErrs, "no_placement_target"); got < 1 {
		t.Fatalf("placement cache error no_placement_target = %d, want >= 1", got)
	}
}

func expvarMapValue(m *expvar.Map, key string) int64 {
	v := m.Get(key)
	if v == nil {
		return 0
	}
	n, _ := strconv.ParseInt(v.String(), 10, 64)
	return n
}

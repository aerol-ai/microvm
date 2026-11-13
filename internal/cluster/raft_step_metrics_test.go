package cluster

import (
	"testing"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"

	"github.com/aerol-ai/microvm/internal/scaleobs"
)

func TestRaftStepTimer(t *testing.T) {
	for _, tc := range []struct {
		key  []string
		want *scaleobs.DurationBuckets
	}{
		{[]string{"raft", "commitTime"}, raftCommitLatency},
		{[]string{"raft", "leader", "dispatchLog"}, raftLeaderStoreLatency},
		{[]string{"raft", "fsm", "enqueue"}, raftFSMEnqueueLatency},
		{[]string{"raft", "rpc", "appendEntries", "storeLogs"}, raftFollowerStoreLatency},
		{[]string{"raft", "replication", "appendEntries", "rpc"}, raftAppendRPCLatency},
		// The per-peer copy raft also sends: counted once, under the label form.
		{[]string{"raft", "replication", "appendEntries", "rpc", "peer-1"}, nil},
		{[]string{"raft", "rpc", "appendEntries"}, nil},
		{[]string{"raft", "leader", "dispatchNumLogs"}, nil},
		{[]string{"raft", "fsm", "apply"}, nil},
		{[]string{"raft", "apply"}, nil},
		{[]string{"memberlist", "udp", "sent"}, nil},
		{[]string{"raft"}, nil},
		{nil, nil},
	} {
		if got := raftStepTimer(tc.key); got != tc.want {
			t.Errorf("raftStepTimer(%q) = %p, want %p", tc.key, got, tc.want)
		}
	}
}

// Once installed, raft's timers reach their histograms through go-metrics'
// process-wide functions, which is how hashicorp/raft reports them; other
// metrics go nowhere.
func TestRaftStepMetricsInstalled(t *testing.T) {
	installRaftStepMetrics()
	installRaftStepMetrics() // once per process

	store, rpc, commit := raftLeaderStoreLatency.Value("le_5ms"), raftAppendRPCLatency.Value("le_25ms"), raftCommitLatency.Value("le_1s")
	metrics.MeasureSince([]string{"raft", "leader", "dispatchLog"}, time.Now().Add(-3*time.Millisecond))
	metrics.MeasureSinceWithLabels([]string{"raft", "replication", "appendEntries", "rpc"}, time.Now().Add(-20*time.Millisecond), []metrics.Label{{Name: "peer_id", Value: "s2"}})
	metrics.AddSample([]string{"raft", "commitTime"}, 400) // 400 ms
	metrics.IncrCounter([]string{"raft", "commitTime"}, 1)
	metrics.SetGauge([]string{"raft", "leader", "dispatchNumLogs"}, 64)
	metrics.MeasureSince([]string{"memberlist", "gossip"}, time.Now())

	if got := raftLeaderStoreLatency.Value("le_5ms"); got != store+1 {
		t.Errorf("leader store le_5ms = %d, want %d", got, store+1)
	}
	if got := raftAppendRPCLatency.Value("le_25ms"); got != rpc+1 {
		t.Errorf("append rpc le_25ms = %d, want %d", got, rpc+1)
	}
	if got := raftCommitLatency.Value("le_1s"); got != commit+1 {
		t.Errorf("commit le_1s = %d, want %d (a counter must not count as a sample)", got, commit+1)
	}
}

package cluster

import (
	"sync"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"

	"github.com/aerol-ai/microvm/internal/scaleobs"
)

// raftStepBuckets start finer than the default ones: on a healthy disk one
// step of a commit (one fsync, or one round trip) takes about a millisecond,
// and the default buckets begin at 5 ms.
var raftStepBuckets = []time.Duration{
	time.Millisecond,
	2 * time.Millisecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	time.Second,
}

// The steps of a commit, from hashicorp/raft's own timings. With
// raftApplyWaitLatency (an entry's append to its FSM start) they say which
// step a slow commit spent its time in. hashicorp/raft writes the leader's
// log before it sends the entries on, so a commit is the leader's write,
// then one follower's round trip, then the hand-off to the FSM.
var (
	// The leader writing a batch of new entries to its own log: one fsync.
	raftLeaderStoreLatency = scaleobs.NewDurationBuckets("aerolvm_raft_leader_store_latency_seconds_bucket", raftStepBuckets...)
	// One AppendEntries round trip from the leader, the follower's write
	// included.
	raftAppendRPCLatency = scaleobs.NewDurationBuckets("aerolvm_raft_append_rpc_latency_seconds_bucket", raftStepBuckets...)
	// A follower writing the entries it was sent to its log: one fsync.
	raftFollowerStoreLatency = scaleobs.NewDurationBuckets("aerolvm_raft_follower_store_latency_seconds_bucket", raftStepBuckets...)
	// An entry from the leader appending it to the leader seeing it
	// committed.
	raftCommitLatency = scaleobs.NewDurationBuckets("aerolvm_raft_commit_latency_seconds_bucket", raftStepBuckets...)
	// The leader handing a committed batch to its FSM. Long when the FSM is
	// behind: the leader's loop waits here and takes no new entries.
	raftFSMEnqueueLatency = scaleobs.NewDurationBuckets("aerolvm_raft_fsm_enqueue_latency_seconds_bucket", raftStepBuckets...)
)

// raftStepTimer is the histogram for one of hashicorp/raft's timer keys, or
// nil for a key this package does not keep. It compares the parts in place:
// it runs for every metric go-metrics sees, memberlist's included.
func raftStepTimer(key []string) *scaleobs.DurationBuckets {
	if len(key) < 2 || key[0] != "raft" {
		return nil
	}
	switch len(key) {
	case 2:
		if key[1] == "commitTime" {
			return raftCommitLatency
		}
	case 3:
		switch {
		case key[1] == "leader" && key[2] == "dispatchLog":
			return raftLeaderStoreLatency
		case key[1] == "fsm" && key[2] == "enqueue":
			return raftFSMEnqueueLatency
		}
	case 4:
		switch {
		case key[1] == "rpc" && key[2] == "appendEntries" && key[3] == "storeLogs":
			return raftFollowerStoreLatency
		case key[1] == "replication" && key[2] == "appendEntries" && key[3] == "rpc":
			return raftAppendRPCLatency
		}
	}
	return nil
}

// raftStepSink keeps the timers raftStepTimer names and drops every other
// metric.
type raftStepSink struct{ metrics.BlackholeSink }

func (s *raftStepSink) AddSample(key []string, val float32) {
	s.AddSampleWithLabels(key, val, nil)
}

func (*raftStepSink) AddSampleWithLabels(key []string, val float32, _ []metrics.Label) {
	if b := raftStepTimer(key); b != nil {
		b.Observe(time.Duration(float64(val) * float64(raftStepGranularity)))
	}
}

// raftStepGranularity is the unit go-metrics divides a timer by before it
// reaches the sink.
const raftStepGranularity = time.Millisecond

var raftStepMetricsOnce sync.Once

// installRaftStepMetrics points go-metrics' process-wide sink at
// raftStepSink. go-metrics keeps one sink per process, and nothing else in
// sandboxd sets one. Its runtime metrics stay off: they call ReadMemStats,
// which stops the world, every second.
func installRaftStepMetrics() {
	raftStepMetricsOnce.Do(func() {
		_, _ = metrics.NewGlobal(&metrics.Config{
			TimerGranularity: raftStepGranularity,
			FilterDefault:    true,
		}, &raftStepSink{})
	})
}

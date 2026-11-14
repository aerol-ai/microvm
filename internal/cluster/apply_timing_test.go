package cluster

import (
	"expvar"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// buckets is a duration histogram as /debug/vars shows it.
func buckets(name string) string { return expvar.Get(name).String() }

// An applied entry records its wait from the leader's append and the FSM's
// own time; a replayed entry (appended long ago) records no wait.
func TestFSMApplyRecordsWaitAndFSMTime(t *testing.T) {
	waitBefore, fsmBefore := buckets("aerolvm_raft_apply_wait_latency_seconds_bucket"), buckets("aerolvm_raft_apply_fsm_latency_seconds_bucket")
	f := newPlacementFSM()
	data, _ := encodeCommand(command{Op: opPutWarmPool, StampUnixNano: 1, WarmPool: &WarmPoolRecord{Image: "a", Depth: 1}})
	f.Apply(&raft.Log{Index: 1, Data: data, AppendedAt: time.Now().Add(-3 * time.Millisecond)})
	if buckets("aerolvm_raft_apply_wait_latency_seconds_bucket") == waitBefore || buckets("aerolvm_raft_apply_fsm_latency_seconds_bucket") == fsmBefore {
		t.Fatal("an applied entry recorded no wait or FSM time")
	}
	waitAfter := buckets("aerolvm_raft_apply_wait_latency_seconds_bucket")
	recordFSMApply(time.Now().Add(-time.Hour), time.Now())
	recordFSMApply(time.Time{}, time.Now())
	if buckets("aerolvm_raft_apply_wait_latency_seconds_bucket") != waitAfter {
		t.Fatal("a replayed or unstamped entry counted as a wait")
	}
}

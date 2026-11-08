package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// Minimal repros for bugs the fault harness found that no open PR fixes.
// Each is skipped until a fix lands; the fixing PR deletes its t.Skip line.

// TestReserveRetryAtFullCapacityIsAccepted: a retry of a reservation that
// already committed (same id, owner and incarnation, e.g. after its answer
// was lost in a leader change) must be accepted, because the FSM applies it
// as a TTL refresh that adds no load. Admission counts the reservation's own
// pending load and then adds the retry on top, so on a full worker the retry
// is refused with ErrCapacityExceeded. The caller sees a failed create while
// its reservation holds the slot until the TTL sweep. The leader-change test
// logs this ("held although its caller got ...") in about half of its kill
// runs.
func TestReserveRetryAtFullCapacityIsAccepted(t *testing.T) {
	fc := newFaultCluster(t, "rtry", 1)
	l := fc.leader().cluster()
	fc.setLease(l.nodeID, staticCapacity(1))
	target := PlacementTarget{NodeID: l.nodeID, APIURL: l.apiURL, DataPlaneHost: l.dataPlaneHost}
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64, DiskGB: 1}
	inc := mustIncarnation(t)
	ctx := context.Background()
	if err := l.ReserveOnTarget(ctx, "sb-retry", target, spec, PlacementSecrets{IncarnationID: inc}, time.Minute); err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	if err := l.ReserveOnTarget(ctx, "sb-retry", target, spec, PlacementSecrets{IncarnationID: inc}, time.Minute); err != nil {
		t.Fatalf("retry of the same reservation on a full worker = %v, want accepted (it adds no load)", err)
	}
}

// TestPendingLoadSurvivesReadAfterExpiryThenRefresh: the pending-load index
// is replicated state, but read paths prune it with the reading server's
// clock (pruneExpiredPendingReservationsLocked, from
// pendingReservationLoadByNode and livePendingReservationCount). Once apply
// decides by the entry's time (PR #1001, C1), a server can prune a claim at
// its own time T+2 and then apply a same-owner retry the leader stamped at
// T+1, before the old expiry. Apply takes the refresh branch, and
// refreshPendingReservationExpiryLocked finds no claim to refresh: the
// reservation lives on to its new expiry while this server counts no load
// for it. If this server becomes leader it admits against that
// under-count (I4). On main read and apply both use the local clock, so the
// path cannot be reached and this test passes there.
func TestPendingLoadSurvivesReadAfterExpiryThenRefresh(t *testing.T) {
	f := newPlacementFSM()
	// An hour in the past: main applies with the wall clock, which is then
	// past every expiry below, so the repro shows only where read time and
	// apply time can differ, as they do once apply uses the entry's time.
	base := time.Now().Truncate(time.Second).Add(-time.Hour)
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64, DiskGB: 1}
	reserve := func(index uint64, at time.Time, expires int64) {
		t.Helper()
		payload, err := encodeCommand(command{
			Op: opReserve, SandboxID: "sb-prune", OwnerNodeID: "w1", Spec: spec,
			IncarnationID: "inc-1", ExpiresUnix: expires,
		})
		if err != nil {
			t.Fatal(err)
		}
		if res := f.Apply(&raft.Log{Index: index, Type: raft.LogCommand, Data: payload, AppendedAt: at}); res != nil {
			if err, ok := res.(error); ok && err != nil {
				t.Fatalf("apply %d: %v", index, err)
			}
		}
	}
	reserve(1, base, base.Unix()+1)
	// A router on this server reads pending load after the expiry second.
	f.pendingReservationLoadByNode(base.Unix() + 2)
	// The leader admitted the same create's retry before the expiry.
	reserve(2, base.Add(time.Second), base.Unix()+120)

	p, ok := f.get("sb-prune")
	if !ok || !p.IsReserved() || p.ExpiresUnix != base.Unix()+120 {
		t.Fatalf("reservation after the refresh = %v %+v, want reserved until %d", ok, p, base.Unix()+120)
	}
	load, _ := f.pendingReservationLoadByNode(base.Unix() + 2)
	if got := load["w1"]; got.CPU != 1 {
		t.Fatalf("pending load on w1 = %+v while sb-prune is reserved until %d, want CPU 1 (I4)", got, p.ExpiresUnix)
	}
	if n := f.livePendingReservationCount("w1", base.Unix()+2); n != 1 {
		t.Fatalf("live pending count on w1 = %d, want 1", n)
	}
}

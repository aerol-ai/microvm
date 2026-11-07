package cluster

import (
	"reflect"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// pendingTestSpec costs 1 CPU, so pending load reads as a reservation count.
var pendingTestSpec = &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64, DiskGB: 1}

func applyPendingReserve(t *testing.T, f *placementFSM, index uint64, id string, at time.Time, expires int64) {
	t.Helper()
	payload, err := encodeCommand(command{
		Op: opReserve, SandboxID: id, OwnerNodeID: "w1", Spec: pendingTestSpec,
		IncarnationID: "inc-" + id, ExpiresUnix: expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := f.Apply(&raft.Log{Index: index, Type: raft.LogCommand, Data: payload, AppendedAt: at}); res != nil {
		if err, ok := res.(error); ok && err != nil {
			t.Fatalf("apply %d (%s): %v", index, id, err)
		}
	}
}

func pendingCPU(f *placementFSM, now int64) int {
	load, _ := f.pendingReservationLoadByNode(now)
	return int(load["w1"].CPU)
}

// pendingIndexState is the replicated pending-load index of one server.
func pendingIndexState(f *placementFSM) (map[string]pendingReservationClaim, int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	claims := make(map[string]pendingReservationClaim, len(f.pendingReservationClaims))
	for id, c := range f.pendingReservationClaims {
		claims[id] = c
	}
	return claims, int(f.pendingReservationCapacity["w1"].CPU)
}

// Found by the offline fault harness (PR #1017, Bug B; the same repro is
// skipped there until this fix lands, under its own name). A read pruned the
// pending-load index with the reading server's clock. Once apply decides by
// the entry's time (C1), a server could prune a claim at its own time T+2,
// then apply a same-owner retry the leader stamped at T+1, before the old
// expiry: the refresh found no claim, and the reservation lived on while this
// server counted no load for it.
func TestPendingLoadKeepsARetryRefreshedAfterALaterRead(t *testing.T) {
	f := newPlacementFSM()
	base := time.Now().Truncate(time.Second).Add(-time.Hour)
	applyPendingReserve(t, f, 1, "sb-prune", base, base.Unix()+1)
	// A router on this server reads pending load after the expiry second.
	f.pendingReservationLoadByNode(base.Unix() + 2)
	// The leader admitted the same create's retry before the expiry.
	applyPendingReserve(t, f, 2, "sb-prune", base.Add(time.Second), base.Unix()+120)

	p, ok := f.get("sb-prune")
	if !ok || !p.IsReserved() || p.ExpiresUnix != base.Unix()+120 {
		t.Fatalf("reservation after the refresh = %v %+v, want reserved until %d", ok, p, base.Unix()+120)
	}
	if got := pendingCPU(f, base.Unix()+2); got != 1 {
		t.Fatalf("pending load on w1 = %d CPU while sb-prune is reserved until %d, want 1 (I4)", got, p.ExpiresUnix)
	}
	if n := f.livePendingReservationCount("w1", base.Unix()+2); n != 1 {
		t.Fatalf("live pending count on w1 = %d, want 1", n)
	}
}

// A read at any time leaves the replicated index as it was, and still
// answers with only the claims that are live at that time.
func TestPendingLoadReadsDoNotChangeTheIndex(t *testing.T) {
	f := newPlacementFSM()
	base := time.Now().Truncate(time.Second).Add(-time.Hour)
	applyPendingReserve(t, f, 1, "sb-a", base, base.Unix()+10)
	applyPendingReserve(t, f, 2, "sb-b", base, base.Unix()+20)
	// Refresh sb-a twice to the same expiry: two heap entries for one claim
	// must not subtract its load twice.
	applyPendingReserve(t, f, 3, "sb-a", base.Add(time.Second), base.Unix()+15)
	applyPendingReserve(t, f, 4, "sb-a", base.Add(2*time.Second), base.Unix()+15)

	claimsBefore, cpuBefore := pendingIndexState(f)
	cases := []struct {
		now  int64
		want int
	}{
		{base.Unix() + 5, 2},  // both live
		{base.Unix() + 15, 2}, // sb-a's last second is still live
		{base.Unix() + 16, 1}, // sb-a expired, sb-b live
		{base.Unix() + 21, 0}, // both expired
		{base.Unix() + 5, 2},  // an earlier clock after a later read: nothing was dropped
	}
	for _, tc := range cases {
		if got := pendingCPU(f, tc.now); got != tc.want {
			t.Fatalf("pending load at +%ds = %d, want %d", tc.now-base.Unix(), got, tc.want)
		}
		if got := f.livePendingReservationCount("w1", tc.now); got != tc.want {
			t.Fatalf("live count at +%ds = %d, want %d", tc.now-base.Unix(), got, tc.want)
		}
	}
	claimsAfter, cpuAfter := pendingIndexState(f)
	if !reflect.DeepEqual(claimsBefore, claimsAfter) || cpuBefore != cpuAfter {
		t.Fatalf("reads changed the index: before %v (%d CPU), after %v (%d CPU)", claimsBefore, cpuBefore, claimsAfter, cpuAfter)
	}
}

// Two servers apply the same entries but read at different times. Their
// indexes must stay equal: apply prunes by the entry's time, reads prune
// nothing.
func TestPendingLoadIndexIsTheSameOnEveryServer(t *testing.T) {
	base := time.Now().Truncate(time.Second).Add(-time.Hour)
	entries := []struct {
		id      string
		at      time.Time
		expires int64
	}{
		{"sb-1", base, base.Unix() + 5},
		{"sb-2", base.Add(time.Second), base.Unix() + 60},
		{"sb-3", base.Add(10 * time.Second), base.Unix() + 70}, // applied after sb-1 expired
	}
	var servers [2]*placementFSM
	for s := range servers {
		f := newPlacementFSM()
		for i, e := range entries {
			if s == 1 {
				// The second server reads far ahead of the leader's clock
				// between entries, the way a skewed follower would.
				f.pendingReservationLoadByNode(e.at.Unix() + 3600)
				f.livePendingReservationCount("w1", e.at.Unix()+3600)
			}
			applyPendingReserve(t, f, uint64(i+1), e.id, e.at, e.expires)
		}
		servers[s] = f
	}
	c0, cpu0 := pendingIndexState(servers[0])
	c1, cpu1 := pendingIndexState(servers[1])
	if !reflect.DeepEqual(c0, c1) || cpu0 != cpu1 {
		t.Fatalf("servers disagree: %v (%d CPU) vs %v (%d CPU)", c0, cpu0, c1, cpu1)
	}
	// The entry at +10s pruned sb-1 (expired at +5s) on both servers.
	if _, ok := c0["sb-1"]; ok || cpu0 != 2 {
		t.Fatalf("index after +10s = %v (%d CPU), want sb-2 and sb-3 only", c0, cpu0)
	}
}

// A new leader's clock can run behind the old leader's, so an entry can carry
// an earlier time than the one before it. If the later-stamped entry already
// pruned a claim, a retry stamped before the old expiry must count the
// reservation again.
func TestPendingLoadRefreshRestoresAPrunedClaim(t *testing.T) {
	f := newPlacementFSM()
	base := time.Now().Truncate(time.Second).Add(-time.Hour)
	applyPendingReserve(t, f, 1, "sb-r", base, base.Unix()+10)
	// Old leader, clock ahead: an unrelated entry at +20s prunes sb-r's claim.
	applyPendingReserve(t, f, 2, "sb-other", base.Add(20*time.Second), base.Unix()+200)
	if claims, _ := pendingIndexState(f); claims["sb-r"].OwnerNodeID != "" {
		t.Fatalf("claim for sb-r survived an entry past its expiry: %v", claims)
	}
	// New leader, clock behind: it stamps sb-r's retry at +9s, before the old
	// expiry, so apply takes the refresh branch.
	applyPendingReserve(t, f, 3, "sb-r", base.Add(9*time.Second), base.Unix()+120)

	claims, cpu := pendingIndexState(f)
	if c, ok := claims["sb-r"]; !ok || c.ExpiresUnix != base.Unix()+120 || cpu != 2 {
		t.Fatalf("after the retry: claim %v (%v), %d CPU; want sb-r counted until %d and 2 CPU", c, ok, cpu, base.Unix()+120)
	}
	if got := pendingCPU(f, base.Unix()+100); got != 2 {
		t.Fatalf("pending load at +100s = %d, want 2", got)
	}
}

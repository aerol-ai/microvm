package cluster

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// ledgerLeader is a leader with no Raft: its leadership, term and barrier are
// the test's, so a test can change the term between admissions.
type ledgerLeader struct {
	c          *Cluster
	leader     bool
	term       uint64
	barrierErr error
	// events records barriers and admission checks in order.
	events []string
}

func newLedgerLeader(members ...Member) *ledgerLeader {
	l := &ledgerLeader{leader: true, term: 1}
	l.c = slotCluster(members...)
	l.c.leaderTermHook = func() (bool, uint64) { return l.leader, l.term }
	l.c.admissionBarrierHook = func() error {
		l.events = append(l.events, fmt.Sprintf("barrier@%d", l.term))
		return l.barrierErr
	}
	return l
}

// admit runs the leader's reservation admission for cmd and returns the
// hold, as if raft took the entry at once (the hold stays until settled).
func (l *ledgerLeader) admit(cmd command) (uint64, error) {
	id, enqueued, err := l.admitNotEnqueued(cmd)
	if err == nil {
		enqueued()
	}
	return id, err
}

// admitNotEnqueued is admit for an entry raft has not taken yet: the caller
// calls enqueued.
func (l *ledgerLeader) admitNotEnqueued(cmd command) (uint64, func(), error) {
	return l.c.admitHold(cmd, func() error {
		l.events = append(l.events, "check")
		if err := l.c.admitReservationCommand(cmd); err != nil {
			return err
		}
		return l.c.admitTeamQuotaCommand(cmd)
	})
}

func (l *ledgerLeader) holds() int {
	l.c.reservationAdmissionMu.Lock()
	defer l.c.reservationAdmissionMu.Unlock()
	return len(l.c.admission.holds)
}

// applyToFSM applies cmd as a committed entry, the way raft would.
func (l *ledgerLeader) applyToFSM(t *testing.T, index uint64, cmd command) {
	t.Helper()
	payload, err := encodeCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if res := l.c.fsm.Apply(&raft.Log{Index: index, Type: raft.LogCommand, Data: payload, AppendedAt: time.Now()}); res != nil {
		if err, ok := res.(error); ok && err != nil {
			t.Fatalf("apply %v: %v", cmd.Op, err)
		}
	}
}

func ledgerReserve(id, owner, incarnation string, cpu float64) command {
	return command{
		Op: opReserve, SandboxID: id, OwnerNodeID: owner, IncarnationID: incarnation,
		Spec:        &models.CreateSandboxRequest{Image: "alpine", CPU: cpu, MemoryMB: 64},
		ExpiresUnix: time.Now().Add(2 * time.Minute).Unix(),
	}
}

// What is admitted but not yet applied counts against the worker, so a
// second create cannot take the slot of one still committing; and once the
// first is applied it counts once, as a claim, not again as a hold.
func TestAdmissionLedgerCountsInFlightCreatesOnce(t *testing.T) {
	l := newLedgerLeader(slotWorker("w1", 2, containerAndFC))
	a := ledgerReserve("sb-a", "w1", "inc-a", 1)
	idA, err := l.admit(a)
	if err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	if _, err := l.admit(ledgerReserve("sb-b", "w1", "inc-b", 1)); err != nil {
		t.Fatalf("second reserve with one slot left: %v", err)
	}
	if _, err := l.admit(ledgerReserve("sb-c", "w1", "inc-c", 1)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("third reserve while two are in flight = %v, want ErrCapacityExceeded", err)
	}
	// sb-a commits; its hold is not settled yet. It must count once.
	l.applyToFSM(t, 1, a)
	if _, err := l.admit(ledgerReserve("sb-c", "w1", "inc-c", 1)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("third reserve after sb-a applied = %v, want ErrCapacityExceeded", err)
	}
	l.c.settleHold(idA, outcomeSettled)
	if _, err := l.admit(ledgerReserve("sb-c", "w1", "inc-c", 1)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("third reserve after sb-a settled = %v, want ErrCapacityExceeded (sb-a is in the FSM, sb-b in flight)", err)
	}
	if got := l.holds(); got != 1 {
		t.Fatalf("holds = %d, want 1 (sb-b)", got)
	}
}

// The pending-create cap counts creates in flight the same way.
func TestAdmissionLedgerPendingCapCountsInFlightCreates(t *testing.T) {
	l := newLedgerLeader(slotWorker("w1", 8, containerAndFC))
	l.c.cfg.ClusterCreateMaxPendingPerWorker = 2
	for _, id := range []string{"sb-1", "sb-2"} {
		if _, err := l.admit(ledgerReserve(id, "w1", "inc-"+id, 1)); err != nil {
			t.Fatalf("%s under the cap: %v", id, err)
		}
	}
	if _, err := l.admit(ledgerReserve("sb-3", "w1", "inc-3", 1)); !errors.Is(err, ErrCreateBackpressure) {
		t.Fatalf("third create at the pending cap = %v, want ErrCreateBackpressure", err)
	}
}

// A resend of a create still in flight (same sandbox, owner, incarnation and
// size) is admitted without being counted again, and its load stays counted
// until the last copy settles. Without this a full worker refused the resend
// while the first copy committed, and the caller saw a failure for a create
// that went through.
func TestAdmissionLedgerResendOfAHeldCreateIsNotCountedTwice(t *testing.T) {
	l := newLedgerLeader(slotWorker("w1", 1, containerAndFC))
	first := ledgerReserve("sb-r", "w1", "inc-r", 1)
	id1, err := l.admit(first)
	if err != nil {
		t.Fatalf("first copy: %v", err)
	}
	id2, err := l.admit(first)
	if err != nil {
		t.Fatalf("resend while the first copy is in flight = %v, want admitted", err)
	}
	cases := []struct {
		name string
		cmd  command
	}{
		{"another sandbox", ledgerReserve("sb-other", "w1", "inc-o", 1)},
		{"same id, new incarnation", ledgerReserve("sb-r", "w1", "inc-r2", 1)},
		{"same create, bigger size", ledgerReserve("sb-r", "w1", "inc-r", 2)},
	}
	for _, tc := range cases {
		if _, err := l.admit(tc.cmd); !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("%s on the full worker = %v, want ErrCapacityExceeded", tc.name, err)
		}
	}
	// The first copy is refused by the FSM (settled), the resend is still in
	// flight: the slot stays taken.
	l.c.settleHold(id1, outcomeSettled)
	if _, err := l.admit(ledgerReserve("sb-other", "w1", "inc-o", 1)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("another sandbox while the resend is in flight = %v, want ErrCapacityExceeded", err)
	}
	l.c.settleHold(id2, outcomeSettled)
	if _, err := l.admit(ledgerReserve("sb-other", "w1", "inc-o", 1)); err != nil {
		t.Fatalf("another sandbox once both copies settled unapplied = %v, want admitted", err)
	}
}

// A resend of a create that already committed (its first answer was lost)
// is applied by the FSM as a TTL refresh. Its hold must add nothing on top of
// the committed claim, or every resend in flight would take a slot from the
// next create. (Admission of the resend itself is PR #1021's filter; this is
// about the hold it leaves while in flight.)
func TestAdmissionLedgerHoldOfACommittedCreateCountsNothing(t *testing.T) {
	l := newLedgerLeader(slotWorker("w1", 3, containerAndFC))
	x := ledgerReserve("sb-x", "w1", "inc-x", 1)
	l.applyToFSM(t, 1, x)
	if _, err := l.admit(x); err != nil {
		t.Fatalf("resend of the committed sb-x on a worker with room: %v", err)
	}
	if _, err := l.admit(ledgerReserve("sb-y", "w1", "inc-y", 1)); err != nil {
		t.Fatalf("sb-y = %v, want admitted: sb-x counts once (claim), sb-y fits", err)
	}
	if _, err := l.admit(ledgerReserve("sb-z", "w1", "inc-z", 1)); err != nil {
		t.Fatalf("sb-z = %v, want admitted: 3 slots hold sb-x, sb-y, sb-z", err)
	}
	if _, err := l.admit(ledgerReserve("sb-w", "w1", "inc-w", 1)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("sb-w = %v, want ErrCapacityExceeded", err)
	}
}

// The first admission of a leader term runs the barrier before it reads the
// FSM, and the term starts with an empty ledger. Later admissions in the term
// skip the barrier. A failed barrier admits nothing and is retried.
func TestAdmissionLedgerNewTermRunsBarrierFirstAndResets(t *testing.T) {
	l := newLedgerLeader(slotWorker("w1", 1, containerAndFC))
	l.term = 5
	if _, err := l.admit(ledgerReserve("sb-1", "w1", "inc-1", 1)); err != nil {
		t.Fatalf("term 5 first admission: %v", err)
	}
	if _, err := l.admit(ledgerReserve("sb-2", "w1", "inc-2", 1)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("term 5 second admission = %v, want ErrCapacityExceeded (sb-1 in flight)", err)
	}
	if want := []string{"barrier@5", "check", "check"}; !reflect.DeepEqual(l.events, want) {
		t.Fatalf("term 5 events = %v, want %v", l.events, want)
	}

	// A new term whose barrier fails: nothing is admitted, the old term's
	// ledger is kept, and the next admission tries the barrier again.
	l.term, l.events, l.barrierErr = 6, nil, ErrNotLeader
	if _, err := l.admit(ledgerReserve("sb-2", "w1", "inc-2", 1)); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("admission with a failing barrier = %v, want ErrNotLeader", err)
	}
	if l.c.admission.term != 5 || l.holds() != 1 {
		t.Fatalf("after a failed barrier: ledger term %d with %d holds, want term 5 with 1", l.c.admission.term, l.holds())
	}

	// The barrier passes: sb-1's hold from term 5 is gone, so sb-2 fits.
	l.barrierErr = nil
	if _, err := l.admit(ledgerReserve("sb-2", "w1", "inc-2", 1)); err != nil {
		t.Fatalf("term 6 admission after the barrier: %v", err)
	}
	if want := []string{"barrier@6", "barrier@6", "check"}; !reflect.DeepEqual(l.events, want) {
		t.Fatalf("term 6 events = %v, want %v (barrier before the first check)", l.events, want)
	}
	if l.c.admission.term != 6 || l.holds() != 1 {
		t.Fatalf("term 6 ledger: term %d with %d holds, want term 6 with only sb-2", l.c.admission.term, l.holds())
	}

	// No longer the leader: refused before any barrier or check.
	l.leader, l.events = false, nil
	if _, err := l.admit(ledgerReserve("sb-3", "w1", "inc-3", 1)); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("admission on a follower = %v, want ErrNotLeader", err)
	}
	if len(l.events) != 0 {
		t.Fatalf("a follower ran %v", l.events)
	}
}

// A term change waits until raft has taken every entry admitted before it,
// then runs its barrier. Otherwise a caller stalled between its check and
// raft.Apply across a lost and regained leadership would put its entry after
// the new term's barrier, while the reset had already dropped its hold.
func TestAdmissionLedgerTermChangeWaitsForEarlierEntriesToReachRaft(t *testing.T) {
	l := newLedgerLeader(slotWorker("w1", 4, containerAndFC))
	var mu sync.Mutex
	l.c.admissionBarrierHook = func() error {
		mu.Lock()
		defer mu.Unlock()
		l.events = append(l.events, "barrier")
		return nil
	}
	record := func(e string) {
		mu.Lock()
		defer mu.Unlock()
		l.events = append(l.events, e)
	}
	snapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), l.events...)
	}
	_, enqueued, err := l.admitNotEnqueued(ledgerReserve("sb-stalled", "w1", "inc-s", 1))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	// The leadership is lost and won again before sb-stalled reaches raft.
	l.c.reservationAdmissionMu.Lock()
	l.term = 2
	l.c.reservationAdmissionMu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, enq, err := l.c.admitHold(ledgerReserve("sb-next", "w1", "inc-n", 1), func() error { record("check"); return nil })
		if err == nil {
			enq()
		}
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	if got := snapshot(); len(got) != 2 || got[0] != "barrier" || got[1] != "check" {
		// Only the first admission's barrier and check so far.
		t.Fatalf("events before sb-stalled reached raft = %v, want the new term's barrier to wait", got)
	}
	record("sb-stalled enqueued")
	enqueued()
	enqueued() // a second call is harmless
	if err := <-done; err != nil {
		t.Fatalf("new-term admission: %v", err)
	}
	want := []string{"barrier", "check", "sb-stalled enqueued", "barrier", "check"}
	if got := snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

// A hold whose commit raft answered with an unknown outcome (leadership lost:
// the entry may still commit) keeps counting until the term changes; a hold
// whose entry raft never appended goes at once.
func TestAdmissionLedgerUnknownOutcomeCountsUntilTheTermChanges(t *testing.T) {
	l := newLedgerLeader(slotWorker("w1", 1, containerAndFC))
	id, err := l.admit(ledgerReserve("sb-lost", "w1", "inc-lost", 1))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	l.c.settleHold(id, raftApplyOutcome(raft.ErrLeadershipLost))
	if _, err := l.admit(ledgerReserve("sb-next", "w1", "inc-next", 1)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("same term, after an unknown outcome = %v, want ErrCapacityExceeded (the entry may still commit)", err)
	}
	if !l.c.admission.holds[id].unknown {
		t.Fatal("the hold is not marked unknown")
	}
	l.term++
	if _, err := l.admit(ledgerReserve("sb-next", "w1", "inc-next", 1)); err != nil {
		t.Fatalf("next term, after its barrier = %v, want admitted", err)
	}

	// Settled at once: raft never appended the entry.
	l2 := newLedgerLeader(slotWorker("w1", 1, containerAndFC))
	id, err = l2.admit(ledgerReserve("sb-gone", "w1", "inc-gone", 1))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	l2.c.settleHold(id, raftApplyOutcome(raft.ErrNotLeader))
	if _, err := l2.admit(ledgerReserve("sb-next", "w1", "inc-next", 1)); err != nil {
		t.Fatalf("after a never-appended entry = %v, want admitted", err)
	}
	// Settling a hold the term change dropped is a no-op.
	l2.c.settleHold(id, outcomeUnknown)
	l2.c.settleHold(999, outcomeSettled)
}

func TestRaftApplyOutcome(t *testing.T) {
	cases := []struct {
		err  error
		want admissionOutcome
	}{
		{nil, outcomeSettled},
		{raft.ErrNotLeader, outcomeSettled},
		{raft.ErrEnqueueTimeout, outcomeSettled},
		{raft.ErrLeadershipTransferInProgress, outcomeSettled},
		{fmt.Errorf("wrapped: %w", raft.ErrNotLeader), outcomeSettled},
		{raft.ErrLeadershipLost, outcomeUnknown},
		{raft.ErrRaftShutdown, outcomeUnknown},
		{raft.ErrAbortedByRestore, outcomeUnknown},
		{errors.New("log store: disk full"), outcomeUnknown},
	}
	for _, tc := range cases {
		if got := raftApplyOutcome(tc.err); got != tc.want {
			t.Errorf("raftApplyOutcome(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// Team quotas count in-flight creates the same way: the second create for a
// team's last slot is refused while the first is still committing, and a
// create that has been applied but not settled counts once.
func TestAdmissionLedgerTeamQuotaCountsInFlightCreatesOnce(t *testing.T) {
	l := newLedgerLeader(slotWorker("w1", 64, containerAndFC))
	l.applyToFSM(t, 1, command{Op: opPutTeamQuota, StampUnixNano: 1, TeamQuota: &TeamQuotaRecord{Team: "risk", MaxSandboxes: 2}})
	team := func(id string) command {
		cmd := ledgerReserve(id, "w1", "inc-"+id, 1)
		cmd.OwnerRef = "team:risk"
		return cmd
	}
	a := team("sb-a")
	idA, err := l.admit(a)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := l.admit(team("sb-b")); err != nil {
		t.Fatalf("second create: %v", err)
	}
	if _, err := l.admit(team("sb-c")); !errors.Is(err, ErrTeamQuotaExceeded) {
		t.Fatalf("third create with two in flight = %v, want ErrTeamQuotaExceeded", err)
	}
	// A resend of an in-flight create adds no sandbox.
	if _, err := l.admit(a); err != nil {
		t.Fatalf("resend of sb-a = %v, want admitted", err)
	}
	// sb-a applied, its hold not settled: one sandbox, not two.
	l.applyToFSM(t, 2, a)
	l.applyToFSM(t, 3, command{Op: opPutTeamQuota, StampUnixNano: 2, TeamQuota: &TeamQuotaRecord{Team: "risk", MaxSandboxes: 3}})
	if _, err := l.admit(team("sb-c")); err != nil {
		t.Fatalf("third create under a quota of 3 = %v, want admitted (sb-a must count once)", err)
	}
	if _, err := l.admit(team("sb-d")); !errors.Is(err, ErrTeamQuotaExceeded) {
		t.Fatalf("fourth create under a quota of 3 = %v, want ErrTeamQuotaExceeded", err)
	}
	l.c.settleHold(idA, outcomeSettled)
	if _, err := l.admit(team("sb-d")); !errors.Is(err, ErrTeamQuotaExceeded) {
		t.Fatalf("fourth create after sb-a settled = %v, want ErrTeamQuotaExceeded", err)
	}
}

// A shrinking resize in flight is not counted before it commits: if it then
// failed, the team would be bigger than the check assumed.
func TestHeldTeamUsageCountsGrowthOnly(t *testing.T) {
	f := newPlacementFSM()
	applyOp(t, f, command{Op: opPutTeamQuota, StampUnixNano: 1, TeamQuota: &TeamQuotaRecord{Team: "risk", MaxCPU: 4}})
	reserve := ledgerReserve("sb-big", "w1", "inc-big", 3)
	reserve.OwnerRef = "team:risk"
	applyOp(t, f, reserve)
	shrink := teamQuotaAsk{sandboxID: "sb-big", team: models.TeamOfOwnerRef("team:risk"), cpu: 1, memoryMB: 64}
	grow := teamQuotaAsk{sandboxID: "sb-new", team: shrink.team, cpu: 2, memoryMB: 64}
	if err := f.admitTeamQuotasOver([]teamQuotaAsk{shrink}, []teamQuotaAsk{grow}); !errors.Is(err, ErrTeamQuotaExceeded) {
		t.Fatalf("a 2-CPU create beside a 3-CPU sandbox whose shrink is in flight = %v, want ErrTeamQuotaExceeded", err)
	}
	if err := f.admitTeamQuotasOver(nil, []teamQuotaAsk{{sandboxID: "sb-new", team: shrink.team, cpu: 1, memoryMB: 64}}); err != nil {
		t.Fatalf("a 1-CPU create = %v, want admitted", err)
	}
	// A growing resize in flight counts its growth only.
	growHeld := teamQuotaAsk{sandboxID: "sb-big", team: shrink.team, cpu: 4, memoryMB: 64}
	if err := f.admitTeamQuotasOver([]teamQuotaAsk{growHeld}, []teamQuotaAsk{{sandboxID: "sb-new", team: shrink.team, cpu: 1, memoryMB: 64}}); !errors.Is(err, ErrTeamQuotaExceeded) {
		t.Fatalf("a create beside a resize to the full quota in flight = %v, want ErrTeamQuotaExceeded", err)
	}
	// A held ask with no team, and none on a row, counts nothing.
	if err := f.admitTeamQuotasOver([]teamQuotaAsk{{sandboxID: "sb-anon", cpu: 8}}, []teamQuotaAsk{{sandboxID: "sb-new", team: shrink.team, cpu: 1, memoryMB: 64}}); err != nil {
		t.Fatalf("a held ask without a team = %v, want ignored", err)
	}
}

// admissionPendingLoad reads committed load and holds in one go and counts
// each reservation once.
func TestAdmissionPendingLoadCountsEachReservationOnce(t *testing.T) {
	f := newPlacementFSM()
	now := time.Now()
	applyCommit := func(index uint64, cmd command) {
		payload, err := encodeCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if res := f.Apply(&raft.Log{Index: index, Type: raft.LogCommand, Data: payload, AppendedAt: now}); res != nil {
			t.Fatalf("apply: %v", res)
		}
	}
	live := ledgerReserve("sb-live", "w1", "inc-live", 1)
	applyCommit(1, live)
	expiring := ledgerReserve("sb-exp", "w1", "inc-exp", 1)
	expiring.ExpiresUnix = now.Unix() + 1
	applyCommit(2, expiring)
	req := capacityRequestFromSpec(live.Spec)
	big := capacityRequestFromSpec(&models.CreateSandboxRequest{CPU: 2, MemoryMB: 64})
	// sb-live (1 CPU) is live; sb-exp (1 CPU) is live until now+1.
	cases := []struct {
		name      string
		now       int64
		held      []heldReservation
		wantCPU   float64
		wantCount int
	}{
		{"no holds", now.Unix(), nil, 2, 2},
		{"a hold whose entry is applied", now.Unix(), []heldReservation{{"sb-live", "w1", "inc-live", req}}, 2, 2},
		{"a hold not applied yet", now.Unix(), []heldReservation{{"sb-new", "w1", "inc-new", req}}, 3, 3},
		{"the same create held twice", now.Unix(), []heldReservation{{"sb-new", "w1", "inc-new", req}, {"sb-new", "w1", "inc-new", req}}, 3, 3},
		{"two incarnations of one id", now.Unix(), []heldReservation{{"sb-new", "w1", "inc-1", req}, {"sb-new", "w1", "inc-2", req}}, 4, 4},
		{"a hold on another owner than the claim", now.Unix(), []heldReservation{{"sb-live", "w2", "inc-live", req}}, 2, 2},
		{"a hold of another size than the claim", now.Unix(), []heldReservation{{"sb-live", "w1", "inc-live", big}}, 4, 3},
		{"a hold whose claim has expired", now.Unix() + 2, []heldReservation{{"sb-exp", "w1", "inc-exp", req}}, 2, 2},
		{"a hold without ids", now.Unix(), []heldReservation{{"", "w1", "", req}, {"sb-x", "", "", req}}, 2, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			load, runtimes, counts := f.admissionPendingLoad(tc.now, []string{"w1", "w1"}, tc.held)
			if load["w1"].CPU != tc.wantCPU || counts["w1"] != tc.wantCount || runtimes["w1"][req.Runtime] != tc.wantCount {
				t.Fatalf("w1: load %+v, count %d, runtimes %v; want %v CPU and %d reservations", load["w1"], counts["w1"], runtimes["w1"], tc.wantCPU, tc.wantCount)
			}
		})
	}
	// Owners not asked for get no count, but their held load is still added.
	load, _, counts := f.admissionPendingLoad(now.Unix(), nil, []heldReservation{{"sb-w2", "w2", "inc", req}})
	if load["w2"].CPU != 1 || len(counts) != 0 {
		t.Fatalf("w2 held load %+v counts %v", load["w2"], counts)
	}
}

// N concurrent reserves through real Raft onto a worker with room for K:
// exactly K are granted (holds never over- or under-count), every grant is in
// every server's FSM, and the ledger is empty afterwards.
func TestAdmissionLedgerConcurrentReservesThroughRaft(t *testing.T) {
	const capacityK, reserves = 16, 64
	bc := newReserveTestCluster(t, time.Millisecond, capacityK)
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}
	var granted, refused atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, reserves)
	for i := range reserves {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := bc.leader.ReserveOnTarget(context.Background(), fmt.Sprintf("sb-cc-%02d", i), bc.target, spec, PlacementSecrets{}, time.Minute)
			switch {
			case err == nil:
				granted.Add(1)
			case errors.Is(err, ErrCapacityExceeded):
				refused.Add(1)
			default:
				errs <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("reserve ended without a verdict: %v", err)
	}
	if granted.Load() != capacityK || refused.Load() != reserves-capacityK {
		t.Fatalf("granted %d, refused %d; want exactly %d and %d", granted.Load(), refused.Load(), capacityK, reserves-capacityK)
	}
	bc.leader.reservationAdmissionMu.Lock()
	holds, term := len(bc.leader.admission.holds), bc.leader.admission.term
	bc.leader.reservationAdmissionMu.Unlock()
	if holds != 0 || term != bc.leader.raft.raft.CurrentTerm() {
		t.Fatalf("ledger after every reserve answered: %d holds in term %d (raft term %d)", holds, term, bc.leader.raft.raft.CurrentTerm())
	}
	if err := bc.leader.raft.raft.Barrier(10 * time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	want := bc.leader.raft.raft.AppliedIndex()
	for i, f := range bc.fsms {
		deadline := time.Now().Add(10 * time.Second)
		for bc.nodes[i].AppliedIndex() < want && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		reserved := 0
		for _, p := range f.snapshot() {
			if p.IsReserved() && p.OwnerNodeID == bc.target.NodeID {
				reserved++
			}
		}
		if reserved != capacityK {
			t.Errorf("%s holds %d reservations, want %d", bc.ids[i], reserved, capacityK)
		}
	}
}

// Leadership lost with an entry in flight, on real Raft: raft answers
// ErrLeadershipLost, so the hold stays (unknown outcome). When this server
// leads again in a later term, the barrier runs first and the ledger starts
// empty. Both endings of the unknown entry are checked: it commits under the
// next term and keeps the worker's only slot, or a follower's term overwrites
// it and the slot is free.
func TestAdmissionLedgerLeadershipLostThenRegained(t *testing.T) {
	t.Run("entry commits in the next term", func(t *testing.T) {
		bc, idx, oldTerm := cutOffLeaderWithEntryInFlight(t, false)
		// Heal only the links to the old leader; the followers still cannot
		// reach each other. Then every server that can win the next term
		// holds sb-cut: a follower needs the old leader's vote, which it gets
		// only once its log has caught up with sb-cut, and a log entry that a
		// leader of the new term has replicated to a majority commits.
		bc.link(idx, true)
		err := bc.reserveOnRegainedLeader(t, idx, oldTerm, "sb-after")
		if !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("reserve in the new term = %v, want ErrCapacityExceeded: sb-cut committed and holds the only slot", err)
		}
		if p, ok := bc.leader.fsm.get("sb-cut"); !ok || !p.IsReserved() {
			t.Fatalf("sb-cut after the new term's barrier = %v %+v, want reserved", ok, p)
		}
		bc.requireFreshLedger(t, oldTerm)
	})
	t.Run("entry is overwritten", func(t *testing.T) {
		bc, idx, oldTerm := cutOffLeaderWithEntryInFlight(t, true)
		// The two followers elect one of them. Its barrier commits its own
		// entries on both followers, so sb-cut, which only the old leader
		// has, can never commit: no server will vote for a log without them.
		other := waitForInmemLeader(t, bc.nodes, idx)
		if err := bc.nodes[other].Barrier(30 * time.Second).Error(); err != nil {
			t.Fatalf("barrier on the followers' leader: %v", err)
		}
		bc.link(idx, true)
		if err := bc.reserveOnRegainedLeader(t, idx, oldTerm, "sb-after"); err != nil {
			t.Fatalf("reserve in the new term = %v, want admitted: sb-cut never committed", err)
		}
		if _, ok := bc.leader.fsm.get("sb-cut"); ok {
			t.Fatal("sb-cut committed although a follower's term overwrote it")
		}
		bc.requireFreshLedger(t, oldTerm)
	})
}

var ledgerSpec = &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}

// leadershipTestTimers are raft's own defaults. The leadership tests cut a
// leader off and wait for elections, so they do not use the benchmark's
// faster timers: on a loaded machine under -race those make a fresh leader
// lose its lease again before the test can use it.
func leadershipTestTimers(c *raft.Config) {
	c.HeartbeatTimeout = time.Second
	c.ElectionTimeout = time.Second
	c.LeaderLeaseTimeout = 500 * time.Millisecond
}

// leadershipTestWait bounds every wait for an election in these tests.
const leadershipTestWait = 60 * time.Second

// cutOffLeaderWithEntryInFlight starts a cluster whose worker has one slot,
// cuts the leader off from both followers (and the followers from each other
// unless followersLinked), and reserves the slot on the cut-off leader, which
// appends the entry and then loses its lease. It returns the cluster, the old
// leader's index and its term.
func cutOffLeaderWithEntryInFlight(t *testing.T, followersLinked bool) (*reserveBenchCluster, int, uint64) {
	t.Helper()
	bc := newReserveTestClusterTuned(t, 0, 1, leadershipTestTimers)
	ctx := context.Background()
	// The first admission of the term (and its barrier) happens while the
	// cluster is whole.
	if err := bc.leader.ReserveOnTarget(ctx, "sb-warm", bc.target, ledgerSpec, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	if err := bc.leader.CancelReservation(ctx, "sb-warm"); err != nil {
		t.Fatalf("cancel warm-up: %v", err)
	}
	idx := -1
	for i, r := range bc.nodes {
		if r == bc.leader.raft.raft {
			idx = i
		}
	}
	oldTerm := bc.leader.raft.raft.CurrentTerm()
	for i := range bc.nodes {
		bc.link(i, false)
	}
	if followersLinked {
		for i := range bc.nodes {
			for j := range bc.nodes {
				if i != idx && j != idx && i != j {
					bc.transports[i].Connect(raft.ServerAddress(bc.ids[j]), bc.transports[j])
				}
			}
		}
	}
	err := bc.leader.ReserveOnTarget(ctx, "sb-cut", bc.target, ledgerSpec, PlacementSecrets{}, time.Minute)
	if !errors.Is(err, ErrNotLeader) {
		t.Fatalf("reserve on a cut-off leader = %v, want ErrNotLeader", err)
	}
	bc.leader.reservationAdmissionMu.Lock()
	var unknown int
	for _, h := range bc.leader.admission.holds {
		if h.unknown {
			unknown++
		}
	}
	bc.leader.reservationAdmissionMu.Unlock()
	if unknown != 1 {
		t.Fatalf("holds with an unknown outcome after leadership was lost = %d, want 1", unknown)
	}
	return bc, idx, oldTerm
}

// link connects (up) or disconnects server i from every other server, both
// ways.
func (bc *reserveBenchCluster) link(i int, up bool) {
	for j := range bc.transports {
		if i == j {
			continue
		}
		if up {
			bc.transports[i].Connect(raft.ServerAddress(bc.ids[j]), bc.transports[j])
			bc.transports[j].Connect(raft.ServerAddress(bc.ids[i]), bc.transports[i])
		} else {
			bc.transports[i].Disconnect(raft.ServerAddress(bc.ids[j]))
			bc.transports[j].Disconnect(raft.ServerAddress(bc.ids[i]))
		}
	}
}

// requireFreshLedger checks the leader's ledger moved past oldTerm and holds
// nothing once every admission has answered.
func (bc *reserveBenchCluster) requireFreshLedger(t *testing.T, oldTerm uint64) {
	t.Helper()
	bc.leader.reservationAdmissionMu.Lock()
	holds, term := len(bc.leader.admission.holds), bc.leader.admission.term
	bc.leader.reservationAdmissionMu.Unlock()
	if holds != 0 || term <= oldTerm {
		t.Fatalf("ledger in the new term: %d holds, term %d (old term %d)", holds, term, oldTerm)
	}
}

// reserveOnRegainedLeader makes server idx lead again in a term after
// oldTerm and reserves id there. Elections after a partition are not
// deterministic, so it drives them: while another server leads it asks that
// one to hand leadership to idx, and a reserve that meets a leadership change
// is retried, as a router would. The retry keeps one incarnation, so it is
// the same create. Bounded by leadershipTestWait.
func (bc *reserveBenchCluster) reserveOnRegainedLeader(t *testing.T, idx int, oldTerm uint64, id string) error {
	t.Helper()
	r := bc.nodes[idx]
	deadline := time.Now().Add(leadershipTestWait)
	for {
		if r.State() == raft.Leader && r.CurrentTerm() > oldTerm {
			err := bc.leader.ReserveOnTarget(context.Background(), id, bc.target, ledgerSpec, PlacementSecrets{IncarnationID: "inc-" + id}, time.Minute)
			if !errors.Is(err, ErrNotLeader) && !errors.Is(err, raft.ErrLeadershipTransferInProgress) {
				if errors.Is(err, ErrCapacityExceeded) {
					// An earlier attempt committed before its answer was
					// lost, and admission counted the resend on top of it
					// (PR #1021 fixes that). The slot was free for this
					// create, which is what the caller asked.
					if p, ok := bc.leader.fsm.get(id); ok && p.IsReserved() && p.IncarnationID == "inc-"+id {
						return nil
					}
				}
				return err
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server %s did not lead again after term %d within %s: state %v, term %d",
				bc.ids[idx], oldTerm, leadershipTestWait, r.State(), r.CurrentTerm())
		}
		for i, n := range bc.nodes {
			if i != idx && n.State() == raft.Leader {
				// Fails when the target is not caught up yet or leadership
				// moved meanwhile; the next round tries again.
				_ = n.LeadershipTransferToServer(raft.ServerID(bc.ids[idx]), raft.ServerAddress(bc.ids[idx])).Error()
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitForInmemLeader returns the index of a leader other than not.
func waitForInmemLeader(t *testing.T, nodes []*raft.Raft, not int) int {
	t.Helper()
	deadline := time.Now().Add(leadershipTestWait)
	for time.Now().Before(deadline) {
		for i, r := range nodes {
			if i != not && r.State() == raft.Leader {
				return i
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no other server became leader")
	return -1
}

// With cluster mode off there is no Cluster and so no ledger: the Noop
// client's reserve is the same no-op it always was, and New refuses to build
// a Cluster.
func TestAdmissionLedgerSingleNodeIsUnaffected(t *testing.T) {
	if err := NewNoop("", "", "").ReserveOnTarget(context.Background(), "sb-1", PlacementTarget{}, nil, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("Noop reserve = %v, want nil", err)
	}
	_, err := New(config.Config{EnableCluster: false}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "EnableCluster is false") {
		t.Fatalf("New with cluster mode off = %v, want a refusal", err)
	}
}

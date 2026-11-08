package cluster

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// Leader change during concurrent reserves (invariants I4 and I8; the gate
// for E2 in plans/cluster-correctness-and-create-latency.md, Section 5).
//
// E2 will stop holding reservationAdmissionMu across the Raft commit. What
// keeps admission exact today is that lock plus the FSM state it reads, and
// a leader change replaces both at once: the new leader has its own lock and
// an FSM that may not yet have applied the old leader's last entries. This
// test pins what must survive that, before E2 changes it:
//
//   - granted <= capacity, counting every reservation the cluster holds, not
//     only the ones a caller heard "yes" for;
//   - every granted reservation is on the new leader, with its owner and
//     incarnation;
//   - once the TTL has passed and the leader's reservation sweep has run,
//     no reservation is left and no server still counts pending load.
const (
	// leaderChangeServers is the Raft server count: the smallest cluster that
	// keeps a quorum when one server is killed.
	leaderChangeServers = 3
	// leaderChangeCapacity is the target worker's budget, in one-CPU
	// reservations.
	leaderChangeCapacity = 16
	// leaderChangeConcurrency is how many reserves race, each for its own
	// sandbox id, all onto the same worker.
	leaderChangeConcurrency = 64
	// leaderChangeAfterGrants is when the leader changes: half the capacity
	// is granted, so admissions run on both sides of the change.
	leaderChangeAfterGrants = leaderChangeCapacity / 2
	// leaderChangeJitter spreads each reserve's first attempt over this
	// window, so requests are still arriving while the leader changes.
	leaderChangeJitter = 300 * time.Millisecond
	// leaderChangeTTL is the reservation TTL. It must outlast the reserves
	// plus an election, so the "visible on the new leader" check runs before
	// any of them can expire; the test fails loudly if it did not.
	leaderChangeTTL = 8 * time.Second
	// leaderChangeDeadline bounds one reserve, retries included.
	leaderChangeDeadline = 20 * time.Second
	// leaderChangeRetryBackoff is the pause before retrying a reserve that
	// met a leader change. It is short on purpose: the first admissions on a
	// new leader are the ones that can read an FSM still missing the old
	// leader's last grants, and a slow retry would always miss them.
	leaderChangeRetryBackoff = 5 * time.Millisecond
)

func TestClusterFaultLeaderChangeDuringConcurrentReserves(t *testing.T) {
	t.Run("transfer", func(t *testing.T) {
		runLeaderChangeReserves(t, "lct", func(fc *faultCluster, old, keep *faultServer) func() {
			// Hand leadership to the one server that is not the target, so the
			// new leader's admission reads a capacity lease, not its own.
			for _, s := range fc.servers {
				if s != old && s != keep {
					f := old.cluster().raft.raft.LeadershipTransferToServer(raftServerID(s), raftServerAddress(s))
					if err := f.Error(); err != nil {
						t.Errorf("leadership transfer %s -> %s: %v", old.id, s.id, err)
					}
					return nil
				}
			}
			return nil
		})
	})
	t.Run("kill", func(t *testing.T) {
		runLeaderChangeReserves(t, "lck", func(fc *faultCluster, old, _ *faultServer) func() {
			// Raft stops at once, with no hand-off and no last heartbeat.
			// The rest of the process (gossip, the internal listener) is
			// closed only after the reserves finish, so peers still list the
			// node as alive meanwhile, as they do a crashed host until gossip
			// marks it dead. A plain Close would leave gossip first and keep
			// Raft serving for up to two seconds.
			_ = old.cluster().raft.raft.Shutdown().Error()
			return func() { fc.stopServer(old) }
		})
	})
}

type leaderChangeResult struct {
	id, incarnation string
	err             error
	answered        time.Time
}

// runLeaderChangeReserves runs the reserves and calls change once half the
// capacity is granted. change returns when the old leader has stopped
// leading; the func it returns (if any) runs after every reserve answered.
func runLeaderChangeReserves(t *testing.T, name string, change func(fc *faultCluster, old, target *faultServer) func()) {
	// The cross-server comparison (I5) is gated: on main a follower that
	// applies an entry in the next second than the leader stamps a different
	// CreatedUnix, which C1 fixes. The fixing PR deletes the t.Skip line.
	var checkReplicas bool
	t.Run("replicas-identical", func(t *testing.T) {
		t.Skip("needs PR #1001 (C1): servers stamp rows with their own clock, so replicas differ by a second")
		checkReplicas = true
	})
	fc := newFaultCluster(t, name, leaderChangeServers)
	old := fc.leader()
	// The worker every reserve targets is a follower that survives the
	// change: killing the target would make every reserve fail for an
	// uninteresting reason.
	var target *faultServer
	for _, s := range fc.servers {
		if s != old {
			target = s
			break
		}
	}
	fc.setLease(target.id, staticCapacity(leaderChangeCapacity))
	tc := target.cluster()
	placementTarget := PlacementTarget{NodeID: tc.nodeID, APIURL: tc.apiURL, DataPlaneHost: tc.dataPlaneHost}
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64, DiskGB: 1}

	var granted atomic.Int32
	changed := make(chan struct{})
	var changeOnce sync.Once
	results := make([]leaderChangeResult, leaderChangeConcurrency)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range results {
		inc, err := MintIncarnationID()
		if err != nil {
			t.Fatalf("MintIncarnationID: %v", err)
		}
		results[i] = leaderChangeResult{id: fmt.Sprintf("sb-%s-%02d", name, i), incarnation: inc}
		wg.Add(1)
		go func(i int, jitter time.Duration) {
			defer wg.Done()
			<-start
			time.Sleep(jitter)
			r := &results[i]
			ctx, cancel := context.WithTimeout(context.Background(), leaderChangeDeadline)
			defer cancel()
			attempt := 0
			r.err = retryLeaderChange(ctx, leaderChangeRetryBackoff, func(ctx context.Context) error {
				// Every attempt goes through whichever server is up, the way a
				// router on any node forwards to the leader. Same id and
				// incarnation each time, so a retry of a write that did commit
				// is the idempotent same-owner refresh.
				via := fc.servers[(i+attempt)%len(fc.servers)].cluster()
				attempt++
				if via == nil {
					return ErrNotLeader
				}
				return via.ReserveOnTarget(ctx, r.id, placementTarget, spec, PlacementSecrets{IncarnationID: r.incarnation}, leaderChangeTTL)
			})
			r.answered = time.Now()
			if r.err == nil && granted.Add(1) == leaderChangeAfterGrants {
				changeOnce.Do(func() { close(changed) })
			}
		}(i, time.Duration(rand.Int63n(int64(leaderChangeJitter))))
	}

	runStart := time.Now()
	close(start)
	select {
	case <-changed:
	case <-time.After(leaderChangeDeadline):
		t.Fatalf("only %d reserves granted before the deadline; the leader change never ran", granted.Load())
	}
	after := change(fc, old, target)
	changeDone := time.Now()
	wg.Wait()
	if after != nil {
		after()
	}
	elapsed := time.Since(runStart)

	newLeader := fc.leader()
	if newLeader == old {
		t.Fatalf("leader is still %s after the change", old.id)
	}
	nl := newLeader.cluster()

	var ok, refused, okAfter int
	var other []string
	for _, r := range results {
		switch {
		case r.err == nil:
			ok++
			if r.answered.After(changeDone) {
				okAfter++
			}
		case errors.Is(r.err, ErrCapacityExceeded):
			refused++
		default:
			other = append(other, fmt.Sprintf("%s: %v", r.id, r.err))
		}
	}
	t.Logf("capacity %d, %d reserves: %d granted (%d of them after the change), %d refused for capacity, %d other; leader %s -> %s; reserves took %s",
		leaderChangeCapacity, leaderChangeConcurrency, ok, okAfter, refused, len(other), old.id, newLeader.id, elapsed.Round(time.Millisecond))
	if len(other) > 0 {
		t.Errorf("reserves ended without a verdict (neither granted nor refused for capacity):\n  %s", strings.Join(other, "\n  "))
	}
	if elapsed >= leaderChangeTTL-time.Second {
		t.Fatalf("reserves took %s, too close to the %s TTL for the visibility check to mean anything; raise leaderChangeTTL", elapsed, leaderChangeTTL)
	}

	// I4: never more granted than the worker can hold. The FSM count also
	// covers a reserve whose answer was lost but whose entry committed.
	if ok > leaderChangeCapacity {
		t.Errorf("granted %d reservations onto a worker with room for %d (I4)", ok, leaderChangeCapacity)
	}
	held := 0
	for _, p := range nl.fsm.snapshot() {
		if p.IsReserved() && p.OwnerNodeID == target.id {
			held++
		}
	}
	if held > leaderChangeCapacity {
		t.Errorf("new leader holds %d reservations on a worker with room for %d (I4)", held, leaderChangeCapacity)
	}
	// A reserve whose answer was lost can commit and still end in an error
	// for its caller. The cluster then holds it until the TTL sweep, which
	// the I8 check below covers; log it so a run shows how often it happens.
	for _, r := range results {
		if r.err == nil {
			continue
		}
		if p, found := nl.PlacementOf(r.id); found && p.IsReserved() {
			t.Logf("reservation %s is held although its caller got: %v", r.id, r.err)
		}
	}

	// Every "yes" a caller got is a reservation the new leader has.
	for _, r := range results {
		if r.err != nil {
			continue
		}
		p, found := nl.PlacementOf(r.id)
		if !found || !p.IsReserved() || p.OwnerNodeID != target.id || p.IncarnationID != r.incarnation {
			t.Errorf("granted reservation %s (incarnation %s) on the new leader: found=%v %+v", r.id, r.incarnation, found, p)
		}
	}
	if checkReplicas {
		fc.requireIdenticalServers("after the leader change")
	}
	fc.requireInvariants("after the leader change")

	// I8 at the cluster layer: none of these creates is ever promoted, so
	// once the TTL has passed and the sweep has run nothing may be left.
	var latest int64
	for _, p := range nl.fsm.snapshot() {
		if p.IsReserved() && p.ExpiresUnix > latest {
			latest = p.ExpiresUnix
		}
	}
	for time.Now().Unix() <= latest {
		time.Sleep(100 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), faultWait)
	defer cancel()
	for {
		l := fc.leader().cluster()
		l.reconcileReservations(ctx)
		if len(l.fsm.expiredReservationIDs(time.Now().Unix())) == 0 {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("expired reservations survived the leader's sweep: %v", l.fsm.expiredReservationIDs(time.Now().Unix()))
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Every server must have applied the sweep's cancels before it is
	// checked; requireInvariants settles first.
	fc.requireInvariants("after the TTL sweep")
	if checkReplicas {
		fc.requireIdenticalServers("after the TTL sweep")
	}
	now := time.Now().Unix()
	for _, s := range fc.up() {
		c := s.cluster()
		for id, p := range c.fsm.snapshot() {
			if p.IsReserved() {
				t.Errorf("%s: orphan reservation %s survived its TTL and the sweep: %+v", s.id, id, p)
			}
		}
		if n := c.fsm.livePendingReservationCount(target.id, now); n != 0 {
			t.Errorf("%s: %d pending creates still counted against %s after the sweep", s.id, n, target.id)
		}
		if load, _ := c.fsm.pendingReservationLoadByNode(now); len(load) != 0 {
			t.Errorf("%s: pending load %+v leaked past the sweep", s.id, load)
		}
		c.fsm.mu.RLock()
		leaked := len(c.fsm.pendingReservationClaims) + len(c.fsm.pendingReservationCapacity) +
			len(c.fsm.pendingReservationRuntimes) + len(c.fsm.pendingReservationIDsByOwner) + len(c.fsm.reservedIndex)
		c.fsm.mu.RUnlock()
		if leaked != 0 {
			t.Errorf("%s: %d pending-reservation index entries leaked past the sweep", s.id, leaked)
		}
	}
}

func raftServerID(s *faultServer) raft.ServerID           { return raft.ServerID(s.id) }
func raftServerAddress(s *faultServer) raft.ServerAddress { return raft.ServerAddress(s.raftAddr) }

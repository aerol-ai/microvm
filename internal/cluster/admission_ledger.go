package cluster

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/raft"
)

// Leader-side admission without a lock across the Raft commit (plan item E2,
// plans/cluster-correctness-and-create-latency.md).
//
// The leader admits a reservation (capacity and pending-create cap) and a
// quota-limited write (team usage) against state the FSM does not enforce on
// its own. It used to hold reservationAdmissionMu from the check until the
// entry committed, so the next check saw the last one in the FSM. That made
// creates commit one at a time: one disk sync each, and hashicorp/raft's
// group commit (up to MaxAppendEntries proposals per sync) never helped.
//
// Now the lock covers only the check. A passed check records a hold in the
// ledger below and releases the lock; the next check counts committed state
// plus every hold (admissionPendingLoad, heldTeamUsageLocked), so what is in
// flight still counts. A hold goes once the commit's outcome is known: the
// FSM applied the entry (accepted or refused), or raft never appended it.
// From then on committed state alone tells the truth.
//
// An unknown outcome (raft appended the entry, then the leader lost its
// leadership) keeps its hold: the entry may still commit under the next
// leader. Nothing can admit on this server again until it wins a new term,
// and the first admission of a term starts with a Raft barrier, which
// returns once this server's FSM has applied every entry ahead of it in the
// log. An older entry that is not ahead of it can never commit, since the
// barrier itself committed over it. So the barrier makes every older hold
// redundant, and the ledger starts the term empty.
//
// That needs every entry admitted in an earlier term to be in the log ahead
// of the barrier, not just admitted before it. raft takes entries and
// barriers through one FIFO channel, so it is enough that raft has taken the
// entry before the barrier is sent. A check that passed holds
// admissionEnqueue for reading until raft.Apply has returned; the term
// change takes it for writing before its barrier. Without that, a caller
// stalled between its check and raft.Apply across a lost and regained
// leadership would put its entry after the new term's barrier, while the
// reset had already dropped its hold: counted nowhere (I4).
//
// The ledger lives only on the leader, in memory: it is not replicated state,
// never touches the FSM, and has nothing to replay after a restart. A
// restarted server starts in a new term anyway.

// admissionOutcome is what the leader knows about a proposed entry once raft
// answers.
type admissionOutcome int

const (
	// outcomeSettled: the FSM applied the entry (it may have refused it), or
	// raft never appended it. Committed state now shows its whole effect.
	outcomeSettled admissionOutcome = iota
	// outcomeUnknown: raft appended the entry and then lost the leadership
	// or stopped before it was applied here. It may still commit.
	outcomeUnknown
)

// raftApplyOutcome says whether an entry raft answered err for can still
// commit. Only the errors raft gives before it appends an entry settle it;
// everything else is unknown, which keeps the hold, the safe side.
func raftApplyOutcome(err error) admissionOutcome {
	switch {
	case err == nil,
		// A follower's or candidate's loop, or a leader that is stepping
		// down, answers ErrNotLeader to entries it never dispatched.
		errors.Is(err, raft.ErrNotLeader),
		// Apply gave up before raft took the entry.
		errors.Is(err, raft.ErrEnqueueTimeout),
		// The leader refuses new entries while it hands leadership over.
		errors.Is(err, raft.ErrLeadershipTransferInProgress):
		return outcomeSettled
	default:
		// ErrLeadershipLost: appended, not yet committed. ErrRaftShutdown can
		// come after the commit, before the apply. A log-store failure may
		// have written part of a batch.
		return outcomeUnknown
	}
}

// admissionHold is one admitted command whose entry the leader has not seen
// applied yet.
type admissionHold struct {
	reservations []heldReservation
	asks         []teamQuotaAsk
	// unknown: the commit's outcome is unknown, so the hold stays until the
	// term changes.
	unknown bool
}

// admissionLedger holds the leader's in-flight admissions for one term. It is
// guarded by Cluster.reservationAdmissionMu.
type admissionLedger struct {
	// term is the leader term the holds belong to and whose barrier has run.
	// Zero until the first admission.
	term  uint64
	next  uint64
	holds map[uint64]*admissionHold
}

// startTerm moves the ledger to term, dropping every hold from earlier
// terms. Call it only after the term's barrier has returned.
func (l *admissionLedger) startTerm(term uint64) {
	l.term = term
	l.holds = nil
}

// add records cmd's hold and returns its id.
func (l *admissionLedger) add(cmd command) uint64 {
	h := &admissionHold{asks: teamQuotaAsks(cmd)}
	if cmd.Op == opReserve || cmd.Op == opReserveBatch {
		for _, r := range reservationCommands(cmd) {
			h.reservations = append(h.reservations, heldReservation{
				SandboxID:     r.SandboxID,
				OwnerNodeID:   r.OwnerNodeID,
				IncarnationID: r.IncarnationID,
				Request:       capacityRequestFromSpec(r.Spec),
			})
		}
	}
	if l.holds == nil {
		l.holds = make(map[uint64]*admissionHold)
	}
	l.next++
	l.holds[l.next] = h
	return l.next
}

// settle ends hold id by its outcome. A hold the term change already dropped
// is gone; nothing to do.
func (l *admissionLedger) settle(id uint64, outcome admissionOutcome) {
	h, ok := l.holds[id]
	if !ok {
		return
	}
	if outcome == outcomeUnknown {
		h.unknown = true
		return
	}
	delete(l.holds, id)
}

// heldReservations lists every held reservation, unknown outcomes included.
func (l *admissionLedger) heldReservations() []heldReservation {
	var out []heldReservation
	for _, h := range l.holds {
		out = append(out, h.reservations...)
	}
	return out
}

// heldAsks lists every held team-usage ask, unknown outcomes included.
func (l *admissionLedger) heldAsks() []teamQuotaAsk {
	var out []teamQuotaAsk
	for _, h := range l.holds {
		out = append(out, h.asks...)
	}
	return out
}

// isHeld reports whether r is a resend of a reservation the ledger holds:
// same sandbox, owner, incarnation and load. Both entries describe one
// create, so whichever applies first makes the other a TTL refresh that adds
// no load, and the holds keep the load counted until the last of them
// settles. A resend that changed its size is checked like a new create.
func (l *admissionLedger) isHeld(r reservationCommand) bool {
	if r.SandboxID == "" || r.OwnerNodeID == "" || r.IncarnationID == "" {
		return false
	}
	req := capacityRequestFromSpec(r.Spec)
	for _, h := range l.holds {
		for _, held := range h.reservations {
			if held.SandboxID == r.SandboxID && held.OwnerNodeID == r.OwnerNodeID &&
				held.IncarnationID == r.IncarnationID && samePendingLoad(held.Request, req) {
				return true
			}
		}
	}
	return false
}

// withoutHeldResends drops the reservations admission must not count again:
// resends of a create still in flight (isHeld). A resend's capacity was
// checked when the first copy was admitted; checking it again against a full
// worker would refuse the caller while the first copy commits.
func (l *admissionLedger) withoutHeldResends(reservations []reservationCommand) []reservationCommand {
	if len(l.holds) == 0 {
		return reservations
	}
	kept := make([]reservationCommand, 0, len(reservations))
	for _, r := range reservations {
		if !l.isHeld(r) {
			kept = append(kept, r)
		}
	}
	return kept
}

// leaderTerm reports whether this server leads and its current term.
func (c *Cluster) leaderTerm() (bool, uint64) {
	if c.leaderTermHook != nil {
		return c.leaderTermHook()
	}
	r := c.raft.raft
	return r.State() == raft.Leader, r.CurrentTerm()
}

// admissionBarrier waits until this server's FSM has applied every entry
// committed before the barrier, i.e. everything any earlier leader committed.
func (c *Cluster) admissionBarrier() error {
	if c.admissionBarrierHook != nil {
		return c.admissionBarrierHook()
	}
	if c.raft == nil || c.raft.raft == nil {
		return nil
	}
	if err := c.raft.raft.Barrier(c.commitTimeout).Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost) {
			return ErrNotLeader
		}
		return fmt.Errorf("cluster: admission barrier: %w", err)
	}
	return nil
}

// admitHold runs admit under the admission lock and, if it passes, records
// cmd's hold. The first admission of a leader term first waits until raft
// has taken every entry admitted before it, then runs the barrier, holding
// the lock so no admission of the term reads the FSM before it; the term is
// recorded only once the barrier returned, so a failed barrier is retried by
// the next admission.
//
// On success it returns the hold's id and enqueued, which the caller must
// call once raft.Apply has returned (it may call it again; only the first
// call counts), and then settle the hold.
func (c *Cluster) admitHold(cmd command, admit func() error) (uint64, func(), error) {
	c.reservationAdmissionMu.Lock()
	defer c.reservationAdmissionMu.Unlock()
	leader, term := c.leaderTerm()
	if !leader {
		return 0, nil, ErrNotLeader
	}
	if c.admission.term != term {
		// Readers are callers whose check passed and who have not yet handed
		// their entry to raft; the write lock waits for them. None can start
		// meanwhile: that takes the admission lock, which this holds.
		c.admissionEnqueue.Lock()
		err := c.admissionBarrier()
		c.admissionEnqueue.Unlock()
		if err != nil {
			return 0, nil, err
		}
		c.admission.startTerm(term)
	}
	if err := admit(); err != nil {
		return 0, nil, err
	}
	id := c.admission.add(cmd)
	// Taken before the admission lock is released, so no term change can run
	// between this check and the entry reaching raft.
	c.admissionEnqueue.RLock()
	return id, sync.OnceFunc(c.admissionEnqueue.RUnlock), nil
}

// settleHold ends a hold once raft has answered for its entry.
func (c *Cluster) settleHold(id uint64, outcome admissionOutcome) {
	c.reservationAdmissionMu.Lock()
	defer c.reservationAdmissionMu.Unlock()
	c.admission.settle(id, outcome)
}

// applyAdmittedEncodedLocal admits cmd, proposes it and keeps its hold until
// raft answers. admit runs under the admission lock; the commit does not.
func (c *Cluster) applyAdmittedEncodedLocal(ctx context.Context, payload []byte, cmd command, admit func() error) error {
	id, enqueued, err := c.admitHold(cmd, admit)
	if err != nil {
		return err
	}
	defer enqueued()
	_, outcome, err := c.applyEncodedLocalOutcome(ctx, payload, enqueued)
	c.settleHold(id, outcome)
	return err
}

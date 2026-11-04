package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The execution ledger is the durable identity of an execution, kept in the
// shared request_idempotency table (one row per execution, scope
// ExecLedgerScope). It outlives the disposable output cache, so a retried
// command id joins or replays the original execution whatever happened to the
// cache. The row-state policy lives here (D14) rather than in a facade, so any
// surface can get durable exec dedup without re-deriving it; the Runloop facade
// still owns the fingerprint scheme (which bytes identify an execution) and the
// per-execution watcher that settles a row once its toolbox session is gone.
//
// Row states, for a plain execution:
//
//	pending — claimed; the command was (or is about to be) submitted, and its
//	          toolbox session may still exist. A pending row is an obligation,
//	          not a lock: it never lapses on a timer (a lapsed row would be
//	          swept, or re-claimed by a retry that runs the command again), and
//	          only its watcher settles it, once the session is confirmed gone.
//	ready   — settled: the session is gone. target_id holds the ExecOutcome, so
//	          the exit status survives a lost output cache, or marks the
//	          execution lost when its session vanished with no result.
//
// A row is deleted early only by the request that claimed it, and only when the
// toolbox refused the command outright: then nothing can have run.
//
// A named-shell execution's row goes ready as soon as the command is submitted,
// with the execution id as target_id: the shell keeps the command's state, so
// the ledger only has to remember which command a retry maps to. Its pending
// state is an ordinary lock that lapses after ExecLedgerTTL.
const (
	// ExecLedgerScope is the request_idempotency scope for exec rows. Its value
	// is load-bearing for upgrades: renaming it would orphan every pending row
	// a running fleet already holds, so it stays "runloop.exec" even though the
	// mechanism is no longer Runloop-specific.
	ExecLedgerScope = "runloop.exec"
	// ExecLedgerTTL is how long a settled execution replays, counted from when
	// it settled, and how long a named execution's claim holds.
	ExecLedgerTTL = 24 * time.Hour
	// ExecObligationHold is a plain execution's pending hold: longer than any
	// sandbox lives, so the row stays until its watcher settles it instead of
	// lapsing on a timer (which would let a retry run the command again).
	ExecObligationHold = 100 * 365 * 24 * time.Hour
)

// ExecOutcome is what the ledger keeps of a settled plain execution: the exit
// status and how many bytes each stream produced, so a replay after the output
// itself is gone still reports real offsets and an honest truncation instead of
// an empty, successful-looking result. Lost marks an execution whose session
// ended before any result was seen (its sandbox restarted, or its submission
// failed): what the command did is unknown, so it is reported as gone, never as
// an exit status.
type ExecOutcome struct {
	Exit      int   `json:"exit"`
	StdoutLen int64 `json:"stdout_len"`
	StderrLen int64 `json:"stderr_len"`
	Lost      bool  `json:"lost,omitempty"`
}

// Encode renders the outcome for storage in a row's target_id.
func (o ExecOutcome) Encode() string {
	encoded, _ := json.Marshal(o)
	return string(encoded)
}

// DecodeExecOutcome reads a plain execution's target_id. ok is false for a row
// with no outcome yet, or one too corrupt to trust.
func DecodeExecOutcome(target string) (outcome ExecOutcome, ok bool) {
	if target == "" || json.Unmarshal([]byte(target), &outcome) != nil {
		return ExecOutcome{}, false
	}
	return outcome, true
}

// ClaimExecLedger claims an execution's row. named=false uses the obligation
// hold (the row stays until its watcher settles it); named=true uses a lapsing
// lock (the shell, not the ledger, owns the command). acquired=false means
// another request — possibly in a previous process — owns it, and the returned
// record says whether it has settled.
func (s *Service) ClaimExecLedger(ctx context.Context, fingerprint string, named bool) (*models.IdempotentRequestRecord, bool, error) {
	hold := ExecObligationHold
	if named {
		hold = ExecLedgerTTL
	}
	return s.ClaimIdempotentRequest(ctx, ExecLedgerScope, fingerprint, time.Now(), hold)
}

// ReleaseExecLedger drops a claim whose command the toolbox refused, so a retry
// with the same id starts it fresh. It detaches from the caller's context: a
// client that disconnected mid-submit is exactly when this runs, and the claim
// must still be freed promptly.
func (s *Service) ReleaseExecLedger(ctx context.Context, fingerprint string) error {
	return s.DeleteIdempotentRequest(context.WithoutCancel(ctx), ExecLedgerScope, fingerprint)
}

// CompleteExecLedger marks the row ready with target (an encoded ExecOutcome,
// or a named execution's id), opening the replay window. It detaches from the
// caller's context so a settling watcher completes even past a request's end.
func (s *Service) CompleteExecLedger(ctx context.Context, fingerprint, target string) error {
	return s.CompleteIdempotentRequest(context.WithoutCancel(ctx), ExecLedgerScope, fingerprint, target, time.Now(), ExecLedgerTTL)
}

// SetExecLedgerTarget records a plain execution's outcome on the still-pending
// row, before its session is torn down, so the exit status is never the
// session's only copy. Unlike CompleteExecLedger it does not detach: the
// watcher that calls it owns the context's lifetime.
func (s *Service) SetExecLedgerTarget(ctx context.Context, fingerprint, target string) error {
	return s.SetIdempotentRequestTarget(ctx, ExecLedgerScope, fingerprint, target)
}

// GetExecLedger reads one execution row.
func (s *Service) GetExecLedger(ctx context.Context, fingerprint string) (*models.IdempotentRequestRecord, error) {
	return s.GetIdempotentRequest(ctx, ExecLedgerScope, fingerprint)
}

// ExecLedgerOutcome returns the recorded outcome of a finished (or lost) plain
// execution. owed reports that its session may still exist (the row is not
// ready yet), so a watcher has to see the cleanup through.
func (s *Service) ExecLedgerOutcome(ctx context.Context, fingerprint string) (outcome ExecOutcome, owed, ok bool) {
	rec, err := s.GetIdempotentRequest(ctx, ExecLedgerScope, fingerprint)
	if err != nil {
		return ExecOutcome{}, false, false
	}
	outcome, ok = DecodeExecOutcome(rec.TargetID)
	return outcome, ok && rec.State != models.RequestStateReady, ok
}

// ListPendingExecLedger returns one page of pending execution rows after the
// given fingerprint, for a restart-time recovery sweep.
func (s *Service) ListPendingExecLedger(ctx context.Context, after string, limit int) ([]*models.IdempotentRequestRecord, error) {
	return s.ListIdempotentRequests(ctx, ExecLedgerScope, models.RequestStatePending, after, limit)
}

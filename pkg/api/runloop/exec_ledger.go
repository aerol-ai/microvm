package runloop

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The execution ledger is the durable identity of every execution this node
// started, kept in the shared request_idempotency table (one row per
// execution, scope execLedgerScope, fingerprint devbox/execution-id). The
// output cache in executions.go is disposable — a restart, the TTL or a
// byte-budget eviction drops it — so it cannot be what stops a retried
// command_id from running the command again. The ledger can: a row exists
// from the moment the execution is claimed until execLedgerTTL after it
// settles, so a retry inside that window joins or replays the original
// whatever happened to the cache.
//
// Row states, for a plain execution:
//
//	pending — claimed; the command was (or is about to be) submitted, and
//	          its toolbox session may still exist. A pending row is an
//	          obligation, not a lock: it never lapses on a timer (a lapsed
//	          row would be swept, or re-claimed by a retry that runs the
//	          command again), and only its watcher settles it, once the
//	          session is confirmed gone. On restart, recoverExecutions
//	          re-attaches a watcher to every pending row.
//	ready   — settled: the session is gone. target_id holds the execOutcome,
//	          so the exit status survives a lost output cache, or marks the
//	          execution lost when its session vanished with no result.
//
// A row is deleted early only by the request that claimed it, and only when
// the toolbox refused the command outright: then nothing can have run.
//
// A named-shell execution's row goes ready as soon as the command is
// submitted, with the execution id as target_id: the shell keeps the
// command's state, so the ledger only has to remember which command a
// retry maps to. Its pending state is an ordinary lock that lapses after
// execLedgerTTL.
const (
	execLedgerScope = "runloop.exec"
	// execLedgerTTL is how long a settled execution replays, counted from
	// when it settled, and how long a named execution's claim holds. The
	// rows are tiny, so the window is the usual idempotency-key day rather
	// than the output cache's hour.
	execLedgerTTL = 24 * time.Hour
	// execObligationHold is a plain execution's pending hold: longer than
	// any devbox lives, so the row stays until its watcher settles it.
	execObligationHold = 100 * 365 * 24 * time.Hour
	// recoveryPageRows is one page of the restart pass. The pass walks
	// every page; the bound keeps each store read, and each burst of new
	// watchers, small.
	recoveryPageRows = 500
)

// recoveryBackoff is the first pause between restart-pass attempts; it
// doubles after each failure. recoveryPagePause spaces the pass's pages, so
// a large backlog's watchers start their toolbox reads in waves rather than
// all at once. Variables so tests can shorten them.
var (
	recoveryBackoff   = time.Second
	recoveryPagePause = 50 * time.Millisecond
)

// execOutcome is what the ledger keeps of a settled plain execution: the
// exit status and how many bytes each stream produced, so a replay after
// the output itself is gone still reports real offsets and an honest
// truncation instead of an empty, successful-looking result. Lost marks an
// execution whose session ended before any result was seen (its devbox
// restarted, or its submission failed): what the command did is unknown,
// so it is reported as gone, never as an exit status.
type execOutcome struct {
	Exit      int   `json:"exit"`
	StdoutLen int64 `json:"stdout_len"`
	StderrLen int64 `json:"stderr_len"`
	Lost      bool  `json:"lost,omitempty"`
}

// errExecutionLost answers a read of a lost execution.
var errExecutionLost = errors.New("execution not found: its session ended before its result was recorded")

// lostConflict answers a retry of a lost execution's command id. The
// command may have run, so running it again is the caller's decision.
func lostConflict() error {
	return conflict("this command id's execution was lost before its result was recorded (its devbox restarted or its submission failed); it may have run, so retry with a new command id")
}

func (o execOutcome) encode() string {
	encoded, _ := json.Marshal(o)
	return string(encoded)
}

func ledgerKey(devboxID string, ref execRef) string { return resultKey(devboxID, ref.id()) }

// namedLedgerKey keys a named-shell execution by its caller-supplied id: its
// execution id is only known once the toolbox has accepted the command. The
// rln- prefix never parses as an execution id, so recovery skips these rows.
func namedLedgerKey(devboxID, shellName, key string) string {
	return devboxID + "/rln-" + shortHash(devboxID, shellName, key)
}

// claimLedger claims a plain execution's row. acquired=false means another
// request (possibly in a previous sandboxd process) owns it, and rec says
// whether it has settled.
func (h *handlers) claimLedger(ctx context.Context, fingerprint string) (*models.IdempotentRequestRecord, bool, error) {
	return h.deps.Service.ClaimIdempotentRequest(ctx, execLedgerScope, fingerprint, time.Now(), execObligationHold)
}

// claimNamedLedger claims a named execution's row, a lock that lapses after
// execLedgerTTL: the shell, not the ledger, owns the command.
func (h *handlers) claimNamedLedger(ctx context.Context, fingerprint string) (*models.IdempotentRequestRecord, bool, error) {
	return h.deps.Service.ClaimIdempotentRequest(ctx, execLedgerScope, fingerprint, time.Now(), execLedgerTTL)
}

// releaseLedger drops a claim whose command the toolbox refused, so a retry
// with the same id starts it fresh.
func (h *handlers) releaseLedger(ctx context.Context, fingerprint string) {
	err := h.deps.Service.DeleteIdempotentRequest(context.WithoutCancel(ctx), execLedgerScope, fingerprint)
	if err != nil && !errors.Is(err, store.ErrNotFound) && h.deps.Logger != nil {
		h.deps.Logger.Warn("runloop execution claim release failed", "claim", fingerprint, "error", err)
	}
}

// completeLedger marks the row ready with target (an encoded outcome, or a
// named execution's id).
func (h *handlers) completeLedger(ctx context.Context, fingerprint, target string) error {
	return h.deps.Service.CompleteIdempotentRequest(context.WithoutCancel(ctx), execLedgerScope, fingerprint, target, time.Now(), execLedgerTTL)
}

// ledgerOutcome returns the recorded outcome of a finished (or lost) plain
// execution. owed reports that its session may still exist (the row is not
// ready yet), so a watcher has to see the cleanup through.
func (h *handlers) ledgerOutcome(ctx context.Context, devboxID string, ref execRef) (outcome execOutcome, owed, ok bool) {
	if ref.command != "" {
		return execOutcome{}, false, false
	}
	rec, err := h.deps.Service.GetIdempotentRequest(ctx, execLedgerScope, ledgerKey(devboxID, ref))
	if err != nil {
		return execOutcome{}, false, false
	}
	outcome, ok = decodeOutcome(rec.TargetID)
	return outcome, ok && rec.State != models.RequestStateReady, ok
}

// decodeOutcome reads a plain execution's target_id. ok is false for a row
// with no outcome yet, or one too corrupt to trust.
func decodeOutcome(target string) (outcome execOutcome, ok bool) {
	if target == "" || json.Unmarshal([]byte(target), &outcome) != nil {
		return execOutcome{}, false
	}
	return outcome, true
}

// execRecovery re-attaches watchers to the executions a previous sandboxd
// process left pending. It follows the lazy-bootstrap latch shape
// (Service.EnsureLayer4Ready): done latches once a pass has walked every
// page, mu keeps two triggers from running it twice. after and cutoff let a
// retried pass resume where a failed read stopped it.
type execRecovery struct {
	done   atomic.Bool
	mu     sync.Mutex
	after  string
	cutoff time.Time
}

// recoverExecutions starts a watcher for every pending plain execution in
// the ledger, walking it page by page to the end. Its context carries no
// caller: the toolbox and store calls are internal, fleet-wide ones, which
// is what a restart-time sweep needs.
func (h *handlers) recoverExecutions(ctx context.Context) error {
	if h.recovery.done.Load() {
		return nil
	}
	h.recovery.mu.Lock()
	defer h.recovery.mu.Unlock()
	if h.recovery.done.Load() {
		return nil
	}
	if h.recovery.cutoff.IsZero() {
		// Rows claimed from here on belong to requests of this process,
		// which start their own watchers once they have submitted. Watching
		// one earlier could see its session missing only because the
		// request has not created it yet.
		h.recovery.cutoff = time.Now()
	}
	for {
		rows, err := h.deps.Service.ListIdempotentRequests(ctx, execLedgerScope, models.RequestStatePending, h.recovery.after, recoveryPageRows)
		if err != nil {
			return err
		}
		for _, row := range rows {
			h.recovery.after = row.Fingerprint
			if !row.CreatedAt.Before(h.recovery.cutoff) {
				continue
			}
			devboxID, execID, ok := strings.Cut(row.Fingerprint, "/")
			if !ok {
				continue
			}
			ref, ok := parseExecID(execID)
			if !ok || ref.command != "" {
				continue // named claims (rln-) are locks the shell owns
			}
			h.startWatcher(context.Background(), devboxID, ref, false)
		}
		if len(rows) < recoveryPageRows {
			break
		}
		time.Sleep(recoveryPagePause)
	}
	h.recovery.done.Store(true)
	return nil
}

// recoverExecutionsInBackground runs the restart pass off the boot path,
// retrying a failed store read a few times.
func (h *handlers) recoverExecutionsInBackground() {
	backoff := recoveryBackoff
	go func() {
		for attempt := 0; attempt < 5; attempt++ {
			err := h.recoverExecutions(context.Background())
			if err == nil {
				return
			}
			if h.deps.Logger != nil {
				h.deps.Logger.Warn("runloop execution recovery failed", "attempt", attempt+1, "error", err)
			}
			time.Sleep(backoff)
			backoff *= 2
		}
	}()
}

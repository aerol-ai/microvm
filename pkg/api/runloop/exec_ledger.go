package runloop

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The durable row-state policy of the execution ledger moved to
// internal/service (service.ExecOutcome + the ClaimExecLedger/CompleteExecLedger
// family), so any surface can get durable exec dedup (D14). What stays here is
// Runloop-specific: the fingerprint scheme (which bytes identify an execution),
// the wire-error shapes a replay returns, and the restart recovery pass that
// re-attaches a per-execution watcher — the watcher itself lives in
// executions.go and is coupled to Runloop's toolbox sessions.

// recoveryPageRows is one page of the restart pass. The pass walks every page;
// the bound keeps each store read, and each burst of new watchers, small.
const recoveryPageRows = 500

// recoveryBackoff is the first pause between restart-pass attempts; it doubles
// after each failure. recoveryPagePause spaces the pass's pages, so a large
// backlog's watchers start their toolbox reads in waves rather than all at once.
// Variables so tests can shorten them.
var (
	recoveryBackoff   = time.Second
	recoveryPagePause = 50 * time.Millisecond
)

// errExecutionLost answers a read of a lost execution.
var errExecutionLost = errors.New("execution not found: its session ended before its result was recorded")

// lostConflict answers a retry of a lost execution's command id. The command
// may have run, so running it again is the caller's decision.
func lostConflict() error {
	return conflict("this command id's execution was lost before its result was recorded (its devbox restarted or its submission failed); it may have run, so retry with a new command id")
}

func ledgerKey(devboxID string, ref execRef) string { return resultKey(devboxID, ref.id()) }

// namedLedgerKey keys a named-shell execution by its caller-supplied id: its
// execution id is only known once the toolbox has accepted the command. The
// rln- prefix never parses as an execution id, so recovery skips these rows.
func namedLedgerKey(devboxID, shellName, key string) string {
	return devboxID + "/rln-" + shortHash(devboxID, shellName, key)
}

// claimLedger claims a plain execution's row (the obligation hold).
func (h *handlers) claimLedger(ctx context.Context, fingerprint string) (*models.IdempotentRequestRecord, bool, error) {
	return h.deps.Service.ClaimExecLedger(ctx, fingerprint, false)
}

// claimNamedLedger claims a named execution's row (a lock that lapses).
func (h *handlers) claimNamedLedger(ctx context.Context, fingerprint string) (*models.IdempotentRequestRecord, bool, error) {
	return h.deps.Service.ClaimExecLedger(ctx, fingerprint, true)
}

// releaseLedger drops a claim whose command the toolbox refused, so a retry
// with the same id starts it fresh.
func (h *handlers) releaseLedger(ctx context.Context, fingerprint string) {
	err := h.deps.Service.ReleaseExecLedger(ctx, fingerprint)
	if err != nil && !errors.Is(err, store.ErrNotFound) && h.deps.Logger != nil {
		h.deps.Logger.Warn("runloop execution claim release failed", "claim", fingerprint, "error", err)
	}
}

// completeLedger marks the row ready with target (an encoded outcome, or a
// named execution's id).
func (h *handlers) completeLedger(ctx context.Context, fingerprint, target string) error {
	return h.deps.Service.CompleteExecLedger(ctx, fingerprint, target)
}

// ledgerOutcome returns the recorded outcome of a finished (or lost) plain
// execution. owed reports that its session may still exist (the row is not
// ready yet), so a watcher has to see the cleanup through.
func (h *handlers) ledgerOutcome(ctx context.Context, devboxID string, ref execRef) (outcome service.ExecOutcome, owed, ok bool) {
	if ref.command != "" {
		return service.ExecOutcome{}, false, false
	}
	return h.deps.Service.ExecLedgerOutcome(ctx, ledgerKey(devboxID, ref))
}

// execRecovery re-attaches watchers to the executions a previous process left
// pending. It follows the lazy-bootstrap latch shape
// (Service.EnsureLayer4Ready): done latches once a pass has walked every page,
// mu keeps two triggers from running it twice. after and cutoff let a retried
// pass resume where a failed read stopped it.
type execRecovery struct {
	done   atomic.Bool
	mu     sync.Mutex
	after  string
	cutoff time.Time
}

// recoverExecutions starts a watcher for every pending plain execution in the
// ledger, walking it page by page to the end. Its context carries no caller:
// the toolbox and store calls are internal, fleet-wide ones, which is what a
// restart-time sweep needs.
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
		// Rows claimed from here on belong to requests of this process, which
		// start their own watchers once they have submitted. Watching one
		// earlier could see its session missing only because the request has
		// not created it yet.
		h.recovery.cutoff = time.Now()
	}
	for {
		rows, err := h.deps.Service.ListPendingExecLedger(ctx, h.recovery.after, recoveryPageRows)
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

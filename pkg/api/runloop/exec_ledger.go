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
// from the moment the execution is claimed until execLedgerTTL after it, so
// a retry inside that window joins or replays the original whatever
// happened to the cache.
//
// Row states, for a plain execution:
//
//	pending — claimed; the command was (or is about to be) submitted, and
//	          its toolbox session may still exist. A pending row is cleanup
//	          owed: on restart, recoverExecutions re-attaches a watcher to
//	          every pending row so no session outlives sandboxd's memory.
//	ready   — finished and its session deleted. target_id holds the
//	          execOutcome, so the exit status survives a lost output cache.
//
// A named-shell execution's row goes ready as soon as the command is
// submitted, with the execution id as target_id: the shell keeps the
// command's state, so the ledger only has to remember which command a
// retry maps to.
const (
	execLedgerScope = "runloop.exec"
	// execLedgerTTL bounds both how long a row may stay pending (a command
	// running longer than this loses its replay protection, not its
	// session: an existing session is always adopted, never resubmitted)
	// and how long a finished execution replays. The rows are tiny, so the
	// window is the usual idempotency-key day rather than the output
	// cache's hour.
	execLedgerTTL = 24 * time.Hour
	// maxRecoveredExecutions bounds one restart's re-attach pass. Pending
	// rows are executions still running on this node, so a real backlog is
	// far smaller.
	maxRecoveredExecutions = 10000
)

// execOutcome is what the ledger keeps of a finished plain execution: the
// exit status and how many bytes each stream produced, so a replay after
// the output itself is gone still reports real offsets and an honest
// truncation instead of an empty, successful-looking result.
type execOutcome struct {
	Exit      int   `json:"exit"`
	StdoutLen int64 `json:"stdout_len"`
	StderrLen int64 `json:"stderr_len"`
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

// claimLedger claims the ledger row. acquired=false means another request
// (possibly in a previous sandboxd process) owns it, and rec says whether
// it has finished.
func (h *handlers) claimLedger(ctx context.Context, fingerprint string) (*models.IdempotentRequestRecord, bool, error) {
	return h.deps.Service.ClaimIdempotentRequest(ctx, execLedgerScope, fingerprint, time.Now(), execLedgerTTL)
}

// releaseLedger drops a claim whose command never ran, so a retry with the
// same id starts it fresh instead of waiting out the TTL.
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

// ledgerOutcome returns the recorded outcome of a finished plain execution.
// owed reports that its session may still exist (the row is not ready
// yet), so a watcher has to see the cleanup through.
func (h *handlers) ledgerOutcome(ctx context.Context, devboxID string, ref execRef) (outcome execOutcome, owed, ok bool) {
	if ref.command != "" {
		return execOutcome{}, false, false
	}
	rec, err := h.deps.Service.GetIdempotentRequest(ctx, execLedgerScope, ledgerKey(devboxID, ref))
	if err != nil || rec.TargetID == "" {
		return execOutcome{}, false, false
	}
	if err := json.Unmarshal([]byte(rec.TargetID), &outcome); err != nil {
		return execOutcome{}, false, false
	}
	return outcome, rec.State != models.RequestStateReady, true
}

// execRecovery re-attaches watchers to the executions a previous sandboxd
// process left pending. It follows the lazy-bootstrap latch shape
// (Service.EnsureLayer4Ready): done latches once a pass succeeds, mu keeps
// two triggers from running it twice.
type execRecovery struct {
	done atomic.Bool
	mu   sync.Mutex
}

// recoverExecutions starts a watcher for every pending plain execution in
// the ledger. Its context carries no caller: the toolbox and store calls are
// internal, fleet-wide ones, which is what a restart-time sweep needs.
func (h *handlers) recoverExecutions(ctx context.Context) error {
	if h.recovery.done.Load() {
		return nil
	}
	h.recovery.mu.Lock()
	defer h.recovery.mu.Unlock()
	if h.recovery.done.Load() {
		return nil
	}
	rows, err := h.deps.Service.ListIdempotentRequests(ctx, execLedgerScope, models.RequestStatePending, maxRecoveredExecutions)
	if err != nil {
		return err
	}
	for _, row := range rows {
		devboxID, execID, ok := strings.Cut(row.Fingerprint, "/")
		if !ok {
			continue
		}
		ref, ok := parseExecID(execID)
		if !ok || ref.command != "" {
			continue
		}
		h.startWatcher(context.Background(), devboxID, ref)
	}
	h.recovery.done.Store(true)
	return nil
}

// recoverExecutionsInBackground runs the restart pass off the boot path,
// retrying a failed store read a few times.
func (h *handlers) recoverExecutionsInBackground() {
	go func() {
		backoff := time.Second
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

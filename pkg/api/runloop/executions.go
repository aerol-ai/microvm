package runloop

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Executions run inside toolbox sessions. A plain execution gets its own
// session (id rlx-<hash>), so the execution id IS the session id. A
// shell_name execution runs in that named shell's persistent session
// (rls-<hash>) and is addressed as <session>.<command id>; commands in one
// shell run in order, which is Runloop's named-shell contract.
//
// Three things track an execution, each with one job:
//
//   - The ledger (exec_ledger.go) is its durable identity: a retried
//     command_id joins or replays the original instead of running again,
//     across restarts and cache evictions.
//   - One watcher goroutine per execution follows it to completion. For a
//     plain execution it also owns the session's cleanup — every idle
//     session is a live shell in the guest — and does not give up while
//     that cleanup is owed. Waiters and output streams block on the
//     watcher's signal instead of each polling the toolbox.
//   - The result cache keeps a finished plain execution's output tail
//     after its session is gone. It is disposable: losing an entry loses
//     output, never the execution's outcome.
const (
	ephemeralPrefix = "rlx-"
	shellPrefix     = "rls-"

	defaultLastN = 100

	// maxCapturedStream keeps the tail of each captured stream. The toolbox
	// holds the full output while the session lives; the cap bounds what
	// sandboxd retains after the session is gone. A stream longer than this
	// is reported as truncated, with real offsets, never silently.
	maxCapturedStream = 1 << 20
	resultCacheBytes  = 64 << 20
	maxResults        = 8192
	resultTTL         = time.Hour

	// killedExitStatus reports an execution ended by kill: 128 + SIGKILL.
	killedExitStatus = 137
)

// Holds and paces that tests shorten.
var (
	// execWaitMax is Runloop's cap on an execution wait_for_status hold
	// and on execute's optimistic_timeout.
	execWaitMax = 25 * time.Second
	// sseHeartbeat keeps an idle output stream inside the SDK's 30s read
	// timeout.
	sseHeartbeat = 15 * time.Second
	// watchMinBackoff / watchMaxBackoff pace a watcher's toolbox reads: quick
	// at first so short commands finish promptly, then capped so a long
	// command costs one session+command read every couple of seconds — and
	// that cost is per execution, not per waiter.
	watchMinBackoff = 100 * time.Millisecond
	watchMaxBackoff = 2 * time.Second
	// watchIdleBackoff paces a watcher whose devbox is not running. A
	// toolbox call would wake a serverless devbox, so it only re-reads the
	// sandbox row until the devbox runs again or is gone.
	watchIdleBackoff = 30 * time.Second
	// submitWait bounds how long a retry waits for the request that claimed
	// an execution to submit its command.
	submitWait = 5 * time.Second
	// namedWatchIdle ends a named execution's watcher once nobody has
	// asked about it for this long. A named shell owns its command, so the
	// watcher there only coalesces readers; it must not poll a command that
	// runs for days (a dev server) with no one waiting.
	namedWatchIdle = time.Minute
)

// execRef addresses one execution inside the toolbox.
type execRef struct {
	session string
	command string // empty for a plain execution: its session's only command
}

func (r execRef) id() string {
	if r.command == "" {
		return r.session
	}
	return r.session + "." + r.command
}

// parseExecID validates an execution id before any part of it reaches a
// toolbox URL path.
func parseExecID(id string) (execRef, bool) {
	if rest, ok := strings.CutPrefix(id, ephemeralPrefix); ok {
		return execRef{session: id}, isHex(rest)
	}
	if rest, ok := strings.CutPrefix(id, shellPrefix); ok {
		hash, cmd, found := strings.Cut(rest, ".")
		if !found || !isHex(hash) || !isHex(cmd) {
			return execRef{}, false
		}
		return execRef{session: shellPrefix + hash, command: cmd}, true
	}
	return execRef{}, false
}

func isHex(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// execResult is a finished plain execution captured before its session
// went away. stdout/stderr hold at most maxCapturedStream bytes each (the
// tail); the lengths are how much the command actually wrote, or -1 when
// the output was too large to read at all.
type execResult struct {
	key       string
	stdout    string
	stderr    string
	stdoutLen int64
	stderrLen int64
	exit      int
	at        time.Time
}

func (r *execResult) size() int { return len(r.stdout) + len(r.stderr) }

type execTracker struct {
	mu      sync.Mutex
	results map[string]*list.Element // key → *execResult, oldest at front
	order   *list.List
	bytes   int
	// watchers holds every execution with a live watcher and what that
	// watcher last saw.
	watchers map[string]watcherState
	// signals wake waiters on a watched execution: closed when its result
	// is recorded or its watcher stops.
	signals map[string]chan struct{}
}

// watcherState is what a watcher last saw. "Watched" implies "running" —
// letting readers skip the toolbox — only while the watcher's reads succeed
// and it has not seen the command finish. While its reads fail, readers go
// to the toolbox themselves so the failure reaches the caller as an error
// instead of hiding behind a "running" status.
type watcherState struct {
	finishing bool      // saw the command finish; cleaning up
	failing   bool      // its last toolbox read failed
	lastRead  time.Time // last time a reader asked (named executions)
}

func newExecTracker() *execTracker {
	return &execTracker{
		results:  make(map[string]*list.Element),
		order:    list.New(),
		watchers: make(map[string]watcherState),
		signals:  make(map[string]chan struct{}),
	}
}

func resultKey(devboxID, execID string) string { return devboxID + "/" + execID }

func (t *execTracker) result(key string) (*execResult, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	el, ok := t.results[key]
	if !ok {
		return nil, false
	}
	res := el.Value.(*execResult)
	if time.Since(res.at) > resultTTL {
		t.removeLocked(el)
		return nil, false
	}
	return res, true
}

// record stores a result unless one is already there: whichever of the
// watcher, a reader and kill gets there first decides how the execution
// ended, and every later caller gets that same result back.
func (t *execTracker) record(res *execResult) *execResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.results[res.key]; ok {
		return el.Value.(*execResult)
	}
	res.at = time.Now()
	t.results[res.key] = t.order.PushBack(res)
	t.bytes += res.size()
	for t.order.Len() > 0 && (t.bytes > resultCacheBytes || t.order.Len() > maxResults) {
		t.removeLocked(t.order.Front())
	}
	t.wakeLocked(res.key)
	return res
}

func (t *execTracker) removeLocked(el *list.Element) {
	res := el.Value.(*execResult)
	t.order.Remove(el)
	delete(t.results, res.key)
	t.bytes -= res.size()
}

func (t *execTracker) wakeLocked(key string) {
	if ch, ok := t.signals[key]; ok {
		close(ch)
		delete(t.signals, key)
	}
}

// watch registers a watcher for key, returning false when one exists.
func (t *execTracker) watch(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.watchers[key]; ok {
		return false
	}
	t.watchers[key] = watcherState{lastRead: time.Now()}
	return true
}

// touch records that a reader asked about key, keeping an on-demand
// watcher alive.
func (t *execTracker) touch(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if state, ok := t.watchers[key]; ok {
		state.lastRead = time.Now()
		t.watchers[key] = state
	}
}

// idleFor reports how long it has been since a reader asked about key.
func (t *execTracker) idleFor(key string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Since(t.watchers[key].lastRead)
}

func (t *execTracker) unwatch(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.watchers, key)
	t.wakeLocked(key)
}

// finishing marks key's watcher as past the command's end.
func (t *execTracker) finishing(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if state, ok := t.watchers[key]; ok {
		state.finishing = true
		t.watchers[key] = state
	}
}

// observed records whether key's watcher's latest toolbox read failed. A
// read that starts failing wakes the waiters, so they re-read the toolbox
// and report the failure instead of sleeping out their hold.
func (t *execTracker) observed(key string, failed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	state, ok := t.watchers[key]
	if !ok || state.failing == failed {
		return
	}
	state.failing = failed
	t.watchers[key] = state
	if failed {
		t.wakeLocked(key)
	}
}

// running reports that a healthy watcher is following key and has not
// seen it finish — the command is still running, no toolbox read needed.
func (t *execTracker) running(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	state, ok := t.watchers[key]
	return ok && !state.finishing && !state.failing
}

// signal returns a channel closed when key's result is recorded or its
// watcher stops; nil when nothing watches key (the caller polls instead).
// A result recorded since the caller last looked returns an already-closed
// channel, so the caller cannot sleep through it.
func (t *execTracker) signal(key string) <-chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.results[key]; ok {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	if _, ok := t.watchers[key]; !ok {
		return nil
	}
	ch, ok := t.signals[key]
	if !ok {
		ch = make(chan struct{})
		t.signals[key] = ch
	}
	return ch
}

// forgetDevbox drops a shut-down devbox's cached results and wakes its
// waiters. Its watchers stop on their own once they see the devbox gone.
func (t *execTracker) forgetDevbox(devboxID string) {
	prefix := devboxID + "/"
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, el := range t.results {
		if strings.HasPrefix(key, prefix) {
			t.removeLocked(el)
		}
	}
	for key := range t.signals {
		if strings.HasPrefix(key, prefix) {
			t.wakeLocked(key)
		}
	}
}

// execState is an execution's full state; views trim it to last_n lines.
// The lengths are the full stream sizes (-1: unknown), so a stream whose
// retained text is shorter than its length was truncated.
type execState struct {
	ref       execRef
	shellName string
	completed bool
	exit      int
	stdout    string
	stderr    string
	stdoutLen int64
	stderrLen int64
}

func (s execState) stdoutCut() bool { return s.stdoutLen != int64(len(s.stdout)) }
func (s execState) stderrCut() bool { return s.stderrLen != int64(len(s.stderr)) }

func (h *handlers) execute(w http.ResponseWriter, r *http.Request, devboxID string) {
	var req executeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	key := trimPtr(req.CommandID)
	if key == "" {
		key = strings.TrimSpace(r.Header.Get("X-Request-Id"))
	}
	ref, err := h.startExecution(r.Context(), devboxID, req.Command, trimPtr(req.ShellName), key)
	if err != nil {
		h.writeToolboxError(w, err)
		return
	}
	state, err := h.awaitExecution(r.Context(), devboxID, ref, trimPtr(req.ShellName), holdFor(req.OptimisticTimeout, execWaitMax))
	if err != nil {
		h.writeToolboxError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, executionViewFor(devboxID, state, lastN(r)))
}

func (h *handlers) executeAsync(w http.ResponseWriter, r *http.Request, devboxID string) {
	var req executeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	ref, err := h.startExecution(r.Context(), devboxID, req.Command, trimPtr(req.ShellName), strings.TrimSpace(r.Header.Get("X-Request-Id")))
	if err != nil {
		h.writeToolboxError(w, err)
		return
	}
	state, err := h.executionState(r.Context(), devboxID, ref)
	if err != nil {
		h.writeToolboxError(w, err)
		return
	}
	state.shellName = trimPtr(req.ShellName)
	writeJSON(w, http.StatusOK, executionViewFor(devboxID, state, defaultLastN))
}

// executeSync is the deprecated blocking form: it holds until the command
// finishes. A client timeout re-POSTs with the same x-request-id and joins
// the same execution.
func (h *handlers) executeSync(w http.ResponseWriter, r *http.Request, devboxID string) {
	var req executeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	ref, err := h.startExecution(r.Context(), devboxID, req.Command, trimPtr(req.ShellName), strings.TrimSpace(r.Header.Get("X-Request-Id")))
	if err != nil {
		h.writeToolboxError(w, err)
		return
	}
	for {
		state, err := h.awaitExecution(r.Context(), devboxID, ref, trimPtr(req.ShellName), execWaitMax)
		if err != nil {
			h.writeToolboxError(w, err)
			return
		}
		if state.completed {
			writeJSON(w, http.StatusOK, executionDetailView{
				DevboxID:   devboxID,
				ExitStatus: state.exit,
				Stdout:     state.stdout,
				Stderr:     state.stderr,
				ShellName:  stringPtr(trimPtr(req.ShellName)),
			})
			return
		}
	}
}

// startExecution submits command and returns its ref. key is the caller's
// retry-stable id (command_id or x-request-id); a retry with the same key
// returns the original execution instead of running the command again.
func (h *handlers) startExecution(ctx context.Context, devboxID, command, shellName, key string) (execRef, error) {
	if strings.TrimSpace(command) == "" {
		return execRef{}, badRequest("command is required")
	}
	if err := h.requireRunning(ctx, devboxID); err != nil {
		return execRef{}, err
	}
	if key == "" {
		key = randomHex()
	}
	if shellName != "" {
		return h.startNamedExecution(ctx, devboxID, command, shellName, key)
	}

	ref := execRef{session: ephemeralPrefix + shortHash(devboxID, key)}
	if _, ok := h.execs.result(resultKey(devboxID, ref.id())); ok {
		return ref, nil
	}
	// The ledger claim, not the toolbox session create, decides which of
	// several racing requests runs the command: it is one atomic write on
	// this node's store, and it outlives this process.
	rec, acquired, err := h.claimLedger(ctx, ledgerKey(devboxID, ref))
	if err != nil {
		return execRef{}, err
	}
	if !acquired {
		if rec.TargetID != "" {
			return ref, nil // finished; readers answer from the ledger
		}
		// In flight under the request that claimed it — possibly in a
		// previous sandboxd process, whose watcher died with it.
		if err := h.awaitSubmitted(ctx, devboxID, ref); err != nil {
			return execRef{}, err
		}
		h.startWatcher(ctx, devboxID, ref)
		return ref, nil
	}
	release, err := h.submitPlain(ctx, devboxID, ref, command)
	if err != nil {
		if release {
			h.releaseLedger(ctx, ledgerKey(devboxID, ref))
		}
		return execRef{}, err
	}
	h.startWatcher(ctx, devboxID, ref)
	return ref, nil
}

// submitPlain runs command in ref's session. release reports, on failure,
// that the command certainly did not run (no session, or its session was
// deleted again), so the claim can be dropped for a clean retry. When that
// is not certain the claim stays, and a retry adopts whatever the session
// holds instead of submitting a second copy.
func (h *handlers) submitPlain(ctx context.Context, devboxID string, ref execRef, command string) (release bool, err error) {
	created, err := h.createSession(ctx, devboxID, ref.session)
	if err != nil {
		return true, err
	}
	if !created {
		// The session predates this claim: a previous holder whose claim
		// lapsed got as far as creating it and may have submitted too.
		sess, err := h.getSession(ctx, devboxID, ref.session)
		if err != nil {
			return false, err
		}
		if len(sess.Commands) > 0 {
			return false, nil
		}
	}
	if _, err := h.sessionExec(ctx, devboxID, ref.session, command); err != nil {
		// Deleting the session also kills a command that did start before
		// the failure was reported.
		return h.deleteSession(context.WithoutCancel(ctx), devboxID, ref.session) == nil, err
	}
	return false, nil
}

func (h *handlers) startNamedExecution(ctx context.Context, devboxID, command, shellName, key string) (execRef, error) {
	fingerprint := namedLedgerKey(devboxID, shellName, key)
	deadline := time.Now().Add(submitWait)
	for {
		rec, acquired, err := h.claimLedger(ctx, fingerprint)
		if err != nil {
			return execRef{}, err
		}
		if acquired {
			break
		}
		execID, err := h.awaitNamedClaim(ctx, fingerprint, rec, deadline)
		if errors.Is(err, store.ErrNotFound) {
			continue // the original attempt failed and let go: claim it
		}
		if err != nil {
			return execRef{}, err
		}
		ref, ok := parseExecID(execID)
		if !ok {
			return execRef{}, fmt.Errorf("execution ledger holds an invalid execution id %q", execID)
		}
		return ref, nil
	}
	session := shellPrefix + shortHash(devboxID, shellName)
	ref, err := func() (execRef, error) {
		if _, err := h.createSession(ctx, devboxID, session); err != nil {
			return execRef{}, err
		}
		cmd, err := h.sessionExec(ctx, devboxID, session, command)
		if err != nil {
			return execRef{}, err
		}
		if !isHex(cmd) {
			return execRef{}, fmt.Errorf("toolbox returned an unexpected command id %q", cmd)
		}
		return execRef{session: session, command: cmd}, nil
	}()
	if err != nil {
		h.releaseLedger(ctx, fingerprint)
		return execRef{}, err
	}
	if err := h.completeLedger(ctx, fingerprint, ref.id()); err != nil && h.deps.Logger != nil {
		// The command runs either way; only a retry of this id loses the
		// mapping and is told to pick a new one.
		h.deps.Logger.Warn("runloop named execution ledger write failed", "devbox_id", devboxID, "execution_id", ref.id(), "error", err)
	}
	return ref, nil
}

// awaitNamedClaim waits for the request holding a named execution's claim
// to record which command it submitted. store.ErrNotFound means that
// request failed and released the claim.
func (h *handlers) awaitNamedClaim(ctx context.Context, fingerprint string, rec *models.IdempotentRequestRecord, deadline time.Time) (string, error) {
	for {
		if rec.TargetID != "" {
			return rec.TargetID, nil
		}
		if !time.Now().Before(deadline) {
			return "", conflict("execution was claimed but never submitted; retry with a new command id")
		}
		if !sleepUntil(ctx, deadline, 50*time.Millisecond, nil) {
			return "", ctx.Err()
		}
		var err error
		if rec, err = h.deps.Service.GetIdempotentRequest(ctx, execLedgerScope, fingerprint); err != nil {
			return "", err
		}
	}
}

// requireRunning refuses to start work on a devbox that is not running
// (a serverless one is woken by the toolbox call itself).
func (h *handlers) requireRunning(ctx context.Context, devboxID string) error {
	sandbox, err := h.deps.Service.GetSandbox(ctx, devboxID)
	if err != nil {
		return err
	}
	if sandbox.Status == models.SandboxStatusStarted || sandbox.Lifecycle.Serverless {
		return nil
	}
	return conflict(fmt.Sprintf("devbox is %s, not running", devboxStatus(sandbox.Status)))
}

// awaitSubmitted waits for the request that claimed ref to submit its
// command into the session.
func (h *handlers) awaitSubmitted(ctx context.Context, devboxID string, ref execRef) error {
	deadline := time.Now().Add(submitWait)
	for {
		sess, err := h.getSession(ctx, devboxID, ref.session)
		if err != nil {
			if !isToolboxNotFound(err) {
				return err
			}
			// Finished and cleaned up between the claim read and this one.
			if _, ok := h.execs.result(resultKey(devboxID, ref.id())); ok {
				return nil
			}
			if _, _, ok := h.ledgerOutcome(ctx, devboxID, ref); ok {
				return nil
			}
		} else if len(sess.Commands) > 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			// The claimer died between claiming and submitting, or its
			// shell died with the devbox. Submitting here could race a
			// second retry doing the same, so the caller picks a new id.
			return conflict("execution was claimed but never submitted; retry with a new command id")
		}
		if !sleepUntil(ctx, deadline, 50*time.Millisecond, nil) {
			return ctx.Err()
		}
	}
}

// watchPace is a watcher's timing, read from the package variables once
// when it starts: the goroutine outlives the call, and tests change them.
type watchPace struct {
	min, max, idle, namedIdle time.Duration
}

func (p watchPace) next(backoff time.Duration) time.Duration { return min(backoff*2, p.max) }

// startWatcher follows an execution to completion. It is detached from the
// request but keeps its values, so its store and toolbox calls stay scoped
// to the caller. At most one runs per execution.
func (h *handlers) startWatcher(ctx context.Context, devboxID string, ref execRef) {
	key := resultKey(devboxID, ref.id())
	if !h.execs.watch(key) {
		return
	}
	ctx = context.WithoutCancel(ctx)
	pace := watchPace{min: watchMinBackoff, max: watchMaxBackoff, idle: watchIdleBackoff, namedIdle: namedWatchIdle}
	go func() {
		defer h.execs.unwatch(key)
		h.watchExecution(ctx, devboxID, ref, pace)
	}()
}

// watchExecution polls ref until it completes and then, for a plain
// execution, finishes it. It ends when that work is done, the session is
// gone, the devbox is gone, or the ledger row has expired — never on a run
// of toolbox errors, because a plain execution's session has no other
// owner to clean it up.
func (h *handlers) watchExecution(ctx context.Context, devboxID string, ref execRef, pace watchPace) {
	key := resultKey(devboxID, ref.id())
	deadline := time.Now().Add(execLedgerTTL)
	backoff := pace.min
	failures := 0
	for time.Now().Before(deadline) {
		if ref.command != "" && h.execs.idleFor(key) > pace.namedIdle {
			return
		}
		running, gone := h.devboxRunning(ctx, devboxID)
		if gone {
			return
		}
		if !running {
			time.Sleep(pace.idle)
			continue
		}
		state, err := h.readLiveState(ctx, devboxID, ref)
		h.execs.observed(key, err != nil && !isToolboxNotFound(err))
		switch {
		case err == nil && state.completed:
			if ref.command == "" {
				h.finishPlain(ctx, devboxID, ref, state, deadline, pace)
			}
			return
		case err == nil:
			failures = 0
		case isToolboxNotFound(err):
			// Killed, finished by another process's watcher, or the shell
			// died with its devbox. A result already stored means only the
			// ledger's final step is left.
			if ref.command == "" {
				h.settleLedger(ctx, devboxID, ref)
			}
			return
		default:
			if failures++; failures == 1 || failures%100 == 0 {
				if h.deps.Logger != nil {
					h.deps.Logger.Warn("runloop execution watcher: toolbox read failed", "devbox_id", devboxID, "execution_id", ref.id(), "failures", failures, "error", err)
				}
			}
		}
		time.Sleep(backoff)
		backoff = pace.next(backoff)
	}
}

// devboxRunning reads the sandbox row — never the toolbox, which would wake
// a serverless devbox. gone means the devbox no longer exists. A store error
// reads as "not running": the watcher idles and asks again.
func (h *handlers) devboxRunning(ctx context.Context, devboxID string) (running, gone bool) {
	sandbox, err := h.deps.Service.GetSandbox(ctx, devboxID)
	if errors.Is(err, store.ErrNotFound) {
		return false, true
	}
	if err != nil {
		return false, false
	}
	return sandbox.Status == models.SandboxStatusStarted, false
}

// finishPlain publishes a finished plain execution and releases its
// session, in an order that keeps every step recoverable:
//
//  1. cache the result, so readers answer at once;
//  2. store the outcome on the still-pending ledger row, so a restart or
//     an evicted cache cannot lose it;
//  3. delete the session, retrying until it is gone — a session left
//     behind is a live shell in the guest;
//  4. mark the ledger row ready: nothing is owed any more.
//
// A row still pending after step 2 is cleanup owed, which is exactly what
// recoverExecutions re-attaches to after a restart.
func (h *handlers) finishPlain(ctx context.Context, devboxID string, ref execRef, state execState, deadline time.Time, pace watchPace) {
	key := resultKey(devboxID, ref.id())
	h.execs.finishing(key)
	res := h.execs.record(resultFromState(key, state))
	outcome := outcomeFromResult(res).encode()
	fingerprint := ledgerKey(devboxID, ref)
	if err := h.deps.Service.SetIdempotentRequestTarget(ctx, execLedgerScope, fingerprint, outcome); err != nil && !errors.Is(err, store.ErrNotFound) && h.deps.Logger != nil {
		h.deps.Logger.Warn("runloop execution outcome write failed", "devbox_id", devboxID, "execution_id", ref.id(), "error", err)
	}
	backoff := pace.min
	for failures := 0; ; failures++ {
		if !time.Now().Before(deadline) {
			return
		}
		running, gone := h.devboxRunning(ctx, devboxID)
		if gone {
			return
		}
		if !running {
			time.Sleep(pace.idle)
			continue
		}
		err := h.deleteSession(ctx, devboxID, ref.session)
		if err == nil {
			break
		}
		if (failures == 0 || failures%100 == 0) && h.deps.Logger != nil {
			h.deps.Logger.Warn("runloop execution session cleanup failed; retrying", "devbox_id", devboxID, "execution_id", ref.id(), "error", err)
		}
		time.Sleep(backoff)
		backoff = pace.next(backoff)
	}
	if err := h.completeLedger(ctx, fingerprint, outcome); err != nil && h.deps.Logger != nil {
		h.deps.Logger.Warn("runloop execution ledger completion failed", "devbox_id", devboxID, "execution_id", ref.id(), "error", err)
	}
}

// settleLedger completes a ledger row whose outcome is stored but whose
// session turned out to be gone already: nothing is owed any more.
func (h *handlers) settleLedger(ctx context.Context, devboxID string, ref execRef) {
	rec, err := h.deps.Service.GetIdempotentRequest(ctx, execLedgerScope, ledgerKey(devboxID, ref))
	if err != nil || rec.State != models.RequestStatePending || rec.TargetID == "" {
		return
	}
	if err := h.completeLedger(ctx, ledgerKey(devboxID, ref), rec.TargetID); err != nil && h.deps.Logger != nil {
		h.deps.Logger.Warn("runloop execution ledger completion failed", "devbox_id", devboxID, "execution_id", ref.id(), "error", err)
	}
}

func resultFromState(key string, state execState) *execResult {
	return &execResult{
		key: key, exit: state.exit,
		stdout: state.stdout, stderr: state.stderr,
		stdoutLen: state.stdoutLen, stderrLen: state.stderrLen,
	}
}

func outcomeFromResult(res *execResult) execOutcome {
	return execOutcome{Exit: res.exit, StdoutLen: res.stdoutLen, StderrLen: res.stderrLen}
}

func stateFromResult(ref execRef, res *execResult) execState {
	return execState{
		ref: ref, completed: true, exit: res.exit,
		stdout: res.stdout, stderr: res.stderr,
		stdoutLen: res.stdoutLen, stderrLen: res.stderrLen,
	}
}

// stateFromOutcome is a finished execution whose output is no longer held:
// the exit status and stream lengths are real, the text is gone.
func stateFromOutcome(ref execRef, outcome execOutcome) execState {
	return execState{ref: ref, completed: true, exit: outcome.Exit, stdoutLen: outcome.StdoutLen, stderrLen: outcome.StderrLen}
}

// executionState returns the execution's current state, cheapest source
// first: the result cache; a live watcher (which means "still running"
// without a toolbox read); the ledger; and only then the toolbox.
func (h *handlers) executionState(ctx context.Context, devboxID string, ref execRef) (execState, error) {
	key := resultKey(devboxID, ref.id())
	h.execs.touch(key)
	if res, ok := h.execs.result(key); ok {
		return stateFromResult(ref, res), nil
	}
	if h.execs.running(key) {
		return execState{ref: ref}, nil
	}
	if outcome, owed, ok := h.ledgerOutcome(ctx, devboxID, ref); ok {
		if owed {
			h.startWatcher(ctx, devboxID, ref)
		}
		return stateFromOutcome(ref, outcome), nil
	}
	state, err := h.readLiveState(ctx, devboxID, ref)
	if err != nil {
		// Readers race the watcher's cleanup: a read can see the session,
		// then lose it to the delete before its next step. Re-check the
		// stores the watcher writes before giving up.
		if res, ok := h.execs.result(key); ok {
			return stateFromResult(ref, res), nil
		}
		if outcome, _, ok := h.ledgerOutcome(ctx, devboxID, ref); ok {
			return stateFromOutcome(ref, outcome), nil
		}
		return execState{}, err
	}
	if state.completed && ref.command == "" {
		state = stateFromResult(ref, h.execs.record(resultFromState(key, state)))
	}
	// Nothing was watching: a plain execution's session needs its cleanup
	// owner back (after a restart, say), and a running execution's readers
	// need someone to signal them — for a named one, only while they keep
	// asking (namedWatchIdle).
	if ref.command == "" || !state.completed {
		h.startWatcher(ctx, devboxID, ref)
	}
	return state, nil
}

// readLiveState reads the execution from the toolbox. It has no side
// effects: capturing and cleaning up belong to the watcher.
func (h *handlers) readLiveState(ctx context.Context, devboxID string, ref execRef) (execState, error) {
	cid := ref.command
	if cid == "" {
		sess, err := h.getSession(ctx, devboxID, ref.session)
		if err != nil {
			return execState{}, err
		}
		if len(sess.Commands) == 0 {
			return execState{ref: ref}, nil
		}
		cid = sess.Commands[0].ID
	}
	cmd, err := h.getCommand(ctx, devboxID, ref.session, cid)
	if err != nil {
		return execState{}, err
	}
	if cmd.ExitCode == nil {
		return execState{ref: ref}, nil
	}
	state := execState{ref: ref, completed: true, exit: int(*cmd.ExitCode)}
	logs, err := h.commandLogs(ctx, devboxID, ref.session, cid)
	if errors.Is(err, errToolboxResponseTooLarge) {
		// The command finished, but its output is past what sandboxd will
		// read into memory: report it as entirely truncated.
		state.stdoutLen, state.stderrLen = -1, -1
		return state, nil
	}
	if err != nil {
		return execState{}, err
	}
	state.stdout, state.stdoutLen = keepTail(logs.Stdout)
	state.stderr, state.stderrLen = keepTail(logs.Stderr)
	return state, nil
}

// keepTail returns the last maxCapturedStream bytes of value and value's
// full length.
func keepTail(value string) (string, int64) {
	if len(value) <= maxCapturedStream {
		return value, int64(len(value))
	}
	return value[len(value)-maxCapturedStream:], int64(len(value))
}

// awaitExecution holds until the execution completes or hold passes. With a
// watcher following the execution it sleeps on the watcher's signal; it
// polls only when nothing watches.
func (h *handlers) awaitExecution(ctx context.Context, devboxID string, ref execRef, shellName string, hold time.Duration) (execState, error) {
	deadline := time.Now().Add(hold)
	key := resultKey(devboxID, ref.id())
	for {
		state, err := h.executionState(ctx, devboxID, ref)
		if err != nil {
			return execState{}, err
		}
		state.shellName = shellName
		if state.completed || !time.Now().Before(deadline) {
			return state, nil
		}
		if !h.sleepForExecution(ctx, key, deadline, statusPollInterval) {
			return state, ctx.Err()
		}
	}
}

// sleepForExecution waits for key's watcher to signal, or polls at interval
// when nothing watches it. It reports false when ctx ended.
func (h *handlers) sleepForExecution(ctx context.Context, key string, deadline time.Time, interval time.Duration) bool {
	signal := h.execs.signal(key)
	if signal != nil {
		interval = time.Until(deadline)
	}
	return sleepUntil(ctx, deadline, interval, signal)
}

func executionViewFor(devboxID string, state execState, n int) executionView {
	view := executionView{
		DevboxID:    devboxID,
		ExecutionID: state.ref.id(),
		Status:      execStatusRunning,
		ShellName:   stringPtr(state.shellName),
	}
	if !state.completed {
		return view
	}
	stdout, stdoutTrunc := tailLines(state.stdout, n)
	stderr, stderrTrunc := tailLines(state.stderr, n)
	view.Status = execStatusCompleted
	view.ExitStatus = intPtr(state.exit)
	view.Stdout = &stdout
	view.Stderr = &stderr
	// A truncated flag sends the SDK to the SSE stream for the full text.
	view.StdoutTruncated = boolPtr(stdoutTrunc || state.stdoutCut())
	view.StderrTruncated = boolPtr(stderrTrunc || state.stderrCut())
	return view
}

// tailLines returns the last n lines of value and whether any were cut.
func tailLines(value string, n int) (string, bool) {
	if n <= 0 || value == "" {
		return value, false
	}
	end := len(value)
	if strings.HasSuffix(value, "\n") {
		end--
	}
	lines := 0
	for i := end - 1; i >= 0; i-- {
		if value[i] == '\n' {
			lines++
			if lines == n {
				return value[i+1:], true
			}
		}
	}
	return value, false
}

func lastN(r *http.Request) int {
	raw := strings.TrimSpace(r.URL.Query().Get("last_n"))
	if raw == "" {
		return defaultLastN
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return defaultLastN
	}
	return n
}

func (h *handlers) lookupExecution(w http.ResponseWriter, devboxID, execID string) (execRef, bool) {
	ref, ok := parseExecID(execID)
	if !ok {
		WriteError(w, http.StatusNotFound, "execution not found")
		return execRef{}, false
	}
	return ref, true
}

func (h *handlers) getExecution(w http.ResponseWriter, r *http.Request, devboxID, execID string) {
	ref, ok := h.lookupExecution(w, devboxID, execID)
	if !ok {
		return
	}
	state, err := h.executionState(r.Context(), devboxID, ref)
	if err != nil {
		h.writeExecutionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, executionViewFor(devboxID, state, lastN(r)))
}

func (h *handlers) waitForExecutionStatus(w http.ResponseWriter, r *http.Request, devboxID, execID string) {
	ref, ok := h.lookupExecution(w, devboxID, execID)
	if !ok {
		return
	}
	var req waitForStatusRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.Statuses) == 0 {
		WriteError(w, http.StatusBadRequest, "statuses is required")
		return
	}
	want := make(map[string]struct{}, len(req.Statuses))
	for _, status := range req.Statuses {
		want[status] = struct{}{}
	}
	_, wantCompleted := want[execStatusCompleted]
	key := resultKey(devboxID, ref.id())
	deadline := time.Now().Add(holdFor(req.TimeoutSeconds, execWaitMax))
	for {
		state, err := h.executionState(r.Context(), devboxID, ref)
		if err != nil {
			h.writeExecutionError(w, err)
			return
		}
		view := executionViewFor(devboxID, state, lastN(r))
		_, matched := want[view.Status]
		// `queued` is never reported (submitted commands read as running),
		// so a wait for it is satisfied by running. A completed execution
		// cannot move again, so it answers even when not asked for.
		if !matched && view.Status == execStatusRunning {
			_, matched = want["queued"]
		}
		if matched || (state.completed && !wantCompleted) {
			writeJSON(w, http.StatusOK, view)
			return
		}
		if !time.Now().Before(deadline) {
			writeWaitTimeout(w)
			return
		}
		if !h.sleepForExecution(r.Context(), key, deadline, statusPollInterval) {
			return
		}
	}
}

// killExecution ends the execution by deleting its session. For a
// named-shell execution that ends the whole shell, including its working
// directory and exported variables: toolbox sessions have no TTY, so there
// is no way to interrupt one command without the shell.
func (h *handlers) killExecution(w http.ResponseWriter, r *http.Request, devboxID, execID string) {
	ref, ok := h.lookupExecution(w, devboxID, execID)
	if !ok {
		return
	}
	var req killExecutionRequest
	if !decodeBody(w, r, &req) {
		return
	}
	key := resultKey(devboxID, ref.id())
	if res, ok := h.execs.result(key); ok {
		writeJSON(w, http.StatusOK, executionViewFor(devboxID, stateFromResult(ref, res), lastN(r)))
		return
	}
	// A command that already finished keeps its real exit status.
	state, err := h.executionState(r.Context(), devboxID, ref)
	switch {
	case err == nil && state.completed:
		writeJSON(w, http.StatusOK, executionViewFor(devboxID, state, lastN(r)))
		return
	case err != nil:
		h.writeExecutionError(w, err)
		return
	}
	if err := h.deleteSession(r.Context(), devboxID, ref.session); err != nil {
		h.writeExecutionError(w, err)
		return
	}
	res := h.execs.record(&execResult{key: key, exit: killedExitStatus})
	if ref.command == "" {
		// Kill removed the session itself, so the execution is settled.
		if err := h.completeLedger(r.Context(), ledgerKey(devboxID, ref), outcomeFromResult(res).encode()); err != nil && h.deps.Logger != nil {
			h.deps.Logger.Warn("runloop execution ledger completion failed", "devbox_id", devboxID, "execution_id", ref.id(), "error", err)
		}
	}
	writeJSON(w, http.StatusOK, executionViewFor(devboxID, stateFromResult(ref, res), lastN(r)))
}

func (h *handlers) sendStdin(w http.ResponseWriter, r *http.Request, devboxID, execID string) {
	ref, ok := h.lookupExecution(w, devboxID, execID)
	if !ok {
		return
	}
	var req sendStdinRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Signal != nil {
		// Closing a session's stdin would end its shell, and without a TTY
		// there is no interrupt to deliver.
		WriteError(w, http.StatusNotImplemented, "stdin signals are not supported by this AerolVM Runloop facade")
		return
	}
	if req.Text == nil || *req.Text == "" {
		WriteError(w, http.StatusBadRequest, "text is required")
		return
	}
	cid := ref.command
	if cid == "" {
		sess, err := h.getSession(r.Context(), devboxID, ref.session)
		if err != nil {
			h.writeExecutionError(w, err)
			return
		}
		if len(sess.Commands) == 0 {
			WriteError(w, http.StatusConflict, "execution has not started")
			return
		}
		cid = sess.Commands[0].ID
	}
	if err := h.sendSessionInput(r.Context(), devboxID, ref.session, cid, *req.Text); err != nil {
		h.writeExecutionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sendStdinResponse{DevboxID: devboxID, ExecutionID: ref.id(), Success: true})
}

// streamOutput serves stream_{stdout,stderr}_updates as SSE. Output is
// delivered once the command completes — toolbox sessions expose a
// command's output only at the end over plain HTTP — with comment
// heartbeats while it runs so the SDK's 30s read timeout never fires.
// offset is a byte position in the command's full output: the client echoes
// the last chunk's offset back on reconnect, so each chunk's offset is
// where the next one starts.
func (h *handlers) streamOutput(w http.ResponseWriter, r *http.Request, devboxID, execID string, stderr bool) {
	ref, ok := h.lookupExecution(w, devboxID, execID)
	if !ok {
		return
	}
	var offset int64
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			WriteError(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		offset = n
	}
	state, err := h.executionState(r.Context(), devboxID, ref)
	if err != nil {
		h.writeExecutionError(w, err)
		return
	}
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()

	key := resultKey(devboxID, ref.id())
	lastBeat := time.Now()
	for !state.completed {
		if time.Since(lastBeat) >= sseHeartbeat {
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			_ = rc.Flush()
			lastBeat = time.Now()
		}
		if !h.sleepForExecution(r.Context(), key, time.Now().Add(sseHeartbeat), time.Second) {
			return
		}
		if state, err = h.executionState(r.Context(), devboxID, ref); err != nil {
			payload, _ := json.Marshal(map[string]any{"code": http.StatusBadGateway, "message": "devbox toolbox unavailable"})
			_, _ = fmt.Fprintf(w, "event: error\ndata: %s\n\n", payload)
			_ = rc.Flush()
			return
		}
	}
	output, total, name := state.stdout, state.stdoutLen, "stdout"
	if stderr {
		output, total, name = state.stderr, state.stderrLen, "stderr"
	}
	for _, chunk := range outputChunks(output, total, offset, name) {
		payload, _ := json.Marshal(chunk)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
	}
	_ = rc.Flush()
}

// outputChunks renders one stream from offset as update chunks. output is
// the retained tail of a stream total bytes long (-1: length unknown, text
// not retained). Bytes before the tail are gone; when the caller's offset
// reaches back into them, a first chunk says so in plain words rather than
// splicing the tail onto that offset as though nothing were missing. Every
// offset is a real position in the full stream, so a reconnect resumes
// correctly.
func outputChunks(output string, total, offset int64, stream string) []executionUpdateChunk {
	if total < 0 {
		if offset > 0 {
			return nil
		}
		return []executionUpdateChunk{{Output: fmt.Sprintf("[AerolVM: this command's %s was too large to keep, so none of it is available]\n", stream)}}
	}
	if offset >= total {
		return nil
	}
	start := total - int64(len(output))
	var chunks []executionUpdateChunk
	if offset < start {
		chunks = append(chunks, executionUpdateChunk{
			Output: fmt.Sprintf("[AerolVM: %d earlier bytes of %s were not kept; each stream keeps only its last %d bytes]\n", start-offset, stream, maxCapturedStream),
			Offset: start,
		})
		offset = start
	}
	if offset < total {
		chunks = append(chunks, executionUpdateChunk{Output: output[offset-start:], Offset: total})
	}
	return chunks
}

func (h *handlers) writeExecutionError(w http.ResponseWriter, err error) {
	if isToolboxNotFound(err) {
		WriteError(w, http.StatusNotFound, "execution not found")
		return
	}
	h.writeToolboxError(w, err)
}

func randomHex() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

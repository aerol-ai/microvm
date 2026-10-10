package runloop

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Executions run inside toolbox sessions. A plain execution gets its own
// session (id rlx-<hash>), so the execution id IS the session id and the
// command's state lives in the sandbox, not in sandboxd — it survives a
// sandboxd restart, and the session-create claim dedupes retries. A
// shell_name execution runs in that named shell's persistent session
// (rls-<hash>) and is addressed as <session>.<command id>; commands in one
// shell run in order, which is Runloop's named-shell contract.
//
// Every idle session is a live shell process in the guest, so a plain
// execution's session is deleted once its result is captured. The capture
// lives in a bounded in-memory cache on the owner node.
const (
	ephemeralPrefix = "rlx-"
	shellPrefix     = "rls-"

	// execWaitMax is Runloop's cap on an execution wait_for_status hold
	// and on execute's optimistic_timeout.
	execWaitMax = 25 * time.Second

	defaultLastN = 100

	// maxCapturedStream keeps the tail of each captured stream. The toolbox
	// already holds the full output in memory; the cap only bounds what
	// sandboxd retains after the session is gone.
	maxCapturedStream = 1 << 20
	resultCacheBytes  = 64 << 20
	maxResults        = 8192
	resultTTL         = time.Hour

	maxNamedClaims = 8192
	namedClaimTTL  = 15 * time.Minute

	// killedExitStatus reports an execution ended by kill: 128 + SIGKILL.
	killedExitStatus = 137

	watchMaxErrors = 30
	sseHeartbeat   = 15 * time.Second
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

// execResult is a finished execution captured before its session went away.
type execResult struct {
	key       string
	stdout    string
	stderr    string
	stdoutCut bool
	stderrCut bool
	exit      int
	at        time.Time
}

func (r *execResult) size() int { return len(r.stdout) + len(r.stderr) }

type namedClaim struct {
	execID string
	err    error
	done   chan struct{}
	at     time.Time
}

type execTracker struct {
	mu      sync.Mutex
	results map[string]*list.Element // key → *execResult, oldest at front
	order   *list.List
	bytes   int
	watches map[string]chan struct{} // plain executions with a live watcher
	named   map[string]*namedClaim   // named-shell retry dedupe
}

func newExecTracker() *execTracker {
	return &execTracker{
		results: make(map[string]*list.Element),
		order:   list.New(),
		watches: make(map[string]chan struct{}),
		named:   make(map[string]*namedClaim),
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
// watcher and kill gets there first decides how the execution ended.
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
	if ch, ok := t.watches[res.key]; ok {
		close(ch)
		delete(t.watches, res.key)
	}
	return res
}

func (t *execTracker) removeLocked(el *list.Element) {
	res := el.Value.(*execResult)
	t.order.Remove(el)
	delete(t.results, res.key)
	t.bytes -= res.size()
}

// watch registers a watcher for key, returning false when one exists.
func (t *execTracker) watch(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.watches[key]; ok {
		return false
	}
	if _, ok := t.results[key]; ok {
		return false
	}
	t.watches[key] = make(chan struct{})
	return true
}

func (t *execTracker) unwatch(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ch, ok := t.watches[key]; ok {
		close(ch)
		delete(t.watches, key)
	}
}

// signal returns a channel closed when key's result is recorded, or nil.
func (t *execTracker) signal(key string) <-chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.watches[key]
}

// claimNamed dedupes retries of a named-shell execution. Unlike a plain
// execution there is no per-execution session to claim, so the claim is
// in memory on the owner node: it covers the SDK's retries, which arrive
// within seconds, but not a sandboxd restart between attempt and retry.
func (t *execTracker) claimNamed(key string) (*namedClaim, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if c, ok := t.named[key]; ok && now.Sub(c.at) <= namedClaimTTL {
		return c, false
	}
	if len(t.named) >= maxNamedClaims {
		for k, c := range t.named {
			if now.Sub(c.at) > namedClaimTTL {
				delete(t.named, k)
			}
		}
		for k := range t.named {
			if len(t.named) < maxNamedClaims {
				break
			}
			delete(t.named, k)
		}
	}
	c := &namedClaim{done: make(chan struct{}), at: now}
	t.named[key] = c
	return c, true
}

func (t *execTracker) finishNamed(key string, c *namedClaim, execID string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c.execID, c.err = execID, err
	close(c.done)
	if err != nil && t.named[key] == c {
		delete(t.named, key)
	}
}

// forgetDevbox drops a shut-down devbox's state.
func (t *execTracker) forgetDevbox(devboxID string) {
	prefix := devboxID + "/"
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, el := range t.results {
		if strings.HasPrefix(key, prefix) {
			t.removeLocked(el)
		}
	}
	for key, ch := range t.watches {
		if strings.HasPrefix(key, prefix) {
			close(ch)
			delete(t.watches, key)
		}
	}
	for key := range t.named {
		if strings.HasPrefix(key, prefix) {
			delete(t.named, key)
		}
	}
}

// execState is an execution's full state; views trim it to last_n lines.
type execState struct {
	ref       execRef
	shellName string
	completed bool
	exit      int
	stdout    string
	stderr    string
	stdoutCut bool
	stderrCut bool
}

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
		if r.Context().Err() != nil {
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
	rkey := resultKey(devboxID, ref.id())
	if _, ok := h.execs.result(rkey); ok {
		return ref, nil
	}
	created, err := h.createSession(ctx, devboxID, ref.session)
	if err != nil {
		return execRef{}, err
	}
	if !created {
		// A retry: the original request owns the command. It submits
		// right after creating the session, so it is almost always
		// already there.
		return ref, h.awaitSubmitted(ctx, devboxID, ref.session)
	}
	if _, err := h.sessionExec(ctx, devboxID, ref.session, command); err != nil {
		_ = h.deleteSession(context.WithoutCancel(ctx), devboxID, ref.session)
		return execRef{}, err
	}
	h.startWatcher(ctx, devboxID, ref)
	return ref, nil
}

func (h *handlers) startNamedExecution(ctx context.Context, devboxID, command, shellName, key string) (execRef, error) {
	claimKey := devboxID + "/" + shellName + "\x00" + key
	claim, owner := h.execs.claimNamed(claimKey)
	if !owner {
		select {
		case <-claim.done:
		case <-ctx.Done():
			return execRef{}, ctx.Err()
		}
		if claim.err != nil {
			return execRef{}, claim.err
		}
		ref, _ := parseExecID(claim.execID)
		return ref, nil
	}
	session := shellPrefix + shortHash(devboxID, shellName)
	execID, err := func() (string, error) {
		if _, err := h.createSession(ctx, devboxID, session); err != nil {
			return "", err
		}
		cmd, err := h.sessionExec(ctx, devboxID, session, command)
		if err != nil {
			return "", err
		}
		if !isHex(cmd) {
			return "", fmt.Errorf("toolbox returned an unexpected command id %q", cmd)
		}
		return execRef{session: session, command: cmd}.id(), nil
	}()
	h.execs.finishNamed(claimKey, claim, execID, err)
	if err != nil {
		return execRef{}, err
	}
	ref, _ := parseExecID(execID)
	return ref, nil
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

// submitWait bounds how long a retry waits for the original request to
// submit the command into the session it claimed. A variable for tests.
var submitWait = 5 * time.Second

func (h *handlers) awaitSubmitted(ctx context.Context, devboxID, session string) error {
	deadline := time.Now().Add(submitWait)
	for {
		sess, err := h.getSession(ctx, devboxID, session)
		if err != nil {
			if isToolboxNotFound(err) {
				// Captured and cleaned up between our claim and this read.
				if _, ok := h.execs.result(resultKey(devboxID, session)); ok {
					return nil
				}
			}
			return err
		}
		if len(sess.Commands) > 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			// The original request died between claiming the session and
			// submitting the command. Re-submitting here could race a
			// second retry doing the same, so make the caller pick a new id.
			return conflict("execution was claimed but never submitted; retry with a new command id")
		}
		if !sleepUntil(ctx, deadline, 50*time.Millisecond, nil) {
			return ctx.Err()
		}
	}
}

// startWatcher follows a plain execution to completion, captures its
// output, and deletes the session so the guest does not accumulate idle
// shells. It is detached from the request but keeps its values, so the
// toolbox calls stay scoped to the caller.
func (h *handlers) startWatcher(ctx context.Context, devboxID string, ref execRef) {
	rkey := resultKey(devboxID, ref.id())
	if !h.execs.watch(rkey) {
		return
	}
	ctx = context.WithoutCancel(ctx)
	go func() {
		defer h.execs.unwatch(rkey)
		backoff := 100 * time.Millisecond
		failures := 0
		for {
			state, err := h.liveState(ctx, devboxID, ref)
			if err == nil && state.completed {
				return
			}
			if err != nil {
				if isToolboxNotFound(err) {
					return
				}
				if failures++; failures >= watchMaxErrors {
					if h.deps.Logger != nil {
						h.deps.Logger.Warn("runloop execution watcher giving up", "devbox_id", devboxID, "execution_id", ref.id(), "error", err)
					}
					return
				}
			} else {
				failures = 0
			}
			time.Sleep(backoff)
			if backoff < time.Second {
				backoff *= 2
			}
		}
	}()
}

// executionState returns the execution's current state from the capture
// cache or the toolbox.
func (h *handlers) executionState(ctx context.Context, devboxID string, ref execRef) (execState, error) {
	if res, ok := h.execs.result(resultKey(devboxID, ref.id())); ok {
		return stateFromResult(ref, res), nil
	}
	return h.liveState(ctx, devboxID, ref)
}

func stateFromResult(ref execRef, res *execResult) execState {
	return execState{
		ref: ref, completed: true, exit: res.exit,
		stdout: res.stdout, stderr: res.stderr,
		stdoutCut: res.stdoutCut, stderrCut: res.stderrCut,
	}
}

// liveState reads the execution from the toolbox. A finished plain
// execution is captured and its session deleted here, whichever caller
// sees it first — the watcher normally, or any reader after a restart
// lost the watcher.
func (h *handlers) liveState(ctx context.Context, devboxID string, ref execRef) (execState, error) {
	rkey := resultKey(devboxID, ref.id())
	cid := ref.command
	if cid == "" {
		sess, err := h.getSession(ctx, devboxID, ref.session)
		if err != nil {
			if res, ok := h.execs.result(rkey); ok {
				return stateFromResult(ref, res), nil
			}
			return execState{}, err
		}
		if len(sess.Commands) == 0 {
			return execState{ref: ref}, nil
		}
		cid = sess.Commands[0].ID
	}
	cmd, err := h.getCommand(ctx, devboxID, ref.session, cid)
	if err != nil {
		if res, ok := h.execs.result(rkey); ok {
			return stateFromResult(ref, res), nil
		}
		return execState{}, err
	}
	if cmd.ExitCode == nil {
		return execState{ref: ref}, nil
	}
	logs, err := h.commandLogs(ctx, devboxID, ref.session, cid)
	if err != nil {
		return execState{}, err
	}
	stdout, stdoutCut := keepTail(logs.Stdout)
	stderr, stderrCut := keepTail(logs.Stderr)
	state := execState{
		ref: ref, completed: true, exit: int(*cmd.ExitCode),
		stdout: stdout, stderr: stderr, stdoutCut: stdoutCut, stderrCut: stderrCut,
	}
	if ref.command == "" {
		res := h.execs.record(&execResult{
			key: rkey, stdout: stdout, stderr: stderr,
			stdoutCut: stdoutCut, stderrCut: stderrCut, exit: state.exit,
		})
		if err := h.deleteSession(ctx, devboxID, ref.session); err != nil && h.deps.Logger != nil {
			h.deps.Logger.Warn("runloop execution session cleanup failed", "devbox_id", devboxID, "execution_id", ref.id(), "error", err)
		}
		return stateFromResult(ref, res), nil
	}
	return state, nil
}

func keepTail(value string) (string, bool) {
	if len(value) <= maxCapturedStream {
		return value, false
	}
	return value[len(value)-maxCapturedStream:], true
}

// awaitExecution holds until the execution completes or hold passes.
func (h *handlers) awaitExecution(ctx context.Context, devboxID string, ref execRef, shellName string, hold time.Duration) (execState, error) {
	deadline := time.Now().Add(hold)
	for {
		state, err := h.executionState(ctx, devboxID, ref)
		if err != nil {
			return execState{}, err
		}
		state.shellName = shellName
		if state.completed || !time.Now().Before(deadline) {
			return state, nil
		}
		if !sleepUntil(ctx, deadline, statusPollInterval, h.execs.signal(resultKey(devboxID, ref.id()))) {
			return state, ctx.Err()
		}
	}
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
	view.StdoutTruncated = boolPtr(stdoutTrunc || state.stdoutCut)
	view.StderrTruncated = boolPtr(stderrTrunc || state.stderrCut)
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
		if !sleepUntil(r.Context(), deadline, statusPollInterval, h.execs.signal(resultKey(devboxID, ref.id()))) {
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
	rkey := resultKey(devboxID, ref.id())
	if res, ok := h.execs.result(rkey); ok {
		writeJSON(w, http.StatusOK, executionViewFor(devboxID, stateFromResult(ref, res), lastN(r)))
		return
	}
	// A command that already finished keeps its real exit status.
	if state, err := h.liveState(r.Context(), devboxID, ref); err == nil && state.completed {
		writeJSON(w, http.StatusOK, executionViewFor(devboxID, state, lastN(r)))
		return
	} else if err != nil && !isToolboxNotFound(err) {
		h.writeExecutionError(w, err)
		return
	} else if err != nil {
		WriteError(w, http.StatusNotFound, "execution not found")
		return
	}
	if err := h.deleteSession(r.Context(), devboxID, ref.session); err != nil {
		h.writeExecutionError(w, err)
		return
	}
	res := h.execs.record(&execResult{key: rkey, exit: killedExitStatus})
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
// offset is a byte position: the client echoes the last chunk's offset
// back on reconnect, so each chunk's offset is where the next one starts.
func (h *handlers) streamOutput(w http.ResponseWriter, r *http.Request, devboxID, execID string, stderr bool) {
	ref, ok := h.lookupExecution(w, devboxID, execID)
	if !ok {
		return
	}
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		n, err := strconv.Atoi(raw)
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

	lastBeat := time.Now()
	for !state.completed {
		if time.Since(lastBeat) >= sseHeartbeat {
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			_ = rc.Flush()
			lastBeat = time.Now()
		}
		if !sleepUntil(r.Context(), time.Now().Add(sseHeartbeat), time.Second, h.execs.signal(resultKey(devboxID, ref.id()))) {
			return
		}
		if state, err = h.executionState(r.Context(), devboxID, ref); err != nil {
			payload, _ := json.Marshal(map[string]any{"code": http.StatusBadGateway, "message": "devbox toolbox unavailable"})
			_, _ = fmt.Fprintf(w, "event: error\ndata: %s\n\n", payload)
			_ = rc.Flush()
			return
		}
	}
	output := state.stdout
	if stderr {
		output = state.stderr
	}
	if offset < len(output) {
		payload, _ := json.Marshal(executionUpdateChunk{Output: output[offset:], Offset: len(output)})
		_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
		_ = rc.Flush()
	}
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

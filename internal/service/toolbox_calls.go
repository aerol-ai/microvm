package service

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// In-flight toolbox requests end when their sandbox does.
//
// A toolbox request (an exec, a file transfer, a session stream) waits on a
// connection into the sandbox. When the sandbox dies without closing that
// connection, nothing on the wire ever says so: a killed gVisor sandbox or
// Firecracker VM leaves no process to send a FIN or a reset, and its address
// goes silent. The request then waited until the kernel gave up on the
// connection, minutes later, and answered 502 (live: an exec into a gVisor
// sandbox killed by a fork bomb answered 502 after 3m18s, while the same
// sandbox answered 404 a second later because the daemon already knew).
//
// So every network toolbox request registers here, by sandbox id, for its
// lifetime, and the paths that learn a sandbox is gone end its requests at
// once: a runtime die/stop or destroy event, an API stop or destroy, a
// reconcile pass that finds the runtime gone, and a stale local copy torn
// down after its ownership moved. The request answers
// ErrSandboxStoppedMidRequest (409). Nothing else ends a request, because a
// long command with no output looks the same on the wire as a dead sandbox:
// not a runtime that cannot be asked about the sandbox (reconcile's unknown
// answer), not an "oom" event (a process in the sandbox was OOM-killed, which
// the sandbox may survive), and not a reconcile listing that says stopped (a
// Firecracker VM paused for a snapshot lists as stopped). The transport's
// dead-peer bound (pkg/toolboxhttp) covers whatever no event reports.
//
// A request registers before it reads the sandbox's row, and the stop paths
// end requests after the row says stopped (and once before, so the common
// case is not delayed by route teardown). A request is therefore either
// registered when its stop is processed, or it reads the stopped row; it
// cannot slip between the two.

// ErrSandboxStoppedMidRequest ends a toolbox request whose sandbox stopped,
// exited or was destroyed while the request waited on it. It wraps
// ErrSandboxNotRunning, so every surface answers 409 and words it for its SDK.
// 409 is deliberate: the SDKs do not resend an exec on a 409 (they do on a
// 503), and whether the command ran is unknown.
var ErrSandboxStoppedMidRequest = fmt.Errorf("%w: it stopped while the request was in flight", ErrSandboxNotRunning)

// Why a sandbox's requests ended, for the error and the metric.
const (
	toolboxEndStopped   = "stopped"
	toolboxEndDestroyed = "destroyed"
	toolboxEndGone      = "runtime_gone"
	toolboxEndMoved     = "moved"
)

// toolboxEndSettle bounds how long a request whose connection broke waits
// for the lifecycle event that explains it. A runc container killed outright
// closes its sockets, so the request fails with EOF a moment before the die
// event arrives; waiting for the event lets it answer 409 like every other
// stopped sandbox instead of 502. It only runs on a broken connection to a
// sandbox whose runtime reports exits (container engines with the event
// monitor on), so a healthy request never waits. A variable for tests.
var toolboxEndSettle = 2 * time.Second

// toolboxCallsEndedTotal counts requests ended because their sandbox
// stopped, by reason.
var toolboxCallsEndedTotal = expvar.NewMap("aerolvm_toolbox_calls_ended_total")

// sandboxStoppedError is ErrSandboxStoppedMidRequest with what happened.
type sandboxStoppedError struct{ detail string }

func (e *sandboxStoppedError) Error() string {
	return ErrSandboxStoppedMidRequest.Error() + " (" + e.detail + ")"
}

func (e *sandboxStoppedError) Unwrap() error { return ErrSandboxStoppedMidRequest }

// toolboxCall is one registered request.
type toolboxCall struct{ cancel context.CancelCauseFunc }

// toolboxCallRegistry holds the in-flight requests by sandbox id. The zero
// value is ready: tests build &Service{} directly.
type toolboxCallRegistry struct {
	mu    sync.Mutex
	calls map[string]map[*toolboxCall]struct{}
}

func (r *toolboxCallRegistry) add(id string, c *toolboxCall) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.calls == nil {
		r.calls = make(map[string]map[*toolboxCall]struct{})
	}
	set := r.calls[id]
	if set == nil {
		set = make(map[*toolboxCall]struct{})
		r.calls[id] = set
	}
	set[c] = struct{}{}
}

func (r *toolboxCallRegistry) remove(id string, c *toolboxCall) {
	r.mu.Lock()
	defer r.mu.Unlock()
	set := r.calls[id]
	if set == nil {
		return
	}
	delete(set, c)
	if len(set) == 0 {
		delete(r.calls, id)
	}
}

// take removes and returns id's requests.
func (r *toolboxCallRegistry) take(id string) []*toolboxCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	set := r.calls[id]
	delete(r.calls, id)
	out := make([]*toolboxCall, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	return out
}

// inFlight is how many requests id has registered.
func (r *toolboxCallRegistry) inFlight(id string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls[id])
}

// TrackToolboxCall registers a toolbox request to sandboxID for its
// lifetime. The returned context ends with ErrSandboxStoppedMidRequest when
// the sandbox stops or is destroyed; release must be called once the request
// is over (it is safe to call more than once). Register before reading the
// sandbox's row (see the comment at the top of this file).
func (s *Service) TrackToolboxCall(ctx context.Context, sandboxID string) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(ctx)
	call := &toolboxCall{cancel: cancel}
	s.toolboxCalls.add(sandboxID, call)
	return ctx, func() {
		s.toolboxCalls.remove(sandboxID, call)
		cancel(nil)
	}
}

// endToolboxCalls ends every in-flight toolbox request to sandboxID. Safe to
// call more than once and when there are none: the stop paths call it twice.
func (s *Service) endToolboxCalls(sandboxID, reason, detail string) {
	calls := s.toolboxCalls.take(sandboxID)
	if len(calls) == 0 {
		return
	}
	if detail == "" {
		detail = reason
	}
	err := &sandboxStoppedError{detail: detail}
	for _, c := range calls {
		c.cancel(err)
	}
	toolboxCallsEndedTotal.Add(reason, int64(len(calls)))
	if s.logger != nil {
		s.logger.Info("toolbox requests ended: sandbox stopped",
			"sandbox_id", sandboxID, "reason", reason, "detail", detail, "requests", len(calls))
	}
}

// toolboxCallEnded is the error that ended ctx's toolbox request because its
// sandbox stopped, or nil.
func toolboxCallEnded(ctx context.Context) error {
	if cause := context.Cause(ctx); cause != nil && errors.Is(cause, ErrSandboxStoppedMidRequest) {
		return cause
	}
	return nil
}

// ToolboxCallEnded reports why a request registered with TrackToolboxCall
// ended early: ErrSandboxStoppedMidRequest when its sandbox stopped, nil
// otherwise (it is still running, or the caller went away).
func ToolboxCallEnded(ctx context.Context) error { return toolboxCallEnded(ctx) }

// toolboxBrokenCause is what a request whose connection to sandbox broke
// answers: ErrSandboxStoppedMidRequest when the sandbox stopped (now, or
// within toolboxEndSettle), nil when nothing says it did, so the caller
// reports a gateway error as before.
func (s *Service) toolboxBrokenCause(ctx context.Context, sandbox *models.Sandbox) error {
	if err := toolboxCallEnded(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil || !s.toolboxEndsByEvent(sandbox) {
		// The caller went away (or a key revoke ended the request), or no
		// event will come to explain it.
		return nil
	}
	timer := time.NewTimer(toolboxEndSettle)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return toolboxCallEnded(ctx)
	case <-timer.C:
		return nil
	}
}

// toolboxEndsByEvent reports whether a runtime event reports this sandbox's
// exit: the container engines' die/destroy events, with the monitor on.
// Firecracker, WASM and isolate have no exit events; their requests end on
// an API stop or destroy, a reconcile pass, or the transport bound.
func (s *Service) toolboxEndsByEvent(sandbox *models.Sandbox) bool {
	if sandbox == nil || !s.cfg.EnableEventMonitor {
		return false
	}
	return !s.isFirecrackerSandbox(sandbox) && !s.isWasmSandbox(sandbox) && !s.isIsolateSandbox(sandbox)
}

// stopDetail is what a die/stop event says about how the sandbox ended.
func stopDetail(action string, exitCode int) string {
	if action == "die" && exitCode != 0 {
		return "exited with code " + strconv.Itoa(exitCode)
	}
	return "stopped"
}

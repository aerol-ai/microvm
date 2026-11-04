package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/scaleobs"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A sandbox missing from reconcile's bulk runtime listing is re-inspected
// before anything is deleted. Only a definitive not-found deletes it
// (runtime.InstanceGone). Every other answer is "unknown": the runtime timed
// out, a shim did not reply, a driver is not registered on this node. An
// unknown sandbox keeps its row, routes, host port, capacity reservation and
// cluster placement, and is asked again next pass.
//
// Deleting on an unknown answer is not recoverable. The row, the cluster
// placement and the host port go at once, and later API calls answer 404
// for a sandbox that may still be running. Keeping a row whose sandbox really
// is gone costs a stale entry until the runtime answers. So when a sandbox
// stays unknown for reconcileUnknownMarkAfter and at least
// reconcileUnknownMarkAfterTicks passes in a row, reconcile records it as
// status=error with a message naming the runtime and the error, and still
// deletes nothing. The tenant sees why it is unusable instead of a "started"
// sandbox whose calls hang. Start or destroy work on an error row as on any
// other. The row heals on its own when the runtime lists the sandbox again.
// Both bounds count, so neither a burst of admin-triggered passes nor one
// slow pass marks a sandbox early.
const (
	reconcileUnknownMarkAfter      = 10 * time.Minute
	reconcileUnknownMarkAfterTicks = 3
	// reconcileUnknownErrorPrefix starts the last_error reconcile writes, so
	// a later pass that sees the sandbox again clears only its own message.
	reconcileUnknownErrorPrefix = "runtime state unknown: "
)

// reconcileUnknownStreak is one sandbox's run of consecutive unknown answers.
type reconcileUnknownStreak struct {
	since  time.Time
	ticks  int
	marked bool
}

// reconcileUnknownTracker holds the open streaks. In memory on purpose: after
// a restart a streak starts again, which only delays the error mark; it can
// never cause a delete. Zero value is ready to use.
type reconcileUnknownTracker struct {
	mu      sync.Mutex
	streaks map[string]*reconcileUnknownStreak
	now     func() time.Time // test seam; nil means time.Now
}

func (t *reconcileUnknownTracker) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// observe records one more unknown answer for id. mark is true exactly once
// per streak, on the pass that crosses both bounds.
func (t *reconcileUnknownTracker) observe(id string) (streak reconcileUnknownStreak, mark bool) {
	now := t.clock()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.streaks == nil {
		t.streaks = make(map[string]*reconcileUnknownStreak)
	}
	s := t.streaks[id]
	if s == nil {
		s = &reconcileUnknownStreak{since: now}
		t.streaks[id] = s
	}
	s.ticks++
	if !s.marked && s.ticks >= reconcileUnknownMarkAfterTicks && now.Sub(s.since) >= reconcileUnknownMarkAfter {
		s.marked = true
		mark = true
	}
	reconcileRuntimeUnknownSandboxes.Set(int64(len(t.streaks)))
	return *s, mark
}

// unmark lets the next pass retry a mark whose store write failed.
func (t *reconcileUnknownTracker) unmark(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.streaks[id]; s != nil {
		s.marked = false
	}
}

// forget ends id's streak: the runtime answered (present or gone).
func (t *reconcileUnknownTracker) forget(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.streaks[id]; !ok {
		return
	}
	delete(t.streaks, id)
	reconcileRuntimeUnknownSandboxes.Set(int64(len(t.streaks)))
}

// retain drops streaks of sandboxes that no longer have a row (destroyed
// through the API meanwhile), so the map and the gauge track only rows.
func (t *reconcileUnknownTracker) retain(known map[string]struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id := range t.streaks {
		if _, ok := known[id]; !ok {
			delete(t.streaks, id)
		}
	}
	reconcileRuntimeUnknownSandboxes.Set(int64(len(t.streaks)))
}

// reconcileGoneContainerConfirmed reports whether a sandbox absent from the
// bulk ListManaged snapshot is DEFINITIVELY gone and safe to reap (which
// deletes the store row, frees its host ports and, in cluster mode, deletes
// the FSM placement). The bulk snapshot is one racy read per tick that skips
// any container it cannot read at that instant (UC-20), so the sandbox is
// re-inspected first:
//   - the runtime finds it: the snapshot was stale; spare it, the next pass
//     adopts it;
//   - the runtime says it does not exist (runtime.InstanceGone): reap;
//   - anything else, including no driver for it on this node: unknown. Keep
//     everything and ask again next pass (reconcileUnknownMarkAfter).
//
// It used to reap on any Inspect error, and on a state with an empty
// container id. That deleted a healthy gVisor sandbox whose netns probe
// failed (UC-320), any firecracker VM whose API socket blipped, and every
// isolate sandbox (isolate states carry no container id).
func (s *Service) reconcileGoneContainerConfirmed(ctx context.Context, sandbox *models.Sandbox) bool {
	if sandbox == nil {
		return true
	}
	rt, err := s.runtimeForSandbox(sandbox)
	if err != nil {
		s.noteReconcileRuntimeUnknown(ctx, sandbox, fmt.Errorf("no runtime driver for it on this node: %w", err))
		return false
	}
	ref := s.runtimeRef(sandbox)
	if strings.TrimSpace(ref) == "" {
		// No container id recorded (a create that failed before the
		// runtime named one). The sandbox id is the container's name, so
		// a not-found for it is still definitive.
		ref = sandbox.ID
	}
	state, err := rt.Inspect(ctx, ref)
	switch {
	case runtime.InstanceGone(state, err):
		s.reconcileUnknown.forget(sandbox.ID)
		return true
	case err != nil:
		s.noteReconcileRuntimeUnknown(ctx, sandbox, err)
		return false
	default:
		s.reconcileUnknown.forget(sandbox.ID)
		return false
	}
}

// noteReconcileRuntimeUnknown counts and logs one unknown answer and, once
// the streak crosses both bounds, records the sandbox as status=error.
// Nothing is released: the capacity reservation, routes, host ports and
// placement stay, because the sandbox may be running.
func (s *Service) noteReconcileRuntimeUnknown(ctx context.Context, sandbox *models.Sandbox, cause error) {
	label := reconcileRuntimeLabel(sandbox)
	scaleobs.Add(reconcileRuntimeUnknownTotal, label, 1)
	streak, mark := s.reconcileUnknown.observe(sandbox.ID)
	if s.logger != nil {
		s.logger.Warn("reconcile: runtime could not say whether the sandbox exists; keeping it",
			"sandbox_id", sandbox.ID,
			"runtime", label,
			"unknown_since", streak.since.UTC().Format(time.RFC3339),
			"passes", streak.ticks,
			"error", cause,
		)
	}
	if !mark {
		return
	}
	msg := fmt.Sprintf("%sthe %s runtime has not reported this sandbox since %s (last error: %v); it was not deleted",
		reconcileUnknownErrorPrefix, label, streak.since.UTC().Format(time.RFC3339), cause)
	done := s.beginSystemAction(ctx, sandbox.ID, systemActionMarkError)
	err := s.store.UpdateStatus(ctx, sandbox.ID, models.SandboxStatusError, msg)
	if errors.Is(err, store.ErrNotFound) {
		// Destroyed meanwhile: nothing to mark, and no streak to keep.
		s.reconcileUnknown.forget(sandbox.ID)
		done(nil)
		return
	}
	done(err)
	if err != nil {
		s.reconcileUnknown.unmark(sandbox.ID)
		if s.logger != nil {
			s.logger.Warn("reconcile: could not record an unknown sandbox as error; retrying next pass",
				"sandbox_id", sandbox.ID, "error", err)
		}
		return
	}
	reconcileRuntimeUnknownMarkedTotal.Add(1)
	// The ingress warm cache would otherwise keep serving it as started.
	s.invalidateWarm(sandbox.ID)
	if s.logger != nil {
		s.logger.Error("audit reconcile marked sandbox error: runtime unanswered",
			"sandbox_id", sandbox.ID,
			"runtime", label,
			"unknown_since", streak.since.UTC().Format(time.RFC3339),
			"passes", streak.ticks,
			"error", cause,
		)
	}
}

// reconcileRuntimeLabel names the runtime a sandbox runs on, for the metric
// key and the log: one of five values, so the map stays small.
func reconcileRuntimeLabel(sandbox *models.Sandbox) string {
	switch sandbox.Runtime {
	case models.RuntimeFirecracker, models.RuntimeWasm, models.RuntimeIsolate:
		return sandbox.Runtime
	}
	return models.SandboxEngine(sandbox)
}

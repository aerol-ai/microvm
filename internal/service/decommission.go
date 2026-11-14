package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Decommission, the worker's half (C9, plans/kubernetes-v2-architecture.md
// §10.5). The leader moves a failover.policy=recreate sandbox off a worker
// that is going away "prepare before break", keeping invariant I1 (one
// executor):
//
//  1. the target pulls the sandbox's image (PrepareMove), so its recreate
//     later starts without a pull;
//  2. this node stops its copy and fences it (ReleaseForMove), so nothing
//     starts it again here: no API start, no wake, no restart on failure,
//     and its links answer 503;
//  3. the leader moves the placement with a compare-and-swap on this owner;
//  4. the target's owner watcher recreates and starts it, and this node's
//     stale-ownership sweep removes the stopped copy.
//
// Downtime is a stop plus a start. A sandbox with no recreate policy is not
// moved: its owner is told at the start (NoticeDecommission) and it is
// stopped at the deadline (StopForDecommission), then orphaned when the node
// is deleted.

// moveFenceTTL is how long a sandbox released for a move stays fenced. The
// leader moves the placement right after the release; if it never does (it
// lost leadership, the swap was refused, the decommission was called off),
// the fence lapses and this node starts the sandbox again
// (resumeLapsedMove): nothing else would, and a sandbox that asked to be
// moved must not simply stay stopped. A later pass releases it once more.
// A var for tests.
var moveFenceTTL = 5 * time.Minute

// moveFences holds the sandboxes released for a move, by expiry. The row
// carries the same fence (statusReasonMoveReleased and its updated_at), so a
// restarted sandboxd still refuses to start the sandbox (R11): this map is
// what this process knows, the row what survives it.
type moveFences struct {
	mu    sync.Mutex
	until map[string]time.Time
	// lapsed holds the fences this process saw lapse: for those, this
	// process's own clock has decided, and the row is not read again.
	lapsed map[string]struct{}
}

func (f *moveFences) set(id string, until time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.until == nil {
		f.until = make(map[string]time.Time)
	}
	f.until[id] = until
	delete(f.lapsed, id)
}

func (f *moveFences) held(id string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	until, ok := f.until[id]
	if !ok {
		return false
	}
	if !now.Before(until) {
		delete(f.until, id)
		if f.lapsed == nil {
			f.lapsed = make(map[string]struct{})
		}
		f.lapsed[id] = struct{}{}
		return false
	}
	return true
}

// known reports whether this process set id's fence, held or lapsed.
func (f *moveFences) known(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, held := f.until[id]
	_, lapsed := f.lapsed[id]
	return held || lapsed
}

func (f *moveFences) clear(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.until, id)
	delete(f.lapsed, id)
}

// moveFenced reports whether id is held for a move. OwnershipFenced folds
// it in, so every path that already refuses a fenced sandbox refuses this
// one too.
func (s *Service) moveFenced(id string) bool {
	if s == nil {
		return false
	}
	return s.moves.held(id, time.Now())
}

// Move results, per sandbox.
const (
	MoveReleased = "released" // stopped and fenced here
	MoveStopped  = "stopped"  // stopped at the deadline
	MoveGone     = "gone"     // no such sandbox here
)

// The stopped row's reason. A release for a move writes one of the two
// move reasons, which is the fence a restarted sandboxd finds (R11):
// statusReasonMoveReleased when the release stopped it (a lapsed move starts
// it again), statusReasonMoveReleasedStopped when it was already stopped
// (it stays stopped, as its user or its timer left it).
const (
	statusReasonDecommission        = "decommission"
	statusReasonMoveReleased        = "decommission_move"
	statusReasonMoveReleasedStopped = "decommission_move_stopped"
)

// movedRowFence is when the move fence a row carries lapses, or zero when
// the row carries none.
func movedRowFence(sb *models.Sandbox) time.Time {
	if sb == nil || sb.Status != models.SandboxStatusStopped {
		return time.Time{}
	}
	if sb.StatusReason != statusReasonMoveReleased && sb.StatusReason != statusReasonMoveReleasedStopped {
		return time.Time{}
	}
	return sb.UpdatedAt.Add(moveFenceTTL)
}

// refuseMovedRowStart is the start gate's check of the row (R11): a row a
// release fenced, in a process that never saw that fence, is fenced again
// here until it lapses, and refused. The caller holds id's lifecycle lock.
func (s *Service) refuseMovedRowStart(sb *models.Sandbox) error {
	until := movedRowFence(sb)
	if until.IsZero() || s.moves.known(sb.ID) || !time.Now().Before(until) {
		return nil
	}
	s.moves.set(sb.ID, until)
	if sb.StatusReason == statusReasonMoveReleased {
		s.scheduleMoveResumeIn(sb.ID, time.Until(until)+time.Second)
	}
	return ErrOwnershipFenced
}

// rearmMoveFences restores, at start, the fences of rows a release left
// stopped, and the check that starts each one again if its move never
// happens: both lived only in the process that released it.
func (s *Service) rearmMoveFences(ctx context.Context) {
	all, err := s.store.List(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("decommission: cannot list the sandboxes released for a move; the start gate still reads each row", "error", err)
		}
		return
	}
	now := time.Now()
	for _, sb := range all {
		until := movedRowFence(sb)
		if until.IsZero() || s.moves.known(sb.ID) {
			continue
		}
		if now.Before(until) {
			s.moves.set(sb.ID, until)
		}
		if sb.StatusReason == statusReasonMoveReleased {
			s.scheduleMoveResumeIn(sb.ID, max(until.Sub(now), 0)+time.Second)
		}
	}
}

// ReleaseForMove stops and fences each of ids so the leader may move its
// placement. Idempotent: an already released sandbox is released again,
// which renews its fence. A sandbox this node no longer owns is refused.
// lifetimes names, per id, the incarnation the leader read when it chose
// the move (R10); a local row of another lifetime is not the one it means,
// and is left alone as gone. An id it does not name is not checked (a
// leader from before R10).
func (s *Service) ReleaseForMove(ctx context.Context, ids []string, lifetimes map[string]string) map[string]string {
	return s.stopEach(ctx, ids, lifetimes, true)
}

// StopForDecommission stops each of ids at the decommission deadline. It is
// not moved, so it is not fenced: until the node is deleted it is still this
// node's sandbox. lifetimes is as for ReleaseForMove.
func (s *Service) StopForDecommission(ctx context.Context, ids []string, lifetimes map[string]string) map[string]string {
	return s.stopEach(ctx, ids, lifetimes, false)
}

func (s *Service) stopEach(ctx context.Context, ids []string, lifetimes map[string]string, fence bool) map[string]string {
	out := make(map[string]string, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		out[id] = s.stopOne(ctx, id, lifetimes[id], fence)
	}
	return out
}

// sameLifetime reports whether a request for lifetime means the local row
// sb. Either side unknown (a request from before R10, or a row from before
// incarnations) matches, as ownershipProven does.
func sameLifetime(sb *models.Sandbox, lifetime string) bool {
	local, want := strings.TrimSpace(sb.AuditIncarnationID), strings.TrimSpace(lifetime)
	return local == "" || want == "" || local == want
}

func (s *Service) stopOne(ctx context.Context, id, lifetime string, fence bool) string {
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return "error: " + err.Error()
	}
	defer unlock()
	sb, err := s.store.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return MoveGone
	}
	if err != nil {
		return "error: " + err.Error()
	}
	// Checked under the lifecycle lock, before anything is stopped: the
	// request was built from a placement read up to minutes ago (the
	// target's pre-pull comes first), and the id may now be a new lifetime
	// of the sandbox. The leader's swap checks the lifetime too, but only
	// after this stop, which it cannot undo.
	if !sameLifetime(sb, lifetime) {
		return MoveGone
	}
	if c := s.Cluster(); c != nil {
		if p, ok := c.PlacementOf(id); ok && strings.TrimSpace(p.OwnerNodeID) != c.SelfNodeID() {
			return "error: this node no longer owns it"
		}
	}
	// Fence before the stop, under the lifecycle lock: once the lock is
	// released, nothing may start it here again.
	if fence {
		s.moves.set(id, time.Now().Add(moveFenceTTL))
	}
	s.cancelRestartTimer(id)
	switch {
	case sb.Status != models.SandboxStatusStopped:
		reason := statusReasonDecommission
		if fence {
			reason = statusReasonMoveReleased
		}
		if _, err := s.stopSandboxLocked(ctx, id, stopModeManual, reason); err != nil {
			if fence {
				s.moves.clear(id)
			}
			return "error: " + err.Error()
		}
	case fence:
		// Already stopped: the row still records the fence, which a
		// restarted sandboxd reads (R11). A sandbox this process stopped
		// for the move keeps saying so, so a lapsed move still starts it.
		reason := statusReasonMoveReleasedStopped
		if sb.StatusReason == statusReasonMoveReleased {
			reason = statusReasonMoveReleased
		}
		set, err := s.store.SetStatusReasonIfStatus(ctx, id, models.SandboxStatusStopped, reason, nil)
		if err == nil && !set {
			err = errors.New("its row changed during the release")
		}
		if err != nil {
			s.moves.clear(id)
			return "error: " + err.Error()
		}
	}
	if fence {
		s.scheduleMoveResumeIn(id, moveFenceTTL+time.Second)
		return MoveReleased
	}
	return MoveStopped
}

// scheduleMoveResumeIn checks id after d, just after its move fence lapses.
// A renewed fence (a later release) makes this check a no-op; that release
// schedules its own.
func (s *Service) scheduleMoveResumeIn(id string, d time.Duration) {
	time.AfterFunc(d, func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		s.resumeLapsedMove(ctx, id)
	})
}

// moveResumeRetry is how soon a lapsed move is checked again when the
// leader could not say whether it happened. A var for tests.
var moveResumeRetry = time.Minute

// resumeLapsedMove starts id again when its move never happened: its fence
// has lapsed, it is still stopped for the move, and the leader itself says
// this node still owns this lifetime of it (a worker's own placement view
// may lag the swap). A placement that did move is left for the
// stale-ownership sweep. A leader that cannot answer means another check
// later. Reports whether it started the sandbox.
func (s *Service) resumeLapsedMove(ctx context.Context, id string) bool {
	if s == nil || s.moves.held(id, time.Now()) {
		return false
	}
	var placed cluster.Placement
	if c := s.Cluster(); c != nil {
		got, err := c.AuthoritativePlacementsByIDs(ctx, []string{id})
		if err != nil {
			s.scheduleMoveResumeIn(id, moveResumeRetry)
			return false
		}
		p, ok := got[id]
		if !ok || strings.TrimSpace(p.OwnerNodeID) != c.SelfNodeID() {
			return false
		}
		placed = p
	}
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return false
	}
	defer unlock()
	// Under the lock: a release that came in meanwhile wins.
	if s.moves.held(id, time.Now()) {
		return false
	}
	sb, err := s.store.Get(ctx, id)
	if err != nil || sb.Status != models.SandboxStatusStopped || sb.StatusReason != statusReasonMoveReleased || !sameLifetime(sb, placed.IncarnationID) {
		return false
	}
	if _, err := s.startSandboxLocked(ctx, id, startForRestart); err != nil {
		s.logger.Warn("decommission: a sandbox whose move never happened could not be started again", "sandbox_id", id, "err", err)
		return false
	}
	s.logger.Info("decommission: started a sandbox again; its move never happened", "sandbox_id", id)
	return true
}

// imagePreparer is a runtime that can pull an image ahead of a create.
type imagePreparer interface {
	PrepareImage(ctx context.Context, imageRef string) error
}

// ErrPrepareUnsupported is PrepareMove's answer for a runtime that cannot
// pull ahead; the move goes on and the recreate pulls as usual.
var ErrPrepareUnsupported = errors.New("this runtime cannot pull an image ahead of a create")

// PrepareMove pulls spec's image on this node ahead of a move's recreate,
// so the moved sandbox starts without a pull. Best effort: an image that
// needs registry credentials is left to the recreate, which unseals them.
func (s *Service) PrepareMove(ctx context.Context, spec models.CreateSandboxRequest) error {
	if spec.Registry != nil {
		return ErrPrepareUnsupported
	}
	image := strings.TrimSpace(spec.Image)
	if image == "" {
		return errors.New("no image to prepare")
	}
	rt, err := s.runtimeForSandbox(&models.Sandbox{Runtime: spec.Runtime})
	if err != nil {
		return err
	}
	p, ok := rt.(imagePreparer)
	if !ok {
		return ErrPrepareUnsupported
	}
	return p.PrepareImage(ctx, image)
}

// KindDecommissionNotice is the audit record a sandbox's owner reads when
// its worker is being decommissioned and the sandbox will not be moved.
const KindDecommissionNotice = "node.decommission_notice"

// NoticeDecommission tells each of ids' owners, through the sandbox's audit
// stream, that its worker goes away and it stops at deadline.
func (s *Service) NoticeDecommission(ctx context.Context, ids []string, deadline time.Time) int {
	sink := s.secretAuditSink()
	if sink == nil {
		return 0
	}
	n := 0
	for _, id := range ids {
		sb, err := s.store.Get(ctx, strings.TrimSpace(id))
		if err != nil {
			continue
		}
		actor := s.auditActor()
		incarnationID, _ := s.auditIdentityFor(sb.ID)
		ev := SecretAuditEvent{
			Time:          time.Now().UTC(),
			Actor:         actor,
			NodeID:        actor,
			SandboxID:     sb.ID,
			Result:        secretAuditResultSuccess,
			Reason:        fmt.Sprintf("its worker is being decommissioned; it stops at %s unless it ends first", deadline.UTC().Format(time.RFC3339)),
			Kind:          KindDecommissionNotice,
			IncarnationID: incarnationID,
			OwnerRef:      sb.OwnerRef,
			Caller:        s.auditCaller(controlplane.ContextWithSystemCaller(context.Background(), auditSubsystemDecommission)),
		}
		ensureSecretAuditEventID(&ev)
		sink.Emit(ev)
		n++
	}
	return n
}

// auditSubsystemDecommission names the decommission's system caller.
const auditSubsystemDecommission = "decommission"

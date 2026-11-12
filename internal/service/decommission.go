package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

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

// moveFences holds the sandboxes released for a move, by expiry.
type moveFences struct {
	mu    sync.Mutex
	until map[string]time.Time
}

func (f *moveFences) set(id string, until time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.until == nil {
		f.until = make(map[string]time.Time)
	}
	f.until[id] = until
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
		return false
	}
	return true
}

func (f *moveFences) clear(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.until, id)
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

// statusReasonDecommission is the stopped row's reason.
const statusReasonDecommission = "decommission"

// ReleaseForMove stops and fences each of ids so the leader may move its
// placement. Idempotent: an already released sandbox is released again,
// which renews its fence. A sandbox this node no longer owns is refused.
func (s *Service) ReleaseForMove(ctx context.Context, ids []string) map[string]string {
	return s.stopEach(ctx, ids, true)
}

// StopForDecommission stops each of ids at the decommission deadline. It is
// not moved, so it is not fenced: until the node is deleted it is still this
// node's sandbox.
func (s *Service) StopForDecommission(ctx context.Context, ids []string) map[string]string {
	return s.stopEach(ctx, ids, false)
}

func (s *Service) stopEach(ctx context.Context, ids []string, fence bool) map[string]string {
	out := make(map[string]string, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		out[id] = s.stopOne(ctx, id, fence)
	}
	return out
}

func (s *Service) stopOne(ctx context.Context, id string, fence bool) string {
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
	if c := s.Cluster(); c != nil {
		if p, ok := c.PlacementOf(id); ok && strings.TrimSpace(p.OwnerNodeID) != c.SelfNodeID() {
			return "error: this node no longer owns it"
		}
	}
	// Fence before the stop, under the lifecycle lock: once the lock is
	// released, nothing may start it here again.
	if fence {
		s.moves.set(id, time.Now().Add(moveFenceTTL))
		s.scheduleMoveResume(id)
	}
	s.cancelRestartTimer(id)
	if sb.Status != models.SandboxStatusStopped {
		if _, err := s.stopSandboxLocked(ctx, id, stopModeManual, statusReasonDecommission); err != nil {
			if fence {
				s.moves.clear(id)
			}
			return "error: " + err.Error()
		}
	}
	if fence {
		return MoveReleased
	}
	return MoveStopped
}

// scheduleMoveResume checks id just after its move fence lapses. A renewed
// fence (a later release) makes this check a no-op; that release
// schedules its own.
func (s *Service) scheduleMoveResume(id string) {
	time.AfterFunc(moveFenceTTL+time.Second, func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		s.resumeLapsedMove(ctx, id)
	})
}

// resumeLapsedMove starts id again when its move never happened: its fence
// has lapsed, it is still stopped for the decommission, and the cluster
// still names this node its owner. A placement that did move is left for
// the stale-ownership sweep. Reports whether it started the sandbox.
func (s *Service) resumeLapsedMove(ctx context.Context, id string) bool {
	if s == nil || s.moves.held(id, time.Now()) {
		return false
	}
	if c := s.Cluster(); c != nil {
		if p, ok := c.PlacementOf(id); ok && strings.TrimSpace(p.OwnerNodeID) != c.SelfNodeID() {
			return false
		}
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
	if err != nil || sb.Status != models.SandboxStatusStopped || sb.StatusReason != statusReasonDecommission {
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

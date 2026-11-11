package service

import (
	"context"
	"errors"
	"expvar"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Worker ownership lease (plan C4 part 1, invariant I1: one executor).
//
// The leader reassigns a dead node's failover.policy=recreate sandboxes once
// it has seen the node dead for SB_DEAD_OWNER_GRACE (Cluster.evictDeadOwner).
// The old owner stops its copy only in reconcileStaleOwnership, which needs a
// reachable leader. A worker cut off by a network partition therefore kept
// running and serving its copy while the leader started the replacement: two
// live copies, possibly writing the same volumes.
//
// So a worker keeps a lease on what it owns. The lease is renewed by an
// authoritative read: AuthoritativePlacementsByIDs, answered only by the
// leader (a follower refuses it, and the leader refuses a peer its gossip
// sees as dead). It runs out after cluster.OwnershipLease, half the grace,
// without one. Then the worker fences every local recreate-policy sandbox: it
// freezes the running ones in place (runtime.Freezer), refuses to start them,
// skips their lifecycle timers, clusterroute.Wrap answers 503 for them, and
// their public HTTP port routes answer 503 + Retry-After instead of proxying
// (a frozen process keeps its listening socket, so the proxy would take each
// connection and never answer it).
// When a read succeeds again, a sandbox whose placement still names this node
// and the same lifetime is thawed; one that moved stays frozen until
// reconcileStaleOwnership removes it, as it always has.
//
// Why half the grace is safe. The leader's grace clock for this node starts
// when its gossip first sees the node dead, and its eviction loop ticks every
// 5 s on top of that. A successful read means the leader's gossip saw this
// node alive when it answered (withInternalMTLS refuses a peer it sees as
// dead), so that clock cannot have started before the read was sent. The
// lease counts from the send time, and the expiry check runs every lease/15,
// so the freeze lands at most lease + lease/15 (16 s by default) after the
// last proven contact, against an earliest reassignment of grace (30 s) after
// it: 14 s of margin before the leader can even ask another node to start a
// copy, which then still has to boot it.
//
// Why a slow but healthy network does not trip it. A read is tried every
// lease/3 (5 s) with a lease/3 timeout, so the lease survives two consecutive
// failed reads and needs three, spanning more than the whole lease, to run
// out. A leader election (1-2 s with the raft defaults) costs at most one.
//
// Only recreate-policy sandboxes are fenced: every other sandbox is orphaned
// on owner death, never moved, so this node stays its only executor.

// ErrOwnershipFenced is the answer for a sandbox this node has not been able
// to prove it still owns: it is frozen until the control plane answers.
var ErrOwnershipFenced = errors.New("cluster: this node cannot reach the control plane to confirm it still owns the sandbox; it is paused until it can")

// ownershipFencedSandboxes is the number of sandboxes this node holds fenced.
var ownershipFencedSandboxes = expvar.NewInt("aerolvm_cluster_ownership_fenced_sandboxes")

// ownershipLease is the worker's lease state. The zero value is a lease that
// has not begun, which fences nothing.
type ownershipLease struct {
	// mu guards the fields below. It is never held across a runtime or
	// control-plane call, so the request path's OwnershipFenced never waits.
	mu sync.Mutex
	// confirmed is when the last successful authoritative read was sent
	// (process start before the first). Zero: the lease has not begun.
	confirmed time.Time
	// confirmedSinceStart is set by the first successful read after start.
	// That read also thaws what a previous process may have left frozen.
	confirmedSinceStart bool
	// started guards StartOwnershipLease against a second set of loops.
	started bool
	fenced  map[string]*fencedSandbox
	// routeRestore holds sandboxes whose fence has been lifted but whose
	// public HTTP routes still answer 503: the swap back failed, and every
	// check retries it until it lands.
	routeRestore map[string]struct{}

	// actionMu serializes the expiry check and the confirm, which both
	// freeze or thaw runtime instances.
	actionMu sync.Mutex

	// owned is what the last successful authoritative read proved, per
	// local sandbox: the placement names this node, is placed, is the same
	// lifetime as the local row, at this OwnerEpoch. ownedAt is when that
	// read was sent. Kept only with SB_CLUSTER_OWNER_CACHE on (E3b): the
	// router then serves a forward whose epoch matches without looking the
	// sandbox up again (OwnerLeaseCheck).
	owned   map[string]uint64
	ownedAt time.Time
}

// OwnerLeaseVerdict is what the owner's last authoritative read says about a
// forward that carries an owner epoch (cluster.HeaderOwnerEpoch).
type OwnerLeaseVerdict int

const (
	// OwnerLeaseUnknown: the read cannot decide (no read, too old, no
	// entry, an older epoch than the forward's, the sandbox is fenced, the
	// flag is off). The router looks the sandbox up, as without E3b.
	OwnerLeaseUnknown OwnerLeaseVerdict = iota
	// OwnerLeaseOwned: the read proves this node owns the sandbox at the
	// forward's epoch. Two authoritative readings agree, so the router
	// serves without a lookup.
	OwnerLeaseOwned
	// OwnerLeaseNewer: the read holds a newer epoch than the forward's: the
	// edge's view predates an owner change this node already saw.
	OwnerLeaseNewer
)

// ownerLeaseHintedMaxAge bounds how old a read may be to vouch for a
// cache-routed forward. The edge's entry may be up to the cache TTL old, so
// the owner's read is the only fresh evidence; 2 s matches how far behind a
// follower may answer a lookup before it refuses (cluster stale-read bound),
// which is what the owner's own lookup would have risked.
const ownerLeaseHintedMaxAge = 2 * time.Second

// ownerFastPathEnabled reports whether the lease keeps per-sandbox owner
// epochs for the router (E3b). It rides the owner cache flag: the two halves
// are turned on together. A server-role node answers lookups from its own
// placement copy, so it has no round trip to save and keeps the lease's
// smaller read, as the owner cache ignores the flag there too.
func (s *Service) ownerFastPathEnabled() bool {
	return s != nil && s.cfg.EnableCluster && s.cfg.ClusterOwnerCache && !s.cfg.IsServer()
}

// OwnerLeaseCheck compares a forward's owner epoch with the last
// authoritative read. A forward that came from a fresh edge lookup (hinted
// false) may lean on a read as old as the lease itself: the edge's lookup is
// the fresh evidence and the read only has to agree with it. A cache-routed
// forward (hinted true) needs a read under ownerLeaseHintedMaxAge.
func (s *Service) OwnerLeaseCheck(id string, epoch uint64, hinted bool, now time.Time) OwnerLeaseVerdict {
	if !s.ownerFastPathEnabled() || epoch == 0 || id == "" {
		return OwnerLeaseUnknown
	}
	maxAge := cluster.OwnershipLease(s.cfg)
	if hinted {
		maxAge = min(maxAge, ownerLeaseHintedMaxAge)
	}
	s.ownership.mu.Lock()
	defer s.ownership.mu.Unlock()
	if s.ownership.owned == nil || s.ownership.ownedAt.IsZero() || now.Sub(s.ownership.ownedAt) > maxAge {
		return OwnerLeaseUnknown
	}
	if _, fenced := s.ownership.fenced[id]; fenced {
		return OwnerLeaseUnknown
	}
	have, ok := s.ownership.owned[id]
	switch {
	case !ok:
		return OwnerLeaseUnknown
	case have == epoch:
		return OwnerLeaseOwned
	case have > epoch:
		return OwnerLeaseNewer
	default:
		return OwnerLeaseUnknown
	}
}

// SetOwnerLeaseForTest installs an owned-epoch reading taken at at, for
// tests outside this package that exercise the router's fast path.
func (s *Service) SetOwnerLeaseForTest(owned map[string]uint64, at time.Time) {
	s.ownership.mu.Lock()
	defer s.ownership.mu.Unlock()
	s.ownership.owned, s.ownership.ownedAt = owned, at
}

// fencedSandbox is one sandbox held by the fence.
type fencedSandbox struct {
	// frozen: the runtime froze it, so a resume must thaw it.
	frozen bool
	// cannotFreeze: its runtime has no Freezer; logged once.
	cannotFreeze bool
	// routesFenced: every public HTTP port answers 503. Until it is set,
	// every check retries the swap.
	routesFenced bool
}

// ownershipLeaseApplies reports whether this node runs a lease at all: only
// in cluster mode, where another node can be handed this node's sandboxes.
func (s *Service) ownershipLeaseApplies() bool {
	return s != nil && s.cfg.EnableCluster && s.store != nil && s.Cluster() != nil
}

// StartOwnershipLease begins the lease and runs its two loops: an
// authoritative read every lease/3, and an expiry check every lease/15 (a
// local clock comparison; it touches the runtime only when the lease has run
// out). A no-op in single-node mode, and when already started.
func (s *Service) StartOwnershipLease(ctx context.Context) {
	if !s.ownershipLeaseApplies() {
		return
	}
	s.ownership.mu.Lock()
	if s.ownership.started {
		s.ownership.mu.Unlock()
		return
	}
	s.ownership.started = true
	s.ownership.mu.Unlock()
	s.beginOwnershipLease(time.Now())

	lease := cluster.OwnershipLease(s.cfg)
	probe := max(lease/3, 10*time.Millisecond)
	check := max(lease/15, 10*time.Millisecond)
	s.startPeriodic(ctx, probe, probe, func(c context.Context) {
		_ = s.confirmOwnership(c, time.Now())
	})
	s.startPeriodic(ctx, check, lease, func(c context.Context) {
		s.enforceOwnershipLease(c, time.Now())
	})
	if s.ownershipLeaseFileOn() {
		go s.runOwnershipLeaseFileWriter(ctx)
	}
}

// beginOwnershipLease starts the lease clock at now: a node that has just
// started has seen no evidence against its ownership yet, and gets one lease
// to find some for it.
func (s *Service) beginOwnershipLease(now time.Time) {
	if !s.ownershipLeaseApplies() {
		return
	}
	s.ownership.mu.Lock()
	if s.ownership.confirmed.IsZero() {
		s.ownership.confirmed = now
	}
	s.ownership.mu.Unlock()
}

// OwnershipFenced reports whether id is held by the ownership fence. It is
// what clusterroute.Wrap asks before serving a sandbox locally.
func (s *Service) OwnershipFenced(id string) bool {
	if s == nil {
		return false
	}
	s.ownership.mu.Lock()
	_, ok := s.ownership.fenced[id]
	s.ownership.mu.Unlock()
	// A sandbox released for a decommission move (C9) is held the same way:
	// its placement is about to name another node.
	return ok || s.moveFenced(id)
}

// FenceOwnershipForTest marks ids fenced without touching the runtime, for
// tests outside this package that exercise the 503.
func (s *Service) FenceOwnershipForTest(ids ...string) {
	s.ownership.mu.Lock()
	defer s.ownership.mu.Unlock()
	for _, id := range ids {
		s.fenceLocked(id)
	}
}

func (s *Service) fenceLocked(id string) *fencedSandbox {
	if s.ownership.fenced == nil {
		s.ownership.fenced = make(map[string]*fencedSandbox)
	}
	f, ok := s.ownership.fenced[id]
	if !ok {
		f = &fencedSandbox{}
		s.ownership.fenced[id] = f
		ownershipFencedSandboxes.Set(int64(len(s.ownership.fenced)))
	}
	return f
}

func (s *Service) unfenceLocked(id string) {
	if _, ok := s.ownership.fenced[id]; ok {
		// Its routes may answer 503 (all of them, or the ones a partly
		// failed swap reached) until restoreFencedRoutes swaps them back.
		if s.ownership.routeRestore == nil {
			s.ownership.routeRestore = make(map[string]struct{})
		}
		s.ownership.routeRestore[id] = struct{}{}
	}
	delete(s.ownership.fenced, id)
	ownershipFencedSandboxes.Set(int64(len(s.ownership.fenced)))
}

// confirmOwnership is one authoritative read, sent at sent. On success the
// lease runs from sent, and every fenced sandbox whose placement proves this
// node still owns it is thawed. A node with no recreate-policy sandbox has
// nothing to confirm and keeps its lease without a read.
func (s *Service) confirmOwnership(ctx context.Context, sent time.Time) error {
	if !s.ownershipLeaseApplies() {
		return nil
	}
	s.ownership.actionMu.Lock()
	defer s.ownership.actionMu.Unlock()
	live, err := s.localLiveSandboxes(ctx)
	if err != nil {
		return err
	}
	rows := recreateSandboxes(live)
	// The lease itself needs only the recreate-policy sandboxes: no other
	// sandbox is ever moved away from a live node. With the router's fast
	// path on (E3b), the read covers every local sandbox, so the router can
	// trust its epochs for all of them.
	read := rows
	if s.ownerFastPathEnabled() {
		read = live
	}
	c := s.Cluster()
	var placements map[string]cluster.Placement
	if len(read) > 0 {
		ids := make([]string, 0, len(read))
		for _, sb := range read {
			ids = append(ids, sb.ID)
		}
		placements, err = authoritativePlacementsForLease(ctx, c, ids)
		if err != nil {
			if s.logger != nil {
				s.logger.Debug("cluster: ownership lease read failed", "sandboxes", len(ids), "error", err)
			}
			return err
		}
	}

	self := strings.TrimSpace(c.SelfNodeID())
	// The file first, so the runtime supervisor thaws a group it froze
	// before the thaws below resume the tasks in it.
	s.recordOwnershipRead(ctx, sent, rows, placements, self)
	s.ownership.mu.Lock()
	if sent.After(s.ownership.confirmed) {
		s.ownership.confirmed = sent
	}
	if s.ownerFastPathEnabled() && sent.After(s.ownership.ownedAt) {
		owned := make(map[string]uint64, len(read))
		for _, sb := range read {
			if p, ok := placements[sb.ID]; ownershipProven(p, ok, self, sb) && p.OwnerEpoch != 0 {
				owned[sb.ID] = p.OwnerEpoch
			}
		}
		s.ownership.owned, s.ownership.ownedAt = owned, sent
	}
	firstSinceStart := !s.ownership.confirmedSinceStart && len(rows) > 0
	if len(rows) > 0 {
		s.ownership.confirmedSinceStart = true
	}
	present := make(map[string]struct{}, len(rows))
	for _, sb := range rows {
		present[sb.ID] = struct{}{}
	}
	fenced := make(map[string]bool, len(s.ownership.fenced))
	for id, f := range s.ownership.fenced {
		if _, ok := present[id]; !ok {
			// The row is gone (the stale-ownership path removed it).
			s.unfenceLocked(id)
			continue
		}
		fenced[id] = f.frozen
	}
	s.ownership.mu.Unlock()

	for _, sb := range rows {
		frozen, isFenced := fenced[sb.ID]
		if !isFenced && !firstSinceStart {
			continue
		}
		p, ok := placements[sb.ID]
		if !ownershipProven(p, ok, self, sb) {
			continue
		}
		// After a restart a previous process may have left the instance
		// frozen with no record of it here; a thaw of an instance that is
		// not frozen is a no-op.
		if frozen || (!isFenced && sb.Status == models.SandboxStatusStarted) {
			if err := s.thawSandbox(ctx, sb); err != nil {
				if s.logger != nil {
					s.logger.Warn("cluster: thaw after ownership was confirmed failed; will retry", "sandbox_id", sb.ID, "error", err)
				}
				continue
			}
		}
		if isFenced {
			s.ownership.mu.Lock()
			s.unfenceLocked(sb.ID)
			s.ownership.mu.Unlock()
			if s.logger != nil {
				s.logger.Info("cluster: ownership confirmed; sandbox resumed", "sandbox_id", sb.ID)
			}
		}
	}
	s.restoreFencedRoutes(ctx)
	return nil
}

// ownershipProven reports whether a placement proves this node still owns the
// local sandbox sb: it exists, is placed (not reserved, being deleted or
// orphaned), names this node, and belongs to the same lifetime of the id.
func ownershipProven(p cluster.Placement, ok bool, self string, sb *models.Sandbox) bool {
	if !ok || p.IsOrphaned() || p.IsDeleting() || p.IsReserved() {
		return false
	}
	if strings.TrimSpace(p.OwnerNodeID) != self {
		return false
	}
	local, placed := strings.TrimSpace(sb.AuditIncarnationID), strings.TrimSpace(p.IncarnationID)
	return local == "" || placed == "" || local == placed
}

// enforceOwnershipLease fences every local recreate-policy sandbox once the
// lease has run out at now. A sandbox already fenced and frozen is left alone;
// a freeze that failed is tried again.
func (s *Service) enforceOwnershipLease(ctx context.Context, now time.Time) {
	if !s.ownershipLeaseApplies() {
		return
	}
	s.ownership.actionMu.Lock()
	defer s.ownership.actionMu.Unlock()
	s.restoreFencedRoutes(ctx)
	lease := cluster.OwnershipLease(s.cfg)
	s.ownership.mu.Lock()
	confirmed := s.ownership.confirmed
	wasFenced := len(s.ownership.fenced)
	s.ownership.mu.Unlock()
	if confirmed.IsZero() || now.Sub(confirmed) <= lease {
		return
	}
	rows, err := s.localRecreateSandboxes(ctx)
	if err != nil {
		return
	}
	for _, sb := range rows {
		if s.fenceSettled(sb) {
			continue
		}
		s.fenceSandbox(ctx, sb.ID)
	}
	s.ownership.mu.Lock()
	nowFenced := len(s.ownership.fenced)
	s.ownership.mu.Unlock()
	if nowFenced > wasFenced && s.logger != nil {
		s.logger.Warn("cluster: no authoritative read from the control plane within the ownership lease; failover.policy=recreate sandboxes are paused until one succeeds",
			"since_last_read", now.Sub(confirmed).Round(time.Millisecond), "lease", lease, "fenced", nowFenced)
	}
}

// fenceSettled reports whether sb is already fenced with nothing left to do:
// frozen, not freezable, or not running (a fenced sandbox cannot be started).
// It keeps a long partition from re-locking every sandbox on every check.
func (s *Service) fenceSettled(sb *models.Sandbox) bool {
	s.ownership.mu.Lock()
	defer s.ownership.mu.Unlock()
	f, ok := s.ownership.fenced[sb.ID]
	return ok && f.routesFenced && (f.frozen || f.cannotFreeze || sb.Status != models.SandboxStatusStarted)
}

// fenceSandbox fences id and freezes its instance if it is running. It holds
// the sandbox's lifecycle boundary, so a start, stop or destroy in flight
// finishes first and none begins until the fence is in place.
func (s *Service) fenceSandbox(ctx context.Context, id string) {
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return
	}
	defer unlock()
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return
	}
	s.ownership.mu.Lock()
	f := s.fenceLocked(id)
	frozen, cannot, routed := f.frozen, f.cannotFreeze, f.routesFenced
	s.ownership.mu.Unlock()
	// The ingress proxy's warm fast path must not reach it either.
	s.invalidateWarm(id)
	// Its public URLs answer 503 before it freezes, so no request is
	// proxied to a process that will never answer.
	if !routed {
		s.fenceSandboxRoutes(ctx, sb)
	}
	if frozen || cannot || sb.Status != models.SandboxStatusStarted {
		return
	}
	rt, err := s.runtimeForSandbox(sb)
	if err != nil {
		return
	}
	fr, ok := rt.(runtime.Freezer)
	if !ok {
		s.ownership.mu.Lock()
		f.cannotFreeze = true
		s.ownership.mu.Unlock()
		if s.logger != nil {
			s.logger.Warn("cluster: this runtime cannot pause a sandbox in place; it is refused but keeps running until ownership is confirmed",
				"sandbox_id", id, "runtime", sb.Runtime)
		}
		return
	}
	if err := fr.Freeze(ctx, s.runtimeRef(sb)); err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: freeze of a fenced sandbox failed; will retry", "sandbox_id", id, "error", err)
		}
		return
	}
	s.ownership.mu.Lock()
	f.frozen = true
	s.ownership.mu.Unlock()
}

// fenceSandboxRoutes swaps every public route of a fenced sandbox for its
// fenced shape (syncPublicRoutes): 503 for HTTP ports, the root (toolbox)
// route and custom domains; an immediate close for raw TCP and TLS ports. A
// failure leaves routesFenced unset, so the next check retries; routes
// already swapped are rewritten in place, which is idempotent.
func (s *Service) fenceSandboxRoutes(ctx context.Context, sb *models.Sandbox) {
	err := s.syncPublicRoutes(ctx, sb)
	s.ownership.mu.Lock()
	if f, ok := s.ownership.fenced[sb.ID]; ok {
		f.routesFenced = err == nil
	}
	// A fence that comes back before the last swap back landed owns the
	// routes again.
	delete(s.ownership.routeRestore, sb.ID)
	s.ownership.mu.Unlock()
	if err != nil && s.logger != nil {
		s.logger.Warn("cluster: could not point a fenced sandbox's public URLs at 503; will retry", "sandbox_id", sb.ID, "error", err)
	}
}

// restoreFencedRoutes swaps the public HTTP routes of every sandbox whose
// fence has been lifted back to their normal shape. Rollback rule: until a
// sandbox's swap back has fully landed it stays in routeRestore, its routes
// keep answering 503 (a quick, retryable answer, never a hang), and every
// check tries again. A sandbox fenced again is left to the fence; one whose
// row is gone was destroyed, and the destroy removed its routes. The caller
// holds actionMu, so no fence runs meanwhile.
func (s *Service) restoreFencedRoutes(ctx context.Context) {
	s.ownership.mu.Lock()
	ids := make([]string, 0, len(s.ownership.routeRestore))
	for id := range s.ownership.routeRestore {
		ids = append(ids, id)
	}
	s.ownership.mu.Unlock()
	for _, id := range ids {
		if s.OwnershipFenced(id) {
			continue
		}
		sb, err := s.store.Get(ctx, id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err == nil {
			if err := s.syncPublicRoutes(ctx, sb); err != nil {
				if s.logger != nil {
					s.logger.Warn("cluster: could not restore a resumed sandbox's public URLs; they answer 503 until a retry lands", "sandbox_id", id, "error", err)
				}
				continue
			}
		}
		s.ownership.mu.Lock()
		delete(s.ownership.routeRestore, id)
		s.ownership.mu.Unlock()
	}
}

// syncPublicRoutes rewrites every public route of sb in the shape its state
// asks for, fenced or not: its exposed ports of every protocol
// (syncExposedPortRoutes), its root route and custom domains
// (syncSandboxPublicRoute, then the WASM mediator dials). The fence and the
// restore both call it.
func (s *Service) syncPublicRoutes(ctx context.Context, sb *models.Sandbox) error {
	err := s.syncExposedPortRoutes(ctx, sb)
	if rerr := s.syncSandboxPublicRoute(ctx, sb); rerr != nil && err == nil {
		err = rerr
	}
	if werr := s.syncWasmCustomDomainRoutes(ctx, sb); werr != nil && err == nil {
		err = werr
	}
	return err
}

// syncExposedPortRoutes rewrites the route of every exposure of sb, in the
// shape its state asks for (syncExposedPortRoute: public or not, then
// applyHTTPPortRoute, installTCPPortRoute or installTLSPortRoute: fenced or
// not, serverless or not).
func (s *Service) syncExposedPortRoutes(ctx context.Context, sb *models.Sandbox) error {
	var firstErr error
	for _, port := range sb.ExposedPorts {
		if err := s.syncExposedPortRoute(ctx, sb, port); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// applyFencedHTTPPortRoute is applyHTTPPortRoute for a fenced sandbox: the
// port answers 503 + Retry-After under the port route's own id, and a wake
// route (serverless, token-gated) goes the way the direct shape removes it.
// The caller holds the port's httpRouteLocks.
func (s *Service) applyFencedHTTPPortRoute(ctx context.Context, id string, port int) error {
	if err := s.publicRoutes().UpsertFencedPortRoute(ctx, id, port); err != nil {
		return err
	}
	_ = s.publicRoutes().DeleteWakeHTTPPortRoute(ctx, id, port)
	return nil
}

// thawSandbox thaws sb's instance under its lifecycle boundary. A runtime
// without Freezer never froze it.
func (s *Service) thawSandbox(ctx context.Context, sb *models.Sandbox) error {
	unlock, err := s.lifecycleLocks.lockCtx(ctx, sb.ID)
	if err != nil {
		return err
	}
	defer unlock()
	rt, err := s.runtimeForSandbox(sb)
	if err != nil {
		return err
	}
	fr, ok := rt.(runtime.Freezer)
	if !ok {
		return nil
	}
	return fr.Thaw(ctx, s.runtimeRef(sb))
}

// localRecreateSandboxes lists this node's failover.policy=recreate rows: the
// only sandboxes another node can be handed while this one still runs them.
func (s *Service) localRecreateSandboxes(ctx context.Context) ([]*models.Sandbox, error) {
	live, err := s.localLiveSandboxes(ctx)
	if err != nil {
		return nil, err
	}
	return recreateSandboxes(live), nil
}

// localLiveSandboxes lists every local sandbox row that is not destroyed.
func (s *Service) localLiveSandboxes(ctx context.Context) ([]*models.Sandbox, error) {
	all, err := s.store.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*models.Sandbox, 0, len(all))
	for _, sb := range all {
		if sb == nil || sb.ID == "" || sb.Status == models.SandboxStatusDestroyed {
			continue
		}
		out = append(out, sb)
	}
	return out, nil
}

// recreateSandboxes keeps the failover.policy=recreate rows of live.
func recreateSandboxes(live []*models.Sandbox) []*models.Sandbox {
	out := make([]*models.Sandbox, 0, len(live))
	for _, sb := range live {
		if sb.Failover != nil && sb.Failover.ShouldRecreate() {
			out = append(out, sb)
		}
	}
	return out
}

// authoritativePlacementsForLease reads ids from the leader in pages the
// control plane accepts. Any failed page fails the read: a partial answer
// proves nothing about the rest.
func authoritativePlacementsForLease(ctx context.Context, c cluster.Client, ids []string) (map[string]cluster.Placement, error) {
	out := make(map[string]cluster.Placement, len(ids))
	for start := 0; start < len(ids); start += cluster.MaxPlacementPageLimit {
		end := min(start+cluster.MaxPlacementPageLimit, len(ids))
		page, err := c.AuthoritativePlacementsByIDs(ctx, ids[start:end])
		if err != nil {
			return nil, err
		}
		for id, p := range page {
			out[id] = p
		}
	}
	return out, nil
}

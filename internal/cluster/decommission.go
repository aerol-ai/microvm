package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// Decommission, the leader's half (C9, plans/kubernetes-v2-architecture.md
// §10.5; the worker's half is internal/service/decommission.go).
//
// The operator decommissions a worker before its machine goes: it cordons
// the node, waits the drain window, then calls EvacuateNode (POST
// /v1/cluster/nodes/{id}/evacuate) until nothing is left, and deletes the
// node. Each call is one bounded, idempotent pass, so the operator records
// progress on the AerolNode and a leader change loses nothing: the next
// leader's pass picks up from the placements as they stand.
//
// A pass:
//
//   - moves up to EvacuateRequest.Max failover.policy=recreate sandboxes,
//     each "prepare before break" (keeps I1, one executor): the target
//     pulls the image, the source stops and fences its copy, then one
//     compare-and-swap on the source as owner moves the placement, and the
//     target's owner watcher recreates it. The target is in another zone
//     when one has room (C10).
//   - tells the owner of every other sandbox, once per leader, that it
//     stops at the deadline (an audit record on the sandbox);
//   - with StopRemaining (the deadline passed), stops those others. They
//     are orphaned when the node is deleted.
//
// A move whose release or swap fails is left for the next pass. A source
// that dies mid-decommission is no longer evacuated: the dead-owner
// failover takes it from there.
//
// A sandbox that cannot move is one of the others, whatever its policy
// asked for: it is noticed, stopped at the deadline and orphaned (a
// recreate-policy one goes to the failover when the node is deleted). The
// leader knows it cannot move when
//
//   - its placement says so: its image is kept on this node only
//     (local_only, or built here), so no other node can run it;
//   - no other worker can restore its snapshot (snapshotRestorers): a
//     gVisor checkpoint of the source's privilege mode, or a build and
//     architecture the source's snapshot fits. Checked again every pass, so
//     a worker that joins makes it movable again;
//   - its source refused the move for good (MoveRefusedPrefix: a warm-pool
//     gVisor sandbox, a runtime that moves nothing by snapshot). This
//     leader remembers that for the decommission; a new leader asks again;
//   - the deadline passed and its move failed: past the deadline every
//     sandbox gets one more try, and one that fails it is stopped with the
//     rest. Before the deadline a failure is retried every pass.
//
// Without that, a sandbox that was counted as movable but never moved kept
// RemainingMovable above zero, and the operator, which ends a decommission
// past its deadline only once nothing movable is left, never ended it.

// MoveHandler is the worker's half, which the leader calls on a peer over
// its internal route and on itself directly. *service.Service implements
// it; AttachMoveHandler wires it in.
type MoveHandler interface {
	// ReleaseForMove and StopForDecommission take, per id, the incarnation
	// the leader read (MoveAction.Incarnations): a row of another lifetime
	// is not the sandbox the leader means.
	ReleaseForMove(ctx context.Context, ids []string, lifetimes map[string]string) map[string]string
	StopForDecommission(ctx context.Context, ids []string, lifetimes map[string]string) map[string]string
	PrepareMove(ctx context.Context, spec models.CreateSandboxRequest) error
	NoticeDecommission(ctx context.Context, ids []string, deadline time.Time) int
}

// NodeEvacuator is the leader side of POST /v1/cluster/nodes/{id}/evacuate.
type NodeEvacuator interface {
	EvacuateNode(ctx context.Context, nodeID string, req EvacuateRequest) (EvacuateResult, error)
}

// EvacuateRequest is the body of an evacuate pass.
type EvacuateRequest struct {
	// DeadlineUnix is when the sandboxes that cannot move are stopped; the
	// owner notice names it. Zero: one hour from now.
	DeadlineUnix int64 `json:"deadline_unix,omitempty"`
	// StopRemaining stops every sandbox that cannot move: the deadline
	// passed.
	StopRemaining bool `json:"stop_remaining,omitempty"`
	// Max bounds the moves this pass makes (default 8, at most 64).
	Max int `json:"max,omitempty"`
}

// EvacuateResult is one pass's outcome.
type EvacuateResult struct {
	NodeID string            `json:"node_id"`
	Moved  []string          `json:"moved,omitempty"`
	Failed map[string]string `json:"failed,omitempty"`
	// RemainingMovable is how many sandboxes that can still move are on
	// the node after this pass: recreate-policy and snapshot moves, less
	// those that cannot move (see above).
	RemainingMovable int `json:"remaining_movable"`
	// Remaining is how many other sandboxes are still placed on it.
	Remaining int `json:"remaining"`
	Noticed   int `json:"noticed,omitempty"`
	Stopped   int `json:"stopped,omitempty"`
	// Done is true when no sandbox is placed on the node: delete it.
	Done bool `json:"done"`
}

const (
	defaultEvacuateMoves = 8
	maxEvacuateMoves     = 64
	// prepareMoveTimeout bounds the target's image pull. A slower pull is
	// left to the recreate: the move goes on without it.
	prepareMoveTimeout = 90 * time.Second
	// moveStepTimeout bounds the release call to the source.
	moveStepTimeout = 30 * time.Second
	// MoveSuffix is the worker's internal move route: POST
	// /v1/cluster/nodes/{id}/move.
	MoveSuffix = "/move"
	// MoveRefusedPrefix starts a source's answer to a release it refuses
	// for good, followed by why: the sandbox cannot move from there at all,
	// so trying again changes nothing. Any other answer that is not
	// released or gone is an error the leader tries again. A leader from
	// before reads it as such an error.
	MoveRefusedPrefix = "refused: "
)

var (
	// ErrNodeNotDrained refuses an evacuate of a node still taking new
	// sandboxes: what moves off it would be replaced.
	ErrNodeNotDrained = errors.New("cluster: cordon the node before evacuating it")
	// ErrNodeNotAlive refuses an evacuate of a node gossip sees dead: its
	// sandboxes are the dead-owner failover's.
	ErrNodeNotAlive = errors.New("cluster: the node is not alive; the dead-owner failover handles its sandboxes")
	// ErrNoMoveHandler: the worker side was never attached.
	ErrNoMoveHandler = errors.New("cluster: this node cannot release sandboxes for a move")

	decommissionMoves = expvar.NewMap("aerolvm_cluster_decommission_moves_total")
)

// MoveAction is the body of the worker's internal move route.
type MoveAction struct {
	// Action is release, stop, notice or prepare; for a snapshot move
	// (snapshot_move.go) release-snapshot, import, drop or start-moved.
	Action string   `json:"action"`
	IDs    []string `json:"ids,omitempty"`
	// Incarnations names, per id, the lifetime the leader read when it
	// chose the action (R10). The worker checks it under the sandbox's
	// lifecycle lock before it stops anything: an id that is a new lifetime
	// by then is not the sandbox meant. The swap that follows checks it
	// too, but cannot undo a stop. A worker from before R10 ignores it.
	Incarnations map[string]string            `json:"incarnations,omitempty"`
	DeadlineUnix int64                        `json:"deadline_unix,omitempty"`
	Spec         *models.CreateSandboxRequest `json:"spec,omitempty"`
	// Target is release-snapshot's: the only node that may pull the bundle.
	Target string `json:"target,omitempty"`
	// Source is import's: the node to pull the bundle from.
	Source string `json:"source,omitempty"`
	// Recreate is start-moved's: what the target rebuilds a gVisor sandbox
	// from, out of the leader's full placement (a worker's placement reads
	// carry no spec).
	Recreate *MoveRecreate `json:"recreate,omitempty"`
}

// MoveActionResult answers a move action.
type MoveActionResult struct {
	Results map[string]string `json:"results,omitempty"`
	Count   int               `json:"count,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// RunMoveAction runs a on h: the worker side of the internal route.
func RunMoveAction(ctx context.Context, h MoveHandler, a MoveAction) (MoveActionResult, error) {
	if h == nil {
		return MoveActionResult{}, ErrNoMoveHandler
	}
	switch a.Action {
	case "release":
		return MoveActionResult{Results: h.ReleaseForMove(ctx, a.IDs, a.Incarnations)}, nil
	case "stop":
		return MoveActionResult{Results: h.StopForDecommission(ctx, a.IDs, a.Incarnations)}, nil
	case "notice":
		return MoveActionResult{Count: h.NoticeDecommission(ctx, a.IDs, time.Unix(a.DeadlineUnix, 0))}, nil
	case "prepare":
		if a.Spec == nil {
			return MoveActionResult{}, errors.New("prepare needs the sandbox spec")
		}
		if err := h.PrepareMove(ctx, *a.Spec); err != nil {
			return MoveActionResult{Error: err.Error()}, nil
		}
		return MoveActionResult{}, nil
	case "release-snapshot", "import", "drop", "start-moved":
		return runSnapshotMoveAction(ctx, h, a)
	default:
		return MoveActionResult{}, errors.New("unknown move action " + a.Action)
	}
}

// moveHandlerHolder keeps the attached MoveHandler.
type moveHandlerHolder struct {
	mu sync.RWMutex
	h  MoveHandler
	// decom is what this leader remembers of each node it evacuates. It is
	// not Raft state: a new leader starts empty, tells the owners again
	// and asks each source again.
	decom map[string]*decomMemory
	// peers stands in for other nodes' handlers in tests: a move action
	// for one of them runs here instead of over the internal route.
	peers map[string]MoveHandler
}

// decomMemory is one node's: the sandboxes whose owners were told, and
// those this leader no longer tries to move.
type decomMemory struct {
	noticed   map[string]bool
	unmovable map[string]unmovableMark
}

// unmovableMark is why a sandbox no longer moves, for the lifetime it was
// learned on: a new lifetime with the same id is asked again.
type unmovableMark struct {
	incarnation string
	reason      string
}

// moveRefusedError is a move its source refused for good
// (MoveRefusedPrefix).
type moveRefusedError struct {
	source, reason string
}

func (e *moveRefusedError) Error() string {
	return e.source + " refuses to move it: " + e.reason
}

// releaseRefusal is the error for a release on source that answered r
// instead of released.
func releaseRefusal(source, r string) error {
	if reason, ok := strings.CutPrefix(r, MoveRefusedPrefix); ok {
		return &moveRefusedError{source: source, reason: reason}
	}
	return errors.New("release on " + source + ": " + r)
}

// AttachMoveHandler wires in the worker side (the service).
func (c *Cluster) AttachMoveHandler(h MoveHandler) {
	c.moves.mu.Lock()
	c.moves.h = h
	c.moves.mu.Unlock()
}

func (c *Cluster) moveHandler() MoveHandler {
	c.moves.mu.RLock()
	defer c.moves.mu.RUnlock()
	return c.moves.h
}

// decomLocked is nodeID's memory, made on first use. Caller holds mu.
func (h *moveHandlerHolder) decomLocked(nodeID string) *decomMemory {
	if h.decom == nil {
		h.decom = make(map[string]*decomMemory)
	}
	m := h.decom[nodeID]
	if m == nil {
		m = &decomMemory{noticed: map[string]bool{}, unmovable: map[string]unmovableMark{}}
		h.decom[nodeID] = m
	}
	return m
}

// noticeOnce is those of ids whose owners this leader has not told yet
// about nodeID's decommission, and records that it now has. A sandbox that
// turns out not to move later in the decommission is told then.
func (c *Cluster) noticeOnce(nodeID string, ids []string) []string {
	c.moves.mu.Lock()
	defer c.moves.mu.Unlock()
	m := c.moves.decomLocked(nodeID)
	var fresh []string
	for _, id := range ids {
		if !m.noticed[id] {
			m.noticed[id] = true
			fresh = append(fresh, id)
		}
	}
	return fresh
}

// markUnmovable records that this leader no longer tries to move p off
// nodeID, and why.
func (c *Cluster) markUnmovable(nodeID string, p Placement, reason string) {
	c.moves.mu.Lock()
	defer c.moves.mu.Unlock()
	c.moves.decomLocked(nodeID).unmovable[p.SandboxID] = unmovableMark{incarnation: strings.TrimSpace(p.IncarnationID), reason: reason}
}

// unmovableReason is why this leader no longer tries to move p off nodeID,
// or "" when it still does.
func (c *Cluster) unmovableReason(nodeID string, p Placement) string {
	c.moves.mu.RLock()
	defer c.moves.mu.RUnlock()
	m := c.moves.decom[nodeID]
	if m == nil {
		return ""
	}
	mark, ok := m.unmovable[p.SandboxID]
	if !ok || mark.incarnation != strings.TrimSpace(p.IncarnationID) {
		return ""
	}
	return mark.reason
}

// keepDecommission forgets what this leader remembers of nodeID's
// sandboxes that are not in owned, and all of nodeID with owned nil (the
// node was deleted), so the memory stays as large as the sandboxes still on
// nodes being evacuated.
func (c *Cluster) keepDecommission(nodeID string, owned map[string]bool) {
	c.moves.mu.Lock()
	defer c.moves.mu.Unlock()
	m := c.moves.decom[nodeID]
	if m == nil {
		return
	}
	if owned == nil {
		delete(c.moves.decom, nodeID)
		return
	}
	for id := range m.noticed {
		if !owned[id] {
			delete(m.noticed, id)
		}
	}
	for id := range m.unmovable {
		if !owned[id] {
			delete(m.unmovable, id)
		}
	}
}

// moveCall runs a move action on node m: locally when it is this node.
func (c *Cluster) moveCall(ctx context.Context, m Member, a MoveAction) (MoveActionResult, error) {
	if m.NodeID == c.nodeID {
		return RunMoveAction(ctx, c.moveHandler(), a)
	}
	c.moves.mu.RLock()
	peer := c.moves.peers[m.NodeID]
	c.moves.mu.RUnlock()
	if peer != nil {
		return RunMoveAction(ctx, peer, a)
	}
	body, err := json.Marshal(a)
	if err != nil {
		return MoveActionResult{}, err
	}
	var out MoveActionResult
	err = c.peerJSON(ctx, m, http.MethodPost, PublicNodesPath+url.PathEscape(m.NodeID)+MoveSuffix, body, &out)
	return out, err
}

// EvacuateNode runs one decommission pass over nodeID's sandboxes.
func (c *Cluster) EvacuateNode(ctx context.Context, nodeID string, req EvacuateRequest) (EvacuateResult, error) {
	nodeID = strings.TrimSpace(nodeID)
	res := EvacuateResult{NodeID: nodeID}
	if c == nil || c.raft == nil || c.raft.raft == nil || c.raft.raft.State() != raft.Leader {
		return res, ErrNotLeader
	}
	if nodeID == "" {
		return res, errors.New("cluster: node id required")
	}
	drained := c.fsm.drainedNodesSnapshot()
	if !drained[nodeID] {
		return res, ErrNodeNotDrained
	}
	source, ok := c.gossip.lookupMember(nodeID)
	if !ok || !source.Alive {
		return res, ErrNodeNotAlive
	}
	// Its capacity, labels included, comes in its heartbeats, not with
	// gossip: whether it moves gVisor sandboxes is a label (checkpointMover).
	source.Capacity = c.heartbeatCapacity(source)
	limit := req.Max
	if limit <= 0 {
		limit = defaultEvacuateMoves
	}
	limit = min(limit, maxEvacuateMoves)
	deadline := time.Now().Add(time.Hour)
	if req.DeadlineUnix > 0 {
		deadline = time.Unix(req.DeadlineUnix, 0)
	}
	restorers := &snapshotRestorers{c: c, source: source, drained: drained}

	var movable []evacuee
	var others []string
	othersLifetimes := make(map[string]string)
	stays := func(p Placement) {
		others = append(others, p.SandboxID)
		if inc := strings.TrimSpace(p.IncarnationID); inc != "" {
			othersLifetimes[p.SandboxID] = inc
		}
	}
	notMoved := func(id, why string) {
		if res.Failed == nil {
			res.Failed = make(map[string]string)
		}
		res.Failed[id] = "not moved: " + why
	}
	for _, id := range c.fsm.idsOwnedBy(nodeID) {
		p, ok := c.fsm.get(id)
		if !ok || strings.TrimSpace(p.OwnerNodeID) != nodeID || p.IsDeleting() {
			continue
		}
		kind, why := c.evacuationOf(p, source, restorers)
		if kind != evacuateStays {
			movable = append(movable, evacuee{p: p, kind: kind})
			continue
		}
		if why != "" {
			notMoved(id, why)
		}
		stays(p)
	}
	sort.Slice(movable, func(i, j int) bool { return movable[i].p.SandboxID < movable[j].p.SandboxID })

	// Moves run side by side: the slow part is each target's image pull.
	batch := movable[:min(limit, len(movable))]
	type outcome struct {
		p   Placement
		err error
	}
	results := make(chan outcome, len(batch))
	var wg sync.WaitGroup
	for _, e := range batch {
		wg.Add(1)
		go func(e evacuee) {
			defer wg.Done()
			move := c.moveOne
			if e.kind == evacuateSnapshot {
				move = c.moveSnapshotOne
			}
			results <- outcome{p: e.p, err: move(ctx, e.p, source)}
		}(e)
	}
	wg.Wait()
	close(results)
	for o := range results {
		id := o.p.SandboxID
		if o.err == nil {
			res.Moved = append(res.Moved, id)
			decommissionMoves.Add("moved", 1)
			continue
		}
		decommissionMoves.Add("failed", 1)
		var refused *moveRefusedError
		switch {
		case errors.As(o.err, &refused):
			// Trying again changes nothing: it does not move, from now on.
			c.markUnmovable(nodeID, o.p, refused.Error())
			decommissionMoves.Add("refused", 1)
			c.logger.Info("cluster: decommission: a sandbox cannot move; it stops at the deadline", "node_id", nodeID, "sandbox_id", id, "err", o.err)
			notMoved(id, refused.Error())
			stays(o.p)
		case req.StopRemaining && ctx.Err() == nil:
			// Its last try, past the deadline, failed: it stops now with the
			// rest. A pass cut short by its caller (ctx) is not a try.
			why := "its move past the deadline failed: " + o.err.Error()
			c.markUnmovable(nodeID, o.p, why)
			decommissionMoves.Add("given_up", 1)
			c.logger.Warn("cluster: decommission: a sandbox did not move by the deadline; it stops with the rest", "node_id", nodeID, "sandbox_id", id, "err", o.err)
			notMoved(id, why)
			stays(o.p)
		default:
			// Before the deadline: the next pass tries again.
			if res.Failed == nil {
				res.Failed = make(map[string]string)
			}
			res.Failed[id] = o.err.Error()
		}
	}
	sort.Strings(res.Moved)
	sort.Strings(others)

	if fresh := c.noticeOnce(nodeID, others); len(fresh) > 0 {
		out, err := c.moveCall(ctx, source, MoveAction{Action: "notice", IDs: fresh, DeadlineUnix: deadline.Unix()})
		if err != nil {
			// Told on the next leader's pass, or not at all: the notice is
			// a courtesy, the deadline stop still comes.
			c.logger.Warn("cluster: decommission notice failed", "node_id", nodeID, "err", err)
		}
		res.Noticed = out.Count
	}
	if req.StopRemaining && len(others) > 0 {
		out, err := c.moveCall(ctx, source, MoveAction{Action: "stop", IDs: others, Incarnations: othersLifetimes})
		if err != nil {
			return res, err
		}
		for _, r := range out.Results {
			if r == "stopped" || r == "gone" {
				res.Stopped++
			}
		}
	}

	owned := make(map[string]bool)
	for _, id := range c.fsm.idsOwnedBy(nodeID) {
		p, ok := c.fsm.get(id)
		if !ok || strings.TrimSpace(p.OwnerNodeID) != nodeID {
			continue
		}
		owned[id] = true
		if kind, _ := c.evacuationOf(p, source, restorers); kind != evacuateStays {
			res.RemainingMovable++
		} else {
			res.Remaining++
		}
	}
	c.keepDecommission(nodeID, owned)
	res.Done = res.RemainingMovable == 0 && res.Remaining == 0
	c.logger.Info("cluster: decommission pass", "node_id", nodeID, "moved", len(res.Moved), "failed", len(res.Failed),
		"remaining_movable", res.RemainingMovable, "remaining", res.Remaining, "stopped", res.Stopped)
	return res, nil
}

// evacuation is how a decommission pass treats one sandbox.
type evacuation int

const (
	// evacuateStays: one of the others, noticed, stopped at the deadline
	// and orphaned when the node is deleted.
	evacuateStays evacuation = iota
	// evacuateRecreate: moveOne, stopped here and recreated on the target.
	evacuateRecreate
	// evacuateSnapshot: moveSnapshotOne, moved with its memory.
	evacuateSnapshot
)

// evacuee is a sandbox a pass moves, and how.
type evacuee struct {
	p    Placement
	kind evacuation
}

// evacuationOf is how a pass treats p on source, and, for a sandbox that
// asked to move but cannot, why not (see the package comment above). Both
// counts of a pass, and the move it makes, read it, so a sandbox that
// cannot move is never counted as movable.
func (c *Cluster) evacuationOf(p Placement, source Member, restorers *snapshotRestorers) (evacuation, string) {
	kind := evacuateStays
	switch {
	case placementRebuildsElsewhere(p):
		kind = evacuateRecreate
	case placementWantsSnapshotMove(p, source):
		kind = evacuateSnapshot
	default:
		if refusal := hostOnlyRefusal(p); refusal != nil && placementWantsFailoverRecreate(p) {
			// Refused up front: another node would not rebuild it
			// (rebuild_refusal.go).
			return evacuateStays, refusal.Error()
		}
		return evacuateStays, ""
	}
	if why := c.unmovableReason(source.NodeID, p); why != "" {
		return evacuateStays, why
	}
	if why := imageStaysOn(p, source.NodeID); why != "" {
		return evacuateStays, why
	}
	if kind == evacuateSnapshot {
		if why := restorers.refusal(p); why != "" {
			return evacuateStays, why
		}
	}
	return kind, ""
}

// imageStaysOn is why p's image runs only on nodeID, or "": no target
// selection takes it elsewhere (selectRecreationTargetAvoiding).
func imageStaysOn(p Placement, nodeID string) string {
	if p.Spec == nil {
		return ""
	}
	if p.Spec.ImageDistributionMode == models.ImageDistributionLocalOnly {
		return "its image is kept on this node only (image distribution local_only)"
	}
	if node, ok := docker.BuiltImagePlacementNode(p.Spec.Image); ok && node == nodeID {
		return "its image was built on this node and is kept there only"
	}
	return ""
}

// releaseAction is the action that stops p on its source, naming the
// lifetime this leader read (R10).
func releaseAction(action string, p Placement) MoveAction {
	a := MoveAction{Action: action, IDs: []string{p.SandboxID}}
	if inc := strings.TrimSpace(p.IncarnationID); inc != "" {
		a.Incarnations = map[string]string{p.SandboxID: inc}
	}
	return a
}

// moveOne moves p off source, prepare before break. The order is what keeps
// one executor: the source's copy is stopped and fenced before the
// placement names the target, and the swap is fenced on source as owner and
// on p's incarnation, so a placement another path moved meanwhile stays put.
func (c *Cluster) moveOne(ctx context.Context, p Placement, source Member) error {
	target, err := c.selectRecreationTargetAvoiding(p, c.lastKnownZone(source.NodeID), source.NodeID)
	if err != nil {
		return err
	}
	if p.Spec != nil {
		if m, ok := c.gossip.lookupMember(target.NodeID); ok || target.IsSelf {
			if target.IsSelf {
				m = Member{NodeID: c.nodeID}
			}
			pctx, cancel := context.WithTimeout(ctx, prepareMoveTimeout)
			out, perr := c.moveCall(pctx, m, MoveAction{Action: "prepare", Spec: p.Spec})
			cancel()
			if perr != nil || out.Error != "" {
				// Best effort: the recreate pulls what was not pulled here.
				c.logger.Info("cluster: decommission move goes on without a pre-pull",
					"sandbox_id", p.SandboxID, "target", target.NodeID, "err", perr, "reason", out.Error)
			}
		}
	}
	rctx, cancel := context.WithTimeout(ctx, moveStepTimeout)
	out, err := c.moveCall(rctx, source, releaseAction("release", p))
	cancel()
	if err != nil {
		return err
	}
	if r := out.Results[p.SandboxID]; r != "released" && r != "gone" {
		return releaseRefusal(source.NodeID, r)
	}
	return c.applyCommand(ctx, command{
		Op:                     opReassign,
		SandboxID:              p.SandboxID,
		OwnerNodeID:            target.NodeID,
		OwnerAPIURL:            target.APIURL,
		OwnerDataPlaneHost:     target.DataPlaneHost,
		ExpectedIncarnationID:  strings.TrimSpace(p.IncarnationID),
		ExpectedOwnerNodeID:    source.NodeID,
		ExpectedOwnerNodeIDSet: true,
		// Counted as a failover move in the FSM: the target's load is
		// unreported until its next heartbeat, as after any failover. A new
		// cause would apply differently on an older server.
		ReassignCause: reassignCauseFailover,
	})
}

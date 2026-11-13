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

// MoveHandler is the worker's half, which the leader calls on a peer over
// its internal route and on itself directly. *service.Service implements
// it; AttachMoveHandler wires it in.
type MoveHandler interface {
	ReleaseForMove(ctx context.Context, ids []string) map[string]string
	StopForDecommission(ctx context.Context, ids []string) map[string]string
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
	// RemainingMovable is how many recreate-policy sandboxes are still on
	// the node after this pass.
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
	Action       string                       `json:"action"`
	IDs          []string                     `json:"ids,omitempty"`
	DeadlineUnix int64                        `json:"deadline_unix,omitempty"`
	Spec         *models.CreateSandboxRequest `json:"spec,omitempty"`
	// Target is release-snapshot's: the only node that may pull the bundle.
	Target string `json:"target,omitempty"`
	// Source is import's: the node to pull the bundle from.
	Source string `json:"source,omitempty"`
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
		return MoveActionResult{Results: h.ReleaseForMove(ctx, a.IDs)}, nil
	case "stop":
		return MoveActionResult{Results: h.StopForDecommission(ctx, a.IDs)}, nil
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
	// noticed is the nodes this leader has already told owners about.
	noticed map[string]bool
	// peers stands in for other nodes' handlers in tests: a move action
	// for one of them runs here instead of over the internal route.
	peers map[string]MoveHandler
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

// noticeOnce reports whether this leader has not told nodeID's owners yet,
// and records that it now has.
func (c *Cluster) noticeOnce(nodeID string) bool {
	c.moves.mu.Lock()
	defer c.moves.mu.Unlock()
	if c.moves.noticed[nodeID] {
		return false
	}
	if c.moves.noticed == nil {
		c.moves.noticed = make(map[string]bool)
	}
	c.moves.noticed[nodeID] = true
	return true
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
	if !c.fsm.drainedNodesSnapshot()[nodeID] {
		return res, ErrNodeNotDrained
	}
	source, ok := c.gossip.lookupMember(nodeID)
	if !ok || !source.Alive {
		return res, ErrNodeNotAlive
	}
	limit := req.Max
	if limit <= 0 {
		limit = defaultEvacuateMoves
	}
	limit = min(limit, maxEvacuateMoves)
	deadline := time.Now().Add(time.Hour)
	if req.DeadlineUnix > 0 {
		deadline = time.Unix(req.DeadlineUnix, 0)
	}

	var movable []Placement
	var others []string
	for _, id := range c.fsm.idsOwnedBy(nodeID) {
		p, ok := c.fsm.get(id)
		if !ok || strings.TrimSpace(p.OwnerNodeID) != nodeID || p.IsDeleting() {
			continue
		}
		if placementWantsFailoverRecreate(p) || placementWantsSnapshotMove(p) {
			movable = append(movable, p)
		} else {
			others = append(others, id)
		}
	}
	sort.Slice(movable, func(i, j int) bool { return movable[i].SandboxID < movable[j].SandboxID })
	sort.Strings(others)

	// Moves run side by side: the slow part is each target's image pull.
	batch := movable[:min(limit, len(movable))]
	type outcome struct {
		id  string
		err error
	}
	results := make(chan outcome, len(batch))
	var wg sync.WaitGroup
	for _, p := range batch {
		wg.Add(1)
		go func(p Placement) {
			defer wg.Done()
			move := c.moveOne
			if placementWantsSnapshotMove(p) {
				move = c.moveSnapshotOne
			}
			results <- outcome{id: p.SandboxID, err: move(ctx, p, source)}
		}(p)
	}
	wg.Wait()
	close(results)
	for o := range results {
		if o.err != nil {
			if res.Failed == nil {
				res.Failed = make(map[string]string)
			}
			res.Failed[o.id] = o.err.Error()
			decommissionMoves.Add("failed", 1)
			continue
		}
		res.Moved = append(res.Moved, o.id)
		decommissionMoves.Add("moved", 1)
	}
	sort.Strings(res.Moved)

	if len(others) > 0 && c.noticeOnce(nodeID) {
		out, err := c.moveCall(ctx, source, MoveAction{Action: "notice", IDs: others, DeadlineUnix: deadline.Unix()})
		if err != nil {
			// Told on the next leader's pass, or not at all: the notice is
			// a courtesy, the deadline stop still comes.
			c.logger.Warn("cluster: decommission notice failed", "node_id", nodeID, "err", err)
		}
		res.Noticed = out.Count
	}
	if req.StopRemaining && len(others) > 0 {
		out, err := c.moveCall(ctx, source, MoveAction{Action: "stop", IDs: others})
		if err != nil {
			return res, err
		}
		for _, r := range out.Results {
			if r == "stopped" || r == "gone" {
				res.Stopped++
			}
		}
	}

	for _, id := range c.fsm.idsOwnedBy(nodeID) {
		p, ok := c.fsm.get(id)
		if !ok || strings.TrimSpace(p.OwnerNodeID) != nodeID {
			continue
		}
		if placementWantsFailoverRecreate(p) || placementWantsSnapshotMove(p) {
			res.RemainingMovable++
		} else {
			res.Remaining++
		}
	}
	res.Done = res.RemainingMovable == 0 && res.Remaining == 0
	c.logger.Info("cluster: decommission pass", "node_id", nodeID, "moved", len(res.Moved), "failed", len(res.Failed),
		"remaining_movable", res.RemainingMovable, "remaining", res.Remaining, "stopped", res.Stopped)
	return res, nil
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
	out, err := c.moveCall(rctx, source, MoveAction{Action: "release", IDs: []string{p.SandboxID}})
	cancel()
	if err != nil {
		return err
	}
	if r := out.Results[p.SandboxID]; r != "released" && r != "gone" {
		return errors.New("release on " + source.NodeID + ": " + r)
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

package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Snapshot moves during decommission (plans/kubernetes-v2-architecture.md
// §10.5, the "can be snapshotted" row): a Firecracker sandbox without the
// recreate policy moves with its memory, keeping its running programs.
// Without this it would be stopped at the drain deadline.
//
// The leader's pass, for one sandbox, keeps one executor (I1) as the
// recreate move does: nothing runs it on the target until the placement
// names the target.
//
//  1. release on the source, naming the target: the source stops the VM,
//     which writes its memory snapshot, and fences it (as a recreate move);
//  2. import on the target: the target pulls the sandbox's row and snapshot
//     from the source over the internal mTLS link (FetchMoveBundle), sealed
//     for this target and this incarnation, and puts them in place stopped,
//     held from its stale-ownership sweep;
//  3. one compare-and-swap on the source as owner moves the placement;
//  4. start on the target: the VM resumes from its memory.
//
// A failed import or swap drops the target's copy, and the source's fence
// lapses into a start from its own snapshot (resumeLapsedMove), so the
// sandbox loses nothing but the time the move took. A failed start leaves
// the sandbox stopped on the target, where its next start restores it.
//
// A gVisor sandbox moves the same way (C21) between workers that both
// carry CheckpointMovesLabel: the source's stop saves it with runsc, and
// the target rebuilds it after the swap, restoring that checkpoint. Its
// steps before the swap get checkpointMoveBudget; a failed one lapses the
// source into a start from its image (its memory is lost, as before C21).

const (
	// PublicInternalMovePath prefixes the source's per-sandbox bundle route.
	PublicInternalMovePath = "/v1/cluster/internal/move/"
	// MoveBundleMediaType is a sealed move bundle.
	MoveBundleMediaType = "application/vnd.aerolvm.move-bundle.v1"
	// importMoveTimeout bounds the target's pull of the bundle: a VM's
	// memory and disks, gigabytes on the internal network.
	importMoveTimeout = 15 * time.Minute
	// moveStartTimeout bounds the target's start after the swap: a restore
	// that copies the sandbox's disk into place first.
	moveStartTimeout = 5 * time.Minute
	// checkpointMoveBudget bounds a gVisor move's steps before the swap:
	// the save and the pull (plan C21: 60 s per sandbox, so a node's
	// decommission deadline fits its moves).
	checkpointMoveBudget = 60 * time.Second
	// CheckpointMovesLabel is the label a worker that moves gVisor
	// sandboxes with their memory carries (SB_GVISOR_CHECKPOINT_MOVES).
	CheckpointMovesLabel = "aerolvm.io/gvisor-checkpoint-moves"
)

// SnapshotMoveHandler is the worker's half of a snapshot move. It is
// optional: a MoveHandler without it never gets a snapshot move.
type SnapshotMoveHandler interface {
	// ReleaseForSnapshotMove is ReleaseForMove for one sandbox, naming the
	// only node that may pull its bundle.
	ReleaseForSnapshotMove(ctx context.Context, id, target string) string
	// ImportMove pulls id's bundle from source and puts it in place.
	ImportMove(ctx context.Context, id, source string) error
	// DropMove undoes ImportMove when the move does not happen.
	DropMove(ctx context.Context, id string) error
	// StartMoved starts id once the placement names this node. rc is what
	// to rebuild it from, for a runtime that rebuilds rather than restarts.
	StartMoved(ctx context.Context, id string, rc *MoveRecreate) error
}

// MoveRecreate is RecreateInputs of a moved sandbox's placement, as the
// leader read it: what the target needs to rebuild the sandbox.
type MoveRecreate struct {
	Spec               models.CreateSandboxRequest `json:"spec"`
	Secrets            PlacementSecrets            `json:"secrets"`
	Ports              map[int]ExposedPortRoute    `json:"ports,omitempty"`
	OwnerSinceUnixNano int64                       `json:"owner_since_unix_nano,omitempty"`
}

// moveRecreateFor is p's MoveRecreate, or nil without a spec.
func moveRecreateFor(p Placement) *MoveRecreate {
	spec, sealed, ports, ok := RecreateInputs(p)
	if !ok {
		return nil
	}
	return &MoveRecreate{Spec: spec, Secrets: sealed, Ports: ports, OwnerSinceUnixNano: p.OwnerSinceUnixNano}
}

// MoveBundlePath is the source's route for id's bundle.
func MoveBundlePath(id string) string {
	return PublicInternalMovePath + url.PathEscape(id) + "/bundle"
}

// MoveBundleAAD binds a move bundle to its sandbox, incarnation and target,
// so one sealed for another node, or another incarnation, does not open.
func MoveBundleAAD(id, incarnationID, target string) []byte {
	return []byte("aerolvm-move-v1|" + id + "|" + incarnationID + "|" + target)
}

// placementWantsSnapshotMove reports whether p moves off source with its
// memory: a Firecracker sandbox, or a gVisor one on a source that moves
// those (checkpointMover), without the recreate policy, which decides
// first, and with no external-storage mounts, whose re-attach on the
// target is not designed (C21).
func placementWantsSnapshotMove(p Placement, source Member) bool {
	if p.IsDeleting() || p.Spec == nil || placementWantsFailoverRecreate(p) || len(p.Spec.Mounts) > 0 {
		return false
	}
	switch strings.TrimSpace(p.Spec.Runtime) {
	case models.RuntimeFirecracker:
		return true
	case models.RuntimeGvisor:
		return checkpointMover(source)
	}
	return false
}

// heartbeatCapacity is m's capacity as its last heartbeat reported it (the
// placement view), or what m already carries when there is none.
func (c *Cluster) heartbeatCapacity(m Member) capacity.Snapshot {
	if got := c.membersWithCapacityFor([]string{m.NodeID}); len(got) == 1 && hasCapacitySnapshot(got[0].Capacity) {
		return got[0].Capacity
	}
	return m.Capacity
}

// checkpointMover reports whether m moves gVisor sandboxes with their
// memory: its capacity reports CheckpointMovesLabel. A worker with the
// switch off (or a build before C21) does not, and its gVisor sandboxes
// take the next §10.5 row.
func checkpointMover(m Member) bool {
	return m.Capacity.Labels[CheckpointMovesLabel] == "true"
}

// snapshotTargetFits reports why target cannot restore a VM snapshotted on
// source, or "" when it can: Firecracker restores a snapshot only on the
// same CPU type and Firecracker version, which the same build on the same
// architecture stands for here (a pool is one machine type).
func snapshotTargetFits(p Placement, source, target Member) string {
	switch {
	case p.Spec != nil && strings.TrimSpace(p.Spec.Runtime) == models.RuntimeGvisor && !checkpointMover(target):
		return fmt.Sprintf("target %s does not restore gVisor checkpoints", target.NodeID)
	case source.Arch != "" && target.Arch != source.Arch:
		return fmt.Sprintf("target %s is %s, the source %s", target.NodeID, target.Arch, source.Arch)
	case source.Version != "" && target.Version != source.Version:
		return fmt.Sprintf("target %s runs %s, the source %s", target.NodeID, target.Version, source.Version)
	}
	return ""
}

// moveSnapshotOne moves p off source by snapshot.
func (c *Cluster) moveSnapshotOne(ctx context.Context, p Placement, source Member) error {
	importTimeout := importMoveTimeout
	pre := ctx
	if p.Spec != nil && strings.TrimSpace(p.Spec.Runtime) == models.RuntimeGvisor {
		var cancel context.CancelFunc
		pre, cancel = context.WithTimeout(ctx, checkpointMoveBudget)
		defer cancel()
		importTimeout = checkpointMoveBudget
	}
	target, err := c.selectRecreationTargetAvoiding(p, c.lastKnownZone(source.NodeID), source.NodeID)
	if err != nil {
		return err
	}
	tm, ok := c.gossip.lookupMember(target.NodeID)
	if target.IsSelf {
		tm, ok = c.gossip.selfMember(), true
	}
	if !ok {
		return fmt.Errorf("target %s is not a member", target.NodeID)
	}
	tm.Capacity = c.heartbeatCapacity(tm)
	if why := snapshotTargetFits(p, source, tm); why != "" {
		return errors.New("snapshot move: " + why)
	}
	rctx, cancel := context.WithTimeout(pre, moveStepTimeout)
	out, err := c.moveCall(rctx, source, MoveAction{Action: "release-snapshot", IDs: []string{p.SandboxID}, Target: target.NodeID})
	cancel()
	if err != nil {
		return err
	}
	if r := out.Results[p.SandboxID]; r != "released" {
		return errors.New("release on " + source.NodeID + ": " + r)
	}
	drop := func(why error) error {
		dctx, cancel := context.WithTimeout(context.Background(), moveStepTimeout)
		defer cancel()
		if _, err := c.moveCall(dctx, tm, MoveAction{Action: "drop", IDs: []string{p.SandboxID}}); err != nil {
			c.logger.Warn("cluster: snapshot move: the target's copy was not dropped", "sandbox_id", p.SandboxID, "target", tm.NodeID, "err", err)
		}
		return why
	}
	ictx, cancel := context.WithTimeout(pre, importTimeout)
	out, err = c.moveCall(ictx, tm, MoveAction{Action: "import", IDs: []string{p.SandboxID}, Source: source.NodeID})
	cancel()
	if err == nil && out.Error != "" {
		err = errors.New(out.Error)
	}
	if err != nil {
		return drop(fmt.Errorf("import on %s: %w", tm.NodeID, err))
	}
	if err := c.applyCommand(ctx, command{
		Op:                     opReassign,
		SandboxID:              p.SandboxID,
		OwnerNodeID:            target.NodeID,
		OwnerAPIURL:            target.APIURL,
		OwnerDataPlaneHost:     target.DataPlaneHost,
		ExpectedIncarnationID:  strings.TrimSpace(p.IncarnationID),
		ExpectedOwnerNodeID:    source.NodeID,
		ExpectedOwnerNodeIDSet: true,
		ReassignCause:          reassignCauseFailover,
	}); err != nil {
		return drop(err)
	}
	// After the swap: not cut short by a gVisor move's budget.
	sctx, cancel := context.WithTimeout(ctx, moveStartTimeout)
	out, err = c.moveCall(sctx, tm, MoveAction{Action: "start-moved", IDs: []string{p.SandboxID}, Recreate: moveRecreateFor(p)})
	cancel()
	if err == nil && out.Error != "" {
		err = errors.New(out.Error)
	}
	if err != nil {
		// Moved, not started: the target holds it stopped, and a start
		// restores it.
		c.logger.Warn("cluster: snapshot move: moved, but the start on the target failed", "sandbox_id", p.SandboxID, "target", tm.NodeID, "err", err)
	}
	return nil
}

// runSnapshotMoveAction runs a snapshot move's actions on a worker whose
// MoveHandler has the snapshot half.
func runSnapshotMoveAction(ctx context.Context, h MoveHandler, a MoveAction) (MoveActionResult, error) {
	sh, ok := h.(SnapshotMoveHandler)
	if !ok {
		return MoveActionResult{}, errors.New("this node cannot move sandboxes by snapshot")
	}
	if len(a.IDs) != 1 || strings.TrimSpace(a.IDs[0]) == "" {
		return MoveActionResult{}, errors.New(a.Action + " takes one sandbox")
	}
	id := strings.TrimSpace(a.IDs[0])
	var err error
	switch a.Action {
	case "release-snapshot":
		if strings.TrimSpace(a.Target) == "" {
			return MoveActionResult{}, errors.New("release-snapshot needs the target")
		}
		return MoveActionResult{Results: map[string]string{id: sh.ReleaseForSnapshotMove(ctx, id, strings.TrimSpace(a.Target))}}, nil
	case "import":
		if strings.TrimSpace(a.Source) == "" {
			return MoveActionResult{}, errors.New("import needs the source")
		}
		err = sh.ImportMove(ctx, id, strings.TrimSpace(a.Source))
	case "drop":
		err = sh.DropMove(ctx, id)
	case "start-moved":
		err = sh.StartMoved(ctx, id, a.Recreate)
	}
	if err != nil {
		return MoveActionResult{Error: err.Error()}, nil
	}
	return MoveActionResult{}, nil
}

// moveBundlePeer is what FetchMoveBundle needs of a cluster role.
type moveBundlePeer interface {
	LookupMember(id string) (Member, bool)
	PeerDialMember(m Member) (*http.Client, string, error)
	SelfNodeID() string
}

// FetchMoveBundle streams sandboxID's sealed move bundle from source into w.
func FetchMoveBundle(ctx context.Context, c Client, source, sandboxID string, w io.Writer) error {
	p, ok := c.(moveBundlePeer)
	if !ok {
		return ErrPeerInternalURLRequired
	}
	m, ok := p.LookupMember(source)
	if !ok || !m.Alive {
		return fmt.Errorf("cluster: move source %s is not a live member", source)
	}
	client, base, err := p.PeerDialMember(m)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+MoveBundlePath(sandboxID), nil)
	if err != nil {
		return err
	}
	SetPeerNodeIDHeader(req, p.SelfNodeID())
	if pat := wasmMigratePAT(c); pat != "" {
		req.Header.Set("Authorization", "Bearer "+pat)
	}
	// A VM's memory and disks take as long as ctx allows (importMoveTimeout,
	// or a gVisor move's budget), not the internal client's per-call limit,
	// which is for control-plane calls: with it, every Firecracker move's
	// pull was cut off mid-stream (F35, p5-move-5).
	streaming := *client
	streaming.Timeout = 0
	resp, err := streaming.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return statusError{status: resp.StatusCode, message: strings.TrimSpace(string(msg))}
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

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

const (
	// PublicInternalMovePath prefixes the source's per-sandbox bundle route.
	PublicInternalMovePath = "/v1/cluster/internal/move/"
	// MoveBundleMediaType is a sealed move bundle.
	MoveBundleMediaType = "application/vnd.aerolvm.move-bundle.v1"
	// importMoveTimeout bounds the target's pull of the bundle: a VM's
	// memory and disks, gigabytes on the internal network.
	importMoveTimeout = 15 * time.Minute
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
	// StartMoved starts id once the placement names this node.
	StartMoved(ctx context.Context, id string) error
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

// placementWantsSnapshotMove reports whether p moves by snapshot: a
// Firecracker sandbox (memory and all) without the recreate policy, which
// decides first, and with no external-storage mounts, whose re-attach on
// the target is not designed (as for C21).
func placementWantsSnapshotMove(p Placement) bool {
	if p.IsDeleting() || p.Spec == nil || placementWantsFailoverRecreate(p) {
		return false
	}
	return strings.TrimSpace(p.Spec.Runtime) == models.RuntimeFirecracker && len(p.Spec.Mounts) == 0
}

// snapshotTargetFits reports why target cannot restore a VM snapshotted on
// source, or "" when it can: Firecracker restores a snapshot only on the
// same CPU type and Firecracker version, which the same build on the same
// architecture stands for here (a pool is one machine type).
func snapshotTargetFits(source, target Member) string {
	switch {
	case source.Arch != "" && target.Arch != source.Arch:
		return fmt.Sprintf("target %s is %s, the source %s", target.NodeID, target.Arch, source.Arch)
	case source.Version != "" && target.Version != source.Version:
		return fmt.Sprintf("target %s runs %s, the source %s", target.NodeID, target.Version, source.Version)
	}
	return ""
}

// moveSnapshotOne moves p off source by snapshot.
func (c *Cluster) moveSnapshotOne(ctx context.Context, p Placement, source Member) error {
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
	if why := snapshotTargetFits(source, tm); why != "" {
		return errors.New("snapshot move: " + why)
	}
	rctx, cancel := context.WithTimeout(ctx, moveStepTimeout)
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
	ictx, cancel := context.WithTimeout(ctx, importMoveTimeout)
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
	sctx, cancel := context.WithTimeout(ctx, moveStepTimeout)
	out, err = c.moveCall(sctx, tm, MoveAction{Action: "start-moved", IDs: []string{p.SandboxID}})
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
		err = sh.StartMoved(ctx, id)
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
	resp, err := client.Do(req)
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

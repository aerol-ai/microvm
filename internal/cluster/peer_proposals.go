package cluster

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// What a worker or gateway may propose through the raw apply routes
// (POST /internal/apply on the internal listener, and the v1
// /v1/cluster/internal/apply). Node certificates get only what their role
// needs (peer_role.go): a server proposes any op, and every other node only
// the ops the Agent code sends (applyCommand), each about the sender
// itself:
//
//	op                                     a worker or gateway may send it when
//	place, claim orphan                    it names the sender as the owner (a
//	                                       claim also only of the sender's
//	                                       orphan); never a gateway, which owns
//	                                       no sandbox
//	spec, ports, custom domains            the sender owns the sandbox now
//	secret recipients, delete, begin       the write is fenced on the sender as
//	delete, move abort                     the owner (the FSM checks the fence)
//	reassign                               to the sender, of a WASM sandbox
//	                                       (the WASM migration's import)
//	drain mark, snapshot home, catalogue   the node it names is the sender
//	slice, obligation report, reclaim
//	claim
//	snapshot forget, reclaim ack           the entry is the sender's, or gone
//	reserve, cancel reserve                any: a reservation never enters
//	                                       the owner index (fsm.go), and a
//	                                       cancel only drops a reservation
//	volume rows and attachments            any (tenant rows, not a node's)
//
// Everything with a route of its own (API tokens, identity, egress
// profiles, team quotas, warm pools, run states, join state, node denies,
// rollouts) and every operator attestation (storage retirement, another
// node's drain mark) is refused here: those come from a server, or through
// the route that checks its caller.
//
// The check runs on the leader before the proposal, never in the FSM's
// apply: what a peer may propose is a property of the request, and replay
// after a restart or a leader change applies every stored entry as it was.
// Ops fenced on an expected owner are checked against that fence, which the
// FSM enforces when it applies; the rest are checked against the leader's
// FSM at proposal time, so a sender acts only on what it held then.

// ErrPeerProposalRefused is a raw apply from a peer whose role may not
// propose that op (403 on both apply listeners).
var ErrPeerProposalRefused = errors.New("cluster: this node's role may not propose this change")

// agentProposableOps are the ops Agent code proposes through the server
// tier, each with the rule that binds it to its sender (peerMayPropose). A
// new Agent op must be added here, or a worker's or gateway's proposal of
// it is refused (TestAgentProposalsAreProposable pins it).
var agentProposableOps = map[opCode]bool{
	opPlace:                    true,
	opDelete:                   true,
	opReassign:                 true,
	opUpsertSpec:               true,
	opAddExposedPort:           true,
	opRemoveExposedPort:        true,
	opReserve:                  true,
	opCancelReserve:            true,
	opSetNodeDrainState:        true,
	opClaimOrphan:              true,
	opAddCustomDomain:          true,
	opRemoveCustomDomain:       true,
	opUpsertVolume:             true,
	opDeleteVolume:             true,
	opPutVolumeAttach:          true,
	opDeleteVolumeAttach:       true,
	opUpdateSecretRecipients:   true,
	opBeginDelete:              true,
	opPublishArtifactCatalog:   true,
	opRegisterSnapshotNode:     true,
	opForgetSnapshotNode:       true,
	opReportStorageObligations: true,
	opClaimVolumeReclaim:       true,
	opAckVolumeReclaim:         true,
	opMoveHandoff:              true,
}

type applyPeerCtxKey struct{}

type applyPeer struct {
	nodeID string
	leaf   *x509.Certificate
}

// ContextWithApplyPeer records which peer sent a raw apply, and its
// verified certificate, for ApplyEncoded's role check. Both apply
// listeners set it after their own peer checks passed.
func ContextWithApplyPeer(ctx context.Context, nodeID string, leaf *x509.Certificate) context.Context {
	return context.WithValue(ctx, applyPeerCtxKey{}, applyPeer{nodeID: strings.TrimSpace(nodeID), leaf: leaf})
}

func applyPeerFromContext(ctx context.Context) (applyPeer, bool) {
	p, ok := ctx.Value(applyPeerCtxKey{}).(applyPeer)
	return p, ok && p.nodeID != ""
}

// checkPeerProposal refuses a raw apply the sending peer's role may not
// propose. A context with no recorded peer is refused like an unknown
// role: both listeners record one, so a missing peer is a bug, and it must
// not pass as a server.
func (c *Cluster) checkPeerProposal(ctx context.Context, cmd command) error {
	peer, _ := applyPeerFromContext(ctx)
	role := ""
	if peer.nodeID != "" {
		role = PeerRole(c, peer.nodeID, peer.leaf)
	}
	if peerMayPropose(role, peer.nodeID, cmd, c.fsm) {
		return nil
	}
	if role == "" {
		role = "unknown"
	}
	if c.logger != nil {
		c.logger.Warn("cluster: refused a raw apply a peer's role may not propose",
			"peer", peer.nodeID, "role", role, "op", int(cmd.Op), "sandbox_id", cmd.SandboxID)
	}
	return fmt.Errorf("%w: node %q (role %s) sent op %d; a worker or gateway proposes changes only to what it owns or names itself, and an operator's change goes to a server",
		ErrPeerProposalRefused, peer.nodeID, role, cmd.Op)
}

// proposalState is what the rule reads from the leader's FSM.
type proposalState interface {
	placementForProposal(sandboxID string, withSpec bool) (Placement, bool)
	snapshotHomeForProposal(name string) (string, bool)
	volumeReclaimForProposal(r VolumeReclaim) (VolumeReclaim, bool)
}

// peerMayPropose is the rule (see the table above). A server proposes
// anything; any other role, or an unknown one, only the Agent ops, each
// bound to the sender.
func peerMayPropose(role, sender string, cmd command, st proposalState) bool {
	if role == JoinRoleServer {
		return true
	}
	sender = strings.TrimSpace(sender)
	if sender == "" || !agentProposableOps[cmd.Op] {
		return false
	}
	is := func(id string) bool { return strings.TrimSpace(id) == sender }
	fencedOnSender := cmd.ExpectedOwnerNodeIDSet && is(cmd.ExpectedOwnerNodeID)
	switch cmd.Op {
	case opPlace, opClaimOrphan, opReassign:
		// A gateway never owns a sandbox (CanOwnSandboxRole), so it never
		// makes itself an owner, nor does a peer an earlier gateway relays
		// for.
		if role == JoinRoleIngress {
			return false
		}
	}
	switch cmd.Op {
	case opPlace:
		return is(cmd.OwnerNodeID)
	case opClaimOrphan:
		if !is(cmd.OwnerNodeID) {
			return false
		}
		p, ok := st.placementForProposal(cmd.SandboxID, false)
		if !ok {
			return true // the FSM answers ErrUnknownSandbox
		}
		if p.IsOrphaned() {
			return is(p.OrphanedOwnerNodeID)
		}
		return is(p.OwnerNodeID)
	case opReassign:
		if !is(cmd.OwnerNodeID) || strings.TrimSpace(cmd.ExpectedMoveToken) != "" {
			return false
		}
		p, ok := st.placementForProposal(cmd.SandboxID, true)
		return ok && p.Spec != nil && strings.EqualFold(strings.TrimSpace(p.Spec.Runtime), models.RuntimeWasm)
	case opUpsertSpec, opAddExposedPort, opRemoveExposedPort, opAddCustomDomain, opRemoveCustomDomain:
		p, ok := st.placementForProposal(cmd.SandboxID, false)
		return ok && is(p.OwnerNodeID)
	case opUpdateSecretRecipients, opDelete, opBeginDelete:
		return fencedOnSender
	case opMoveHandoff:
		// Only the abort a source sends for itself; opening a handoff is the
		// leader's (beginMoveHandoff).
		return strings.TrimSpace(cmd.MoveToken) == "" && fencedOnSender
	case opSetNodeDrainState, opRegisterSnapshotNode, opPublishArtifactCatalog, opClaimVolumeReclaim:
		return is(cmd.NodeID)
	case opForgetSnapshotNode:
		home, ok := st.snapshotHomeForProposal(cmd.SnapshotName)
		return !ok || is(home)
	case opReportStorageObligations:
		if len(cmd.ObligationReports) == 0 {
			return false
		}
		for _, r := range cmd.ObligationReports {
			if !is(r.Reporter) {
				return false
			}
		}
		return true
	case opAckVolumeReclaim:
		if cmd.VolumeReclaim == nil {
			return false
		}
		cur, ok := st.volumeReclaimForProposal(*cmd.VolumeReclaim)
		return !ok || is(cur.NodeID)
	}
	// opReserve, opCancelReserve, and the tenant volume rows and
	// attachments: open to any node (see the table above).
	return true
}

// placementForProposal reads one placement for the rule; withSpec resolves
// a spec kept in the recovery store.
func (f *placementFSM) placementForProposal(sandboxID string, withSpec bool) (Placement, bool) {
	if f == nil {
		return Placement{}, false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	id := strings.TrimSpace(sandboxID)
	if withSpec {
		return f.fullPlacementLocked(id)
	}
	p, ok := f.placements[id]
	return p, ok
}

// snapshotHomeForProposal is the node a snapshot name points at.
func (f *placementFSM) snapshotHomeForProposal(name string) (string, bool) {
	if f == nil {
		return "", false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	node, ok := f.snapshotNodeIndex[strings.TrimSpace(name)]
	return node, ok
}

// volumeReclaimForProposal is the stored entry a reclaim names.
func (f *placementFSM) volumeReclaimForProposal(r VolumeReclaim) (VolumeReclaim, bool) {
	if f == nil {
		return VolumeReclaim{}, false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	cur, ok := f.volumeReclaims[r.key()]
	return cur, ok
}

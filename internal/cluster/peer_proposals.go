package cluster

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// What a worker or gateway may propose through the raw apply routes
// (POST /internal/apply on the internal listener, and the v1
// /v1/cluster/internal/apply). Node certificates get only what their role
// needs (peer_role.go): a server proposes any op, and every other node only
// the ops the Agent code sends (applyCommand). Those are its sandboxes'
// placement lifecycle, ports and domains, volumes, snapshots, its catalogue
// slice, storage obligations, volume reclaims, a move abort, and its own
// drain mark. Everything with a route of its own (API tokens, identity,
// egress profiles, team quotas, warm pools, run states, join state, node
// denies, rollouts) and every operator attestation (storage retirement,
// another node's drain mark) is refused here: those come from a server,
// or through the route that checks its caller.
//
// The check runs on the leader before the proposal, never in the FSM's
// apply: what a peer may propose is a property of the request, and replay
// after a restart or a leader change applies every stored entry as it was.

// ErrPeerProposalRefused is a raw apply from a peer whose role may not
// propose that op (403 on both apply listeners).
var ErrPeerProposalRefused = errors.New("cluster: this node's role may not propose this change")

// agentProposableOps are the ops Agent code proposes through the server
// tier. A new Agent op must be added here, or a worker's or gateway's
// proposal of it is refused (TestAgentProposalsAreProposable pins it).
var agentProposableOps = map[opCode]bool{
	opPlace:                    true,
	opDelete:                   true,
	opReassign:                 true,
	opUpsertSpec:               true,
	opAddExposedPort:           true,
	opRemoveExposedPort:        true,
	opReserve:                  true,
	opCancelReserve:            true,
	opSetNodeDrainState:        true, // its own node only (peerMayPropose)
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
	if peerMayPropose(role, peer.nodeID, cmd) {
		return nil
	}
	if role == "" {
		role = "unknown"
	}
	if c.logger != nil {
		c.logger.Warn("cluster: refused a raw apply a peer's role may not propose",
			"peer", peer.nodeID, "role", role, "op", int(cmd.Op))
	}
	return fmt.Errorf("%w: node %q (role %s) sent op %d; a worker or gateway proposes only its own sandboxes' changes, and an operator's change goes to a server",
		ErrPeerProposalRefused, peer.nodeID, role, cmd.Op)
}

// peerMayPropose is the rule: a server proposes anything; any other role
// (or an unknown one) proposes the Agent ops, and a drain mark only for
// itself (a local `sandboxd-node-lifecycle.sh drain` on that node).
func peerMayPropose(role, peerID string, cmd command) bool {
	if role == JoinRoleServer {
		return true
	}
	if !agentProposableOps[cmd.Op] {
		return false
	}
	if cmd.Op == opSetNodeDrainState {
		return peerID != "" && strings.TrimSpace(cmd.NodeID) == peerID
	}
	return true
}

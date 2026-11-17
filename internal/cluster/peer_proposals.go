package cluster

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

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
//	reclaim claim                          also one the sender may adopt now:
//	                                       the rule the reclaim listing
//	                                       applies (mayAdoptVolumeReclaim)
//	custom domain add                      also not a name of the cluster's
//	                                       own: its base domain or API host
//	reserve                                any: a reservation never enters
//	                                       the owner index (fsm.go)
//	cancel reserve                         the reservation is the sender's:
//	                                       it reserved it or is its target
//	volume rows and attachments            any (tenant rows, not a node's)
//
// The leader also writes what an op says about the nodes it names, rather
// than taking the sender's word (stampProposal): the API URL and data-plane
// host of the owner a worker's place, claim, reassign or reserve names come
// from that node's member record, and every reservation records the node
// that sent it.
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
// propose, and returns the sender and its role. A context with no recorded
// peer is refused like an unknown role: both listeners record one, so a
// missing peer is a bug, and it must not pass as a server.
func (c *Cluster) checkPeerProposal(ctx context.Context, cmd command) (sender, role string, err error) {
	peer, _ := applyPeerFromContext(ctx)
	if peer.nodeID != "" {
		role = PeerRole(c, peer.nodeID, peer.leaf)
	}
	if peerMayPropose(role, peer.nodeID, cmd, leaderProposalState{placementFSM: c.fsm, c: c, now: time.Now()}) {
		return peer.nodeID, role, nil
	}
	if role == "" {
		role = "unknown"
	}
	if c.logger != nil {
		c.logger.Warn("cluster: refused a raw apply a peer's role may not propose",
			"peer", peer.nodeID, "role", role, "op", int(cmd.Op), "sandbox_id", cmd.SandboxID)
	}
	return "", "", fmt.Errorf("%w: node %q (role %s) sent op %d; a worker or gateway proposes changes only to what it owns or names itself, and an operator's change goes to a server",
		ErrPeerProposalRefused, peer.nodeID, role, cmd.Op)
}

// stampProposal writes what cmd says about the nodes it names from what
// this leader knows, never from the sender: a reservation records sender
// as the node that sent it, and a worker's or gateway's place, claim,
// reassign or reserve gets the named owner's API URL and data-plane host
// from that node's member record, which is where every other node then
// sends that sandbox's calls and traffic. A server's proposal keeps its
// addresses: servers are trusted with every op. The payload is re-encoded
// only when something changed.
func (c *Cluster) stampProposal(payload []byte, cmd command, sender string, server bool) ([]byte, command, error) {
	changed := false
	if cmd.Op == opReserve || cmd.Op == opReserveBatch {
		if cmd.ReservedBy != sender {
			cmd.ReservedBy, changed = sender, true
		}
	}
	if !server {
		switch cmd.Op {
		case opPlace, opClaimOrphan, opReassign, opReserve:
			owner := strings.TrimSpace(cmd.OwnerNodeID)
			if owner == "" {
				break
			}
			m, ok := c.memberRecord(owner)
			if !ok {
				return nil, cmd, fmt.Errorf("%w: node %q names owner %q, which is not a member this leader knows", ErrPeerProposalRefused, sender, owner)
			}
			apiURL, dataPlaneHost := m.APIURL, m.DataPlaneHost
			// A member whose gossip meta was cut to a smaller tier
			// (gossip.go) carries no data-plane host, or no API URL. For
			// the sender's own sandboxes its word is what its record would
			// have said (a node gossips its own addresses); for another
			// node's, nothing is taken from the sender.
			if owner == sender {
				if strings.TrimSpace(apiURL) == "" {
					apiURL = cmd.OwnerAPIURL
				}
				if strings.TrimSpace(dataPlaneHost) == "" {
					dataPlaneHost = cmd.OwnerDataPlaneHost
				}
			} else if strings.TrimSpace(apiURL) == "" {
				return nil, cmd, fmt.Errorf("%w: node %q names owner %q, whose member record has no API URL", ErrPeerProposalRefused, sender, owner)
			}
			if cmd.OwnerAPIURL != apiURL || cmd.OwnerDataPlaneHost != dataPlaneHost {
				cmd.OwnerAPIURL, cmd.OwnerDataPlaneHost, changed = apiURL, dataPlaneHost, true
			}
		}
	}
	if !changed {
		return payload, cmd, nil
	}
	out, err := encodeCommand(cmd)
	if err != nil {
		return nil, cmd, fmt.Errorf("cluster: encode command: %w", err)
	}
	return out, cmd, nil
}

// CustomDomainProver is the optional half of SandboxRecreator that checks a
// custom hostname's DNS proof for a sandbox owned by ownerRef: the TXT
// record bound to that owner, or the operator's record. The service
// implements it.
type CustomDomainProver interface {
	ProveCustomDomain(ctx context.Context, hostname, ownerRef string) error
}

// customDomainProofTimeout bounds the leader's DNS lookup for one add.
const customDomainProofTimeout = 5 * time.Second

// proveCustomDomain checks, on the leader, the DNS proof of a custom
// hostname a worker or gateway adds to a sandbox it owns. The owner checks
// the proof before it proposes; the leader checks it again because the
// owner is the one asking. A name the sandbox already holds (a replay, a
// rebuild) is not checked again. With no prover attached (a leader whose
// service is not wired, as in tests), nothing more is checked.
func (c *Cluster) proveCustomDomain(ctx context.Context, cmd command) error {
	p, ok := c.fsm.placementForProposal(cmd.SandboxID, false)
	if !ok {
		return nil // the FSM answers ErrUnknownSandbox
	}
	host := strings.TrimSpace(cmd.Hostname)
	for _, held := range p.CustomHostnames {
		if held == host {
			return nil
		}
	}
	prover, ok := c.currentRecreator().(CustomDomainProver)
	if !ok {
		return nil
	}
	pctx, cancel := context.WithTimeout(ctx, customDomainProofTimeout)
	defer cancel()
	if err := prover.ProveCustomDomain(pctx, host, strings.TrimSpace(p.OwnerRef)); err != nil {
		return fmt.Errorf("%w: custom hostname %q has no DNS proof for this sandbox's owner: %w", ErrPeerProposalRefused, host, err)
	}
	return nil
}

// memberRecord is nodeID's member record as this leader's gossip view has
// it: this node's own, or the gossiped one. ok is false for a node with no
// record.
func (c *Cluster) memberRecord(nodeID string) (Member, bool) {
	if c.gossip == nil {
		return Member{}, false
	}
	if nodeID == c.nodeID {
		return c.gossip.selfMember(), true
	}
	return c.gossip.lookupMember(nodeID)
}

// proposalState is what the rule reads from the leader: its FSM, its
// membership view and its configuration (leaderProposalState).
type proposalState interface {
	placementForProposal(sandboxID string, withSpec bool) (Placement, bool)
	snapshotHomeForProposal(name string) (string, bool)
	volumeReclaimForProposal(r VolumeReclaim) (VolumeReclaim, bool)
	// reclaimAdoptable reports whether sender may take cur over from the
	// node that holds it now, by the rule the listing applies
	// (volumeReclaimsFor).
	reclaimAdoptable(cur VolumeReclaim, sender string) bool
	// clusterHostname reports whether host is a name of the cluster's own
	// (the base domain, a name under it, or the API host), or not a valid
	// custom hostname at all.
	clusterHostname(host string) bool
}

// leaderProposalState is the leader's proposalState: its FSM, plus its
// membership view for the reclaim rule and its configuration for the
// cluster's own names.
type leaderProposalState struct {
	*placementFSM
	c   *Cluster
	now time.Time
}

func (s leaderProposalState) reclaimAdoptable(cur VolumeReclaim, sender string) bool {
	var g *gossipNode
	if s.c != nil {
		g = s.c.gossip
	}
	if g == nil {
		return false
	}
	return volumeReclaimAdoptableBy(cur, sender, gossipReclaimNodeState(g), gossipReclaimAdopters(g), s.now)
}

func (s leaderProposalState) clusterHostname(host string) bool {
	if s.c == nil {
		return true
	}
	return models.ReservedCustomDomain(host, s.c.cfg.Domain, s.c.cfg.PublicHost, s.c.cfg.IngressAdvertiseHost)
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
		if !ok || !is(p.OwnerNodeID) {
			return false
		}
		// A name of the cluster's own would route ahead of the API host and
		// the per-sandbox routes on every gateway (the tls-mux inserts
		// custom names first): only a server binds one.
		return cmd.Op != opAddCustomDomain || !st.clusterHostname(cmd.Hostname)
	case opUpdateSecretRecipients, opDelete, opBeginDelete:
		return fencedOnSender
	case opMoveHandoff:
		// Only the abort a source sends for itself; opening a handoff is the
		// leader's (beginMoveHandoff).
		return strings.TrimSpace(cmd.MoveToken) == "" && fencedOnSender
	case opSetNodeDrainState, opRegisterSnapshotNode, opPublishArtifactCatalog:
		return is(cmd.NodeID)
	case opClaimVolumeReclaim:
		if !is(cmd.NodeID) || cmd.VolumeReclaim == nil {
			return false
		}
		cur, ok := st.volumeReclaimForProposal(*cmd.VolumeReclaim)
		if !ok || is(cur.NodeID) {
			return true // the FSM answers ErrVolumeReclaimMoved, or nothing moves
		}
		return st.reclaimAdoptable(cur, sender)
	case opCancelReserve:
		p, ok := st.placementForProposal(cmd.SandboxID, false)
		if !ok || !p.IsReserved() {
			return true // the FSM cancels only a reservation
		}
		// A reservation from before the leader recorded its sender names
		// no one: only its target or a server cancels it, and it expires.
		return is(p.OwnerNodeID) || is(p.ReservedBy)
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
	// opReserve and the tenant volume rows and attachments: open to any
	// node (see the table above).
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

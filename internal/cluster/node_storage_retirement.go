package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/raft"
)

// NodeStorageRetirement is an operator's attestation that a node's storage was
// destroyed, replicated through the placement FSM.
//
// It has to be cluster state, not a row on the node that served the API call:
// the deletion obligations an attestation discharges live in the delete
// outbox of whichever node owns the secret, and an operator's request reaches
// an arbitrary ingress or server. A node-local table meant the owners never
// learned, and list/revoke through a different entry node saw a different set.
//
// The payload is tiny administrative metadata — one row per decommissioned
// node — so replicating it costs nothing like the placement state does.
type NodeStorageRetirement struct {
	NodeID string `json:"node_id"`
	Actor  string `json:"actor,omitempty"`
	Reason string `json:"reason,omitempty"`
	// AttestedUnixNano is the fence discharge compares copy provenance
	// against, in NANOSECONDS. Second granularity would round the attestation
	// backwards, so a copy distributed a few hundred milliseconds before it
	// would read as newer than the attestation and stay pinned forever.
	AttestedUnixNano int64 `json:"attested_unix_nano"`
}

// AttestedAt is the fence discharge decisions compare obligation provenance
// against.
func (r NodeStorageRetirement) AttestedAt() time.Time {
	if r.AttestedUnixNano <= 0 {
		return time.Time{}
	}
	return time.Unix(0, r.AttestedUnixNano).UTC()
}

// NodeStorageRetirementsResponse is the agent-facing read.
type NodeStorageRetirementsResponse struct {
	Retirements []NodeStorageRetirement `json:"retirements"`
	// Authoritative distinguishes "no attestations" from "could not ask".
	// A discharge is irreversible evidence-wise, so a non-authoritative
	// answer must never be read as an empty set.
	Authoritative bool `json:"authoritative,omitempty"`
}

// RetireNodeStorage records the attestation in the replicated control plane.
func (c *Cluster) RetireNodeStorage(ctx context.Context, nodeID, actor, reason string, attestedAt time.Time) error {
	nodeID = strings.TrimSpace(nodeID)
	if c == nil {
		return fmt.Errorf("cluster: RetireNodeStorage requires a cluster")
	}
	if nodeID == "" {
		return fmt.Errorf("cluster: RetireNodeStorage requires non-empty nodeID")
	}
	if attestedAt.IsZero() {
		attestedAt = time.Now()
	}
	return c.applyCommand(ctx, command{
		Op:     opRetireNodeStorage,
		NodeID: nodeID,
		StorageRetirement: &NodeStorageRetirement{
			NodeID:           nodeID,
			Actor:            strings.TrimSpace(actor),
			Reason:           strings.TrimSpace(reason),
			AttestedUnixNano: attestedAt.UTC().UnixNano(),
		},
	})
}

// RevokeNodeStorageRetirement withdraws the attestation cluster-wide.
func (c *Cluster) RevokeNodeStorageRetirement(ctx context.Context, nodeID string) error {
	nodeID = strings.TrimSpace(nodeID)
	if c == nil {
		return fmt.Errorf("cluster: RevokeNodeStorageRetirement requires a cluster")
	}
	if nodeID == "" {
		return fmt.Errorf("cluster: RevokeNodeStorageRetirement requires non-empty nodeID")
	}
	return c.applyCommand(ctx, command{Op: opRevokeNodeStorage, NodeID: nodeID})
}

// AuthoritativeNodeStorageRetirements answers from the leader, forwarding
// when this node is a follower.
//
// Discharging a deletion obligation without an ACK is irreversible, so it may
// not be authorized by a lagging replica or a cached set: an operator who
// revokes an attestation on one node must not have another node still
// discharging against it. A follower's own FSM says Authoritative=true about
// its own state and still cannot order itself against the revoke.
//
// Server and mixed nodes need this as much as workers do — they hold delete
// outboxes of their own, and without it every one of them fails closed
// forever on an attestation the operator did make.
func (c *Cluster) AuthoritativeNodeStorageRetirements(ctx context.Context) ([]NodeStorageRetirement, error) {
	if c == nil || c.fsm == nil || c.raft == nil || c.raft.raft == nil {
		return nil, fmt.Errorf("cluster: authoritative node storage retirement read unavailable")
	}
	if c.raft.raft.State() == raft.Leader {
		// Leadership is not enough. Election and log replication do not imply
		// this node's FSM has APPLIED everything that was committed before it
		// won: a follower can acknowledge replication of an operator's revoke,
		// become leader, and still be serving the old attestation. Authorizing
		// an irreversible discharge from that state is exactly the case this
		// read exists to prevent, so it takes a quorum-backed barrier first.
		if err := c.awaitAuthoritativeFSM(ctx); err != nil {
			return nil, err
		}
		return c.fsm.nodeStorageRetirementsSnapshot(), nil
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	leader := c.Leader()
	if leader == "" {
		return nil, ErrNotLeader
	}
	if c.currentInternalClient() == nil || c.gossip == nil {
		return nil, ErrPeerInternalURLRequired
	}
	peerInternal := c.gossip.peerInternalURL(leader)
	if peerInternal == "" {
		return nil, ErrPeerInternalURLRequired
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
		strings.TrimRight(peerInternal, "/")+PublicInternalNodeStorageRetirementsPath+"?authoritative=true", nil)
	if err != nil {
		return nil, fmt.Errorf("cluster: build authoritative retirement read: %w", err)
	}
	SetPeerNodeIDHeader(req, c.nodeID)
	if c.patToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.patToken)
	}
	resp, err := c.ClientForPeer(leader).Do(req)
	if err != nil {
		return nil, fmt.Errorf("cluster: authoritative retirement read: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if resp.StatusCode == http.StatusServiceUnavailable {
			return nil, ErrNotLeader
		}
		return nil, fmt.Errorf("cluster: authoritative retirement read: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out NodeStorageRetirementsResponse
	if err := decodeControlPlaneJSON(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("cluster: decode authoritative retirement read: %w", err)
	}
	if !out.Authoritative {
		return nil, fmt.Errorf("cluster: authoritative retirement read was not authoritative")
	}
	return out.Retirements, nil
}

// awaitAuthoritativeFSM makes a local FSM read linearizable: VerifyLeader is
// the quorum round that proves this node is STILL the leader (a deposed one's
// FSM is not the authority), and Barrier waits for every entry committed
// before now to be applied, because raft applies asynchronously.
//
// Anything that authorizes an irreversible act reads through here; a second
// leadership check alone would not close the apply lag.
func (c *Cluster) awaitAuthoritativeFSM(ctx context.Context) error {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return fmt.Errorf("cluster: authoritative read unavailable")
	}
	timeout := c.commitTimeout
	if timeout <= 0 {
		timeout = controlPlaneRequestTimeout
	}
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	if err := c.raft.raft.VerifyLeader().Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost) {
			return ErrNotLeader
		}
		return fmt.Errorf("cluster: verify leader for authoritative read: %w", err)
	}
	if err := c.raft.raft.Barrier(timeout).Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost) {
			return ErrNotLeader
		}
		return fmt.Errorf("cluster: fsm barrier for authoritative read: %w", err)
	}
	return nil
}

// NodeStorageRetirementsForPeerAuthoritative is the peer-facing form of the
// same authoritative read: the barrier belongs to the read, not to the caller,
// so a worker asking the leader gets the same guarantee a server does.
func (c *Cluster) NodeStorageRetirementsForPeerAuthoritative(ctx context.Context) (NodeStorageRetirementsResponse, error) {
	recs, err := c.AuthoritativeNodeStorageRetirements(ctx)
	if err != nil {
		return NodeStorageRetirementsResponse{}, err
	}
	return NodeStorageRetirementsResponse{Retirements: recs, Authoritative: true}, nil
}

// NodeStorageRetirements reads the replicated attestation set from the local
// FSM. Server-role nodes hold the FSM, so this is a local read.
func (c *Cluster) NodeStorageRetirements(context.Context) ([]NodeStorageRetirement, error) {
	if c == nil || c.fsm == nil {
		return nil, fmt.Errorf("cluster: node holds no placement state")
	}
	return c.fsm.nodeStorageRetirementsSnapshot(), nil
}

// NodeStorageRetirementsForPeer answers the agent-facing read.
func (c *Cluster) NodeStorageRetirementsForPeer() NodeStorageRetirementsResponse {
	if c == nil || c.fsm == nil {
		return NodeStorageRetirementsResponse{}
	}
	return NodeStorageRetirementsResponse{
		Retirements:   c.fsm.nodeStorageRetirementsSnapshot(),
		Authoritative: true,
	}
}

// RetireNodeStorage forwards the attestation to the control plane. Agents hold
// no FSM, so the command rides the same leader-forwarding path as every other
// write an agent issues.
func (a *Agent) RetireNodeStorage(ctx context.Context, nodeID, actor, reason string, attestedAt time.Time) error {
	nodeID = strings.TrimSpace(nodeID)
	if a == nil {
		return fmt.Errorf("cluster: RetireNodeStorage requires an agent")
	}
	if nodeID == "" {
		return fmt.Errorf("cluster: RetireNodeStorage requires non-empty nodeID")
	}
	if attestedAt.IsZero() {
		attestedAt = time.Now()
	}
	return a.applyCommand(ctx, command{
		Op:     opRetireNodeStorage,
		NodeID: nodeID,
		StorageRetirement: &NodeStorageRetirement{
			NodeID:           nodeID,
			Actor:            strings.TrimSpace(actor),
			Reason:           strings.TrimSpace(reason),
			AttestedUnixNano: attestedAt.UTC().UnixNano(),
		},
	})
}

// RevokeNodeStorageRetirement withdraws the attestation cluster-wide.
func (a *Agent) RevokeNodeStorageRetirement(ctx context.Context, nodeID string) error {
	nodeID = strings.TrimSpace(nodeID)
	if a == nil {
		return fmt.Errorf("cluster: RevokeNodeStorageRetirement requires an agent")
	}
	if nodeID == "" {
		return fmt.Errorf("cluster: RevokeNodeStorageRetirement requires non-empty nodeID")
	}
	return a.applyCommand(ctx, command{Op: opRevokeNodeStorage, NodeID: nodeID})
}

// NodeStorageRetirements reads the replicated set from the server tier. An
// unavailable control plane is an ERROR, never an empty set: discharging an
// obligation is irreversible, and so is failing to discharge one that the
// operator attested.
//
// This is the DISCOVERY read, answerable by any server. A caller about to act
// irreversibly uses AuthoritativeNodeStorageRetirements.
func (a *Agent) NodeStorageRetirements(ctx context.Context) ([]NodeStorageRetirement, error) {
	return a.nodeStorageRetirements(ctx, false)
}

// AuthoritativeNodeStorageRetirements asks the control plane for the LEADER's
// answer. A worker discharging an obligation without an ACK is doing
// something irreversible, so it must not be authorized by a server whose FSM
// has not yet applied the operator's revoke.
func (a *Agent) AuthoritativeNodeStorageRetirements(ctx context.Context) ([]NodeStorageRetirement, error) {
	return a.nodeStorageRetirements(ctx, true)
}

func (a *Agent) nodeStorageRetirements(ctx context.Context, authoritative bool) ([]NodeStorageRetirement, error) {
	if a == nil {
		return nil, fmt.Errorf("cluster: agent is not configured")
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	path := PublicInternalNodeStorageRetirementsPath
	if authoritative {
		path += "?authoritative=true"
	}
	var resp NodeStorageRetirementsResponse
	// Both paths carry the query: the internal one is what is actually
	// dialled, and dropping "authoritative=true" there would silently turn a
	// leader read into a follower read.
	if err := a.doControlPlaneJSON(reqCtx, http.MethodGet, path, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("cluster: read node storage retirements: %w", err)
	}
	if !resp.Authoritative {
		return nil, fmt.Errorf("cluster: node storage retirement read was not authoritative")
	}
	return resp.Retirements, nil
}

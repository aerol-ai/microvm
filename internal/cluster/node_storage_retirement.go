package cluster

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
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
	NodeID       string `json:"node_id"`
	Actor        string `json:"actor,omitempty"`
	Reason       string `json:"reason,omitempty"`
	AttestedUnix int64  `json:"attested_unix"`
}

// AttestedAt is the fence discharge decisions compare obligation provenance
// against.
func (r NodeStorageRetirement) AttestedAt() time.Time {
	if r.AttestedUnix <= 0 {
		return time.Time{}
	}
	return time.Unix(r.AttestedUnix, 0).UTC()
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
			NodeID:       nodeID,
			Actor:        strings.TrimSpace(actor),
			Reason:       strings.TrimSpace(reason),
			AttestedUnix: attestedAt.UTC().Unix(),
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
			NodeID:       nodeID,
			Actor:        strings.TrimSpace(actor),
			Reason:       strings.TrimSpace(reason),
			AttestedUnix: attestedAt.UTC().Unix(),
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
func (a *Agent) NodeStorageRetirements(ctx context.Context) ([]NodeStorageRetirement, error) {
	if a == nil {
		return nil, fmt.Errorf("cluster: agent is not configured")
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var resp NodeStorageRetirementsResponse
	if err := a.doControlPlaneJSON(reqCtx, http.MethodGet, PublicInternalNodeStorageRetirementsPath, PublicInternalNodeStorageRetirementsPath, nil, &resp); err != nil {
		return nil, fmt.Errorf("cluster: read node storage retirements: %w", err)
	}
	if !resp.Authoritative {
		return nil, fmt.Errorf("cluster: node storage retirement read was not authoritative")
	}
	return resp.Retirements, nil
}

package service

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
)

// Terminal storage retirement (D5).
//
// A deletion obligation to a peer is discharged by exactly two things: an
// authenticated generation-scoped DELETE ACK, or an operator's explicit
// attestation, recorded here, that the node's storage was destroyed.
// Membership disappearance and TTLs are deliberately NOT accepted — a removed
// node may still hold a disk full of ciphertext, and bounded per-tick retries
// are not a bound on retained rows. Without this protocol, permanent loss of a
// node left outbox and tomb metadata pending forever.
//
// Three rules keep the attestation honest:
//
//  1. It names an exact node identity. Nothing is inferred.
//  2. It is FENCED BY TIME. Node IDs are operator-chosen and reusable, so only
//     obligations that already existed when the operator attested are
//     discharged; anything journalled afterwards belongs to a different
//     physical node and must still be ACK'd.
//  3. A node that is alive again revokes it automatically. A live node can
//     ACK, so its obligations are real again.
//
// Every discharge is written to the audit trail with its own reason, so the
// evidence never claims the peer confirmed deletion when an operator attested
// instead.

const secretAuditReasonStorageRetired = "storage_retired"

var (
	// nodeStorageRetirementsTotal counts attestations recorded.
	nodeStorageRetirementsTotal = expvar.NewInt("aerolvm_node_storage_retirements_total")
	// nodeStorageRetirementsRevoked counts attestations withdrawn, whether by
	// an operator or automatically because the node came back alive.
	nodeStorageRetirementsRevoked = expvar.NewInt("aerolvm_node_storage_retirements_revoked_total")
	// secretObligationsDischargedTotal counts recipient obligations discharged
	// by attestation rather than by an ACK. A non-zero value means some
	// ciphertext deletion was never confirmed by the holder.
	secretObligationsDischargedTotal = expvar.NewInt("aerolvm_secret_obligations_storage_retired_total")
)

// ErrNodeStorageRetirementAlive refuses an attestation for a node gossip still
// reports as alive. A live node can ACK; attesting its disk destroyed would
// discard a real obligation.
var ErrNodeStorageRetirementAlive = errors.New("cluster: node is alive; storage retirement requires a decommissioned node")

// nodeStorageRetirementCache memoizes the attestation set for one maintenance
// tick. The set is bounded by the number of nodes an operator has ever
// decommissioned, and the delete-outbox pass consults it per row.
type nodeStorageRetirementCache struct {
	byNode    map[string]time.Time
	expiresAt time.Time
}

const nodeStorageRetirementCacheTTL = 30 * time.Second

// identityMembers reads the local gossip view for identity/liveness questions
// and only falls back to the control-plane membership RPC when gossip has
// nothing yet — the same rule aliveMemberSet already follows.
func identityMembers(c cluster.Client) []cluster.Member {
	if c == nil {
		return nil
	}
	if members := c.LocalMembers(); len(members) > 0 {
		return members
	}
	return c.Members()
}

// RetireNodeStorage records an operator attestation that nodeID's storage was
// destroyed. Refused while gossip reports the node alive.
func (s *Service) RetireNodeStorage(ctx context.Context, nodeID, actor, reason string) error {
	if s == nil || s.store == nil {
		return errors.New("store is not configured")
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return errors.New("retire node storage: node id required")
	}
	if c := s.Cluster(); c != nil {
		if nodeID == strings.TrimSpace(c.SelfNodeID()) {
			return fmt.Errorf("%w: cannot attest this node's own storage", ErrNodeStorageRetirementAlive)
		}
		for _, m := range identityMembers(c) {
			if strings.TrimSpace(m.NodeID) == nodeID && m.Alive {
				return ErrNodeStorageRetirementAlive
			}
		}
	}
	if err := s.store.PutNodeStorageRetirement(ctx, nodeID, actor, reason, time.Now().UTC()); err != nil {
		return err
	}
	s.invalidateNodeStorageRetirements()
	nodeStorageRetirementsTotal.Add(1)
	if s.logger != nil {
		s.logger.Warn("cluster: node storage attested destroyed; pending deletion obligations to it will be discharged without an ACK",
			"node_id", nodeID, "actor", actor, "reason", reason)
	}
	return nil
}

// RevokeNodeStorageRetirement withdraws an attestation.
func (s *Service) RevokeNodeStorageRetirement(ctx context.Context, nodeID string) (bool, error) {
	if s == nil || s.store == nil {
		return false, errors.New("store is not configured")
	}
	removed, err := s.store.DeleteNodeStorageRetirement(ctx, strings.TrimSpace(nodeID))
	if err != nil {
		return false, err
	}
	if removed {
		s.invalidateNodeStorageRetirements()
		nodeStorageRetirementsRevoked.Add(1)
	}
	return removed, nil
}

// ListNodeStorageRetirements exposes the attestation set for operators.
func (s *Service) ListNodeStorageRetirements(ctx context.Context) ([]store.NodeStorageRetirement, error) {
	if s == nil || s.store == nil {
		return nil, errors.New("store is not configured")
	}
	return s.store.ListNodeStorageRetirements(ctx)
}

func (s *Service) invalidateNodeStorageRetirements() {
	if s == nil {
		return
	}
	s.nodeRetirementMu.Lock()
	s.nodeRetirements = nil
	s.nodeRetirementMu.Unlock()
}

// nodeStorageRetirements returns nodeID -> attestation time, cached for a
// maintenance tick.
func (s *Service) nodeStorageRetirements(ctx context.Context) map[string]time.Time {
	if s == nil || s.store == nil {
		return nil
	}
	now := time.Now()
	s.nodeRetirementMu.Lock()
	if s.nodeRetirements != nil && now.Before(s.nodeRetirements.expiresAt) {
		out := s.nodeRetirements.byNode
		s.nodeRetirementMu.Unlock()
		return out
	}
	s.nodeRetirementMu.Unlock()

	recs, err := s.store.ListNodeStorageRetirements(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: node storage retirement list failed", "err", err)
		}
		return nil
	}
	byNode := make(map[string]time.Time, len(recs))
	for _, rec := range recs {
		byNode[rec.NodeID] = rec.AttestedAt
	}
	s.nodeRetirementMu.Lock()
	s.nodeRetirements = &nodeStorageRetirementCache{byNode: byNode, expiresAt: now.Add(nodeStorageRetirementCacheTTL)}
	s.nodeRetirementMu.Unlock()
	return byNode
}

// reapLiveNodeStorageRetirements withdraws attestations for nodes that are
// alive again. A live node can ACK, so its obligations stopped being
// undischargeable — and a reused node id must never inherit a previous
// machine's attestation.
func (s *Service) reapLiveNodeStorageRetirements(ctx context.Context) {
	if s == nil || s.store == nil {
		return
	}
	retired := s.nodeStorageRetirements(ctx)
	if len(retired) == 0 {
		return
	}
	c := s.Cluster()
	if c == nil {
		return
	}
	for _, m := range identityMembers(c) {
		id := strings.TrimSpace(m.NodeID)
		if id == "" || !m.Alive {
			continue
		}
		if _, ok := retired[id]; !ok {
			continue
		}
		removed, err := s.RevokeNodeStorageRetirement(ctx, id)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("cluster: revoke storage retirement for a live node failed", "node_id", id, "err", err)
			}
			continue
		}
		if removed && s.logger != nil {
			s.logger.Warn("cluster: node with an attested-destroyed storage is alive again; attestation revoked and its obligations are pending once more",
				"node_id", id)
		}
	}
}

// dischargeRetiredStorageRecipients splits an obligation's pending recipients
// into those still owed an ACK and those covered by an attestation.
//
// createdAt is the obligation's journalling time and is the fence: an
// attestation only covers what already existed when it was made.
func dischargeRetiredStorageRecipients(recipients []string, retired map[string]time.Time, createdAt time.Time) (pending, discharged []string) {
	if len(recipients) == 0 || len(retired) == 0 {
		return recipients, nil
	}
	pending = make([]string, 0, len(recipients))
	for _, id := range recipients {
		trimmed := strings.TrimSpace(id)
		attestedAt, ok := retired[trimmed]
		if ok && !createdAt.IsZero() && createdAt.After(attestedAt) {
			// Journalled after the attestation: a different physical node
			// behind a reused id. Still owed a real ACK.
			ok = false
		}
		if ok {
			discharged = append(discharged, trimmed)
			continue
		}
		pending = append(pending, id)
	}
	return pending, discharged
}

// recordStorageRetirementDischarge writes the evidence for obligations that
// were closed by attestation rather than by an ACK. The distinct reason is the
// point: a reader must be able to tell "the holder confirmed deletion" from
// "an operator attested the disk is gone".
func (s *Service) recordStorageRetirementDischarge(sandboxID, incarnationID string, generation int64, discharged []string) {
	if s == nil || len(discharged) == 0 {
		return
	}
	secretObligationsDischargedTotal.Add(int64(len(discharged)))
	sink := s.secretAuditSink()
	_, ownerRef := s.auditIdentityFor(sandboxID)
	now := time.Now().UTC()
	for _, nodeID := range discharged {
		if s.logger != nil {
			s.logger.Warn("cluster: secret deletion obligation discharged by storage-retirement attestation, not by an ACK",
				"sandbox_id", sandboxID, "node_id", nodeID, "generation", generation)
		}
		if sink == nil {
			continue
		}
		event := SecretAuditEvent{
			Time:          now,
			Actor:         s.auditActor(),
			NodeID:        nodeID,
			SandboxID:     sandboxID,
			IncarnationID: incarnationID,
			OwnerRef:      ownerRef,
			Ref:           secretDeleteObligationRef(sandboxID, incarnationID),
			Result:        secretAuditResultSuccess,
			Reason:        secretAuditReasonStorageRetired,
			Kind:          secretAuditKindSecretOpen,
		}
		if durable, ok := sink.(DurableSecretAuditSink); ok {
			if err := durable.EmitDurable(event); err != nil && s.logger != nil {
				s.logger.Warn("cluster: storage-retirement discharge evidence not persisted",
					"sandbox_id", sandboxID, "node_id", nodeID, "err", err)
			}
			continue
		}
		sink.Emit(event)
	}
}

func secretDeleteObligationRef(sandboxID, incarnationID string) string {
	return "secret-delete:" + sandboxID + ":" + incarnationID
}

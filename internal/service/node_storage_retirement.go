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
	attestedAt := time.Now().UTC()
	// In cluster mode the attestation belongs to the replicated control
	// plane. The deletion obligations it discharges live in the delete outbox
	// of whichever node owns the secret, and an operator's request lands on
	// an arbitrary entry node — a local row would be invisible to every owner
	// and would make list/revoke depend on which node was called.
	if writer, ok := s.nodeStorageRetirementWriter(); ok {
		if err := writer.RetireNodeStorage(ctx, nodeID, actor, reason, attestedAt); err != nil {
			return err
		}
	} else if err := s.store.PutNodeStorageRetirement(ctx, nodeID, actor, reason, attestedAt); err != nil {
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
	nodeID = strings.TrimSpace(nodeID)
	if writer, ok := s.nodeStorageRetirementWriter(); ok {
		existing, err := s.clusterNodeStorageRetirements(ctx)
		if err != nil {
			return false, err
		}
		if _, present := existing[nodeID]; !present {
			return false, nil
		}
		if err := writer.RevokeNodeStorageRetirement(ctx, nodeID); err != nil {
			return false, err
		}
		s.invalidateNodeStorageRetirements()
		nodeStorageRetirementsRevoked.Add(1)
		return true, nil
	}
	removed, err := s.store.DeleteNodeStorageRetirement(ctx, nodeID)
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
	if reader, ok := s.nodeStorageRetirementReader(); ok {
		recs, err := reader.NodeStorageRetirements(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]store.NodeStorageRetirement, 0, len(recs))
		for _, rec := range recs {
			out = append(out, store.NodeStorageRetirement{
				NodeID:     rec.NodeID,
				Actor:      rec.Actor,
				Reason:     rec.Reason,
				AttestedAt: rec.AttestedAt(),
			})
		}
		return out, nil
	}
	return s.store.ListNodeStorageRetirements(ctx)
}

// nodeStorageRetirementWriter / nodeStorageRetirementReader expose the
// replicated attestation registry when this node runs in cluster mode. Both
// *Cluster (local FSM) and *Agent (control-plane RPC) implement them; Noop
// does not, which is what keeps standalone mode on the local table.
func (s *Service) nodeStorageRetirementWriter() (interface {
	RetireNodeStorage(context.Context, string, string, string, time.Time) error
	RevokeNodeStorageRetirement(context.Context, string) error
}, bool) {
	if s == nil || !s.cfg.EnableCluster {
		return nil, false
	}
	c := s.Cluster()
	if c == nil {
		return nil, false
	}
	w, ok := c.(interface {
		RetireNodeStorage(context.Context, string, string, string, time.Time) error
		RevokeNodeStorageRetirement(context.Context, string) error
	})
	return w, ok
}

// authoritativeNodeStorageRetirements answers from the Raft leader, never
// from this node's 30-second discovery cache or a follower's FSM.
//
// The cache is fine for deciding whether a discharge MIGHT apply; it must not
// authorize one. An operator who revokes an attestation on one node would
// otherwise have every other owner still discharging obligations against it
// for up to a full cache TTL — and a discharge cannot be taken back. In
// standalone mode the local table is the authority, so this returns it.
func (s *Service) authoritativeNodeStorageRetirements(ctx context.Context) (map[string]time.Time, error) {
	if s == nil || s.store == nil {
		return nil, errors.New("store is not configured")
	}
	if !s.cfg.EnableCluster {
		// Standalone: the local table IS the authority.
		recs, err := s.store.ListNodeStorageRetirements(ctx)
		if err != nil {
			return nil, err
		}
		byNode := make(map[string]time.Time, len(recs))
		for _, rec := range recs {
			byNode[rec.NodeID] = rec.AttestedAt
		}
		return byNode, nil
	}
	reader, ok := s.authoritativeRetirementReader()
	if !ok {
		// Clustered, but this node cannot ask the leader. The local table is
		// not the authority here, so there is nothing to authorize an
		// irreversible discharge with.
		return nil, errors.New("cluster: authoritative node storage retirement read is unavailable")
	}
	recs, err := reader.AuthoritativeNodeStorageRetirements(ctx)
	if err != nil {
		return nil, err
	}
	byNode := make(map[string]time.Time, len(recs))
	for _, rec := range recs {
		byNode[rec.NodeID] = rec.AttestedAt()
	}
	return byNode, nil
}

// authoritativeRetirementReader is the capability a node needs to authorize a
// discharge. Both production cluster clients implement it; the compile-time
// assertions live next to the tests.
type authoritativeRetirementReader interface {
	AuthoritativeNodeStorageRetirements(context.Context) ([]cluster.NodeStorageRetirement, error)
}

func (s *Service) authoritativeRetirementReader() (authoritativeRetirementReader, bool) {
	if s == nil || !s.cfg.EnableCluster {
		return nil, false
	}
	c := s.Cluster()
	if c == nil {
		return nil, false
	}
	r, ok := c.(authoritativeRetirementReader)
	return r, ok
}

func (s *Service) nodeStorageRetirementReader() (interface {
	NodeStorageRetirements(context.Context) ([]cluster.NodeStorageRetirement, error)
}, bool) {
	if s == nil || !s.cfg.EnableCluster {
		return nil, false
	}
	c := s.Cluster()
	if c == nil {
		return nil, false
	}
	r, ok := c.(interface {
		NodeStorageRetirements(context.Context) ([]cluster.NodeStorageRetirement, error)
	})
	return r, ok
}

// clusterNodeStorageRetirements reads the replicated set. An unreachable
// control plane is an error, never an empty set: reading "no attestations"
// from a failed RPC would silently re-pin obligations an operator discharged,
// and reading a stale one could discharge an obligation that was revoked.
func (s *Service) clusterNodeStorageRetirements(ctx context.Context) (map[string]time.Time, error) {
	reader, ok := s.nodeStorageRetirementReader()
	if !ok {
		return nil, errors.New("cluster: node storage retirement registry is unavailable")
	}
	recs, err := reader.NodeStorageRetirements(ctx)
	if err != nil {
		return nil, err
	}
	byNode := make(map[string]time.Time, len(recs))
	for _, rec := range recs {
		byNode[rec.NodeID] = rec.AttestedAt()
	}
	return byNode, nil
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

	var byNode map[string]time.Time
	if _, clustered := s.nodeStorageRetirementReader(); clustered {
		replicated, err := s.clusterNodeStorageRetirements(ctx)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("cluster: node storage retirement read failed; obligations stay pending this tick", "err", err)
			}
			return nil
		}
		byNode = replicated
	} else {
		recs, err := s.store.ListNodeStorageRetirements(ctx)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("cluster: node storage retirement list failed", "err", err)
			}
			return nil
		}
		byNode = make(map[string]time.Time, len(recs))
		for _, rec := range recs {
			byNode[rec.NodeID] = rec.AttestedAt
		}
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
// The fence is PER RECIPIENT, and it compares the time that recipient's
// ciphertext COPY was distributed — not the time the deletion job was
// written. Both directions of the row-wide alternative are wrong:
//
//   - An upsert merges a new recipient into an existing row and preserves the
//     original created_at, so a recipient added after the attestation would
//     inherit an older row's age and be discharged without an ACK.
//   - A copy distributed before the disk was destroyed can have its deletion
//     journalled afterwards. That job belongs to the destroyed disk, but a
//     created_at fence reads it as a reused node id and pins it forever
//     against a node that can never ACK.
//
// copiedAt carries SecretDeleteOutboxRecord.RecipientCopiedAt; rows written
// before that column existed fall back to the row-wide createdAt, which is
// exactly the behavior they were written under.
func dischargeRetiredStorageRecipients(recipients []string, retired map[string]time.Time, createdAt time.Time, copiedAt map[string]time.Time) (pending, discharged []string) {
	if len(recipients) == 0 || len(retired) == 0 {
		return recipients, nil
	}
	pending = make([]string, 0, len(recipients))
	for _, id := range recipients {
		trimmed := strings.TrimSpace(id)
		attestedAt, ok := retired[trimmed]
		if ok {
			provenance := createdAt
			if at, found := copiedAt[trimmed]; found && !at.IsZero() {
				provenance = at
			}
			if !provenance.IsZero() && provenance.After(attestedAt) {
				// This copy was handed over after the operator attested the
				// disk destroyed, so it lives on a different physical node
				// behind a reused id. Still owed a real ACK.
				ok = false
			}
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
//
// It returns the node ids whose evidence is safe to act on. A durable sink
// that could not persist the record yields NOTHING for that node: the
// obligation is the only thing that will bring the discharge back for another
// attempt, so removing it on a failed write would lose both the retry and the
// per-sandbox discharge history, leaving only a node-level attestation that
// cannot say which lifecycles it covered. A warning in the log is not
// evidence.
func (s *Service) recordStorageRetirementDischarge(sandboxID, incarnationID string, generation int64, discharged []string) []string {
	if s == nil || len(discharged) == 0 {
		return nil
	}
	sink := s.secretAuditSink()
	_, ownerRef := s.auditIdentityFor(sandboxID)
	now := time.Now().UTC()
	recorded := make([]string, 0, len(discharged))
	for _, nodeID := range discharged {
		if sink != nil {
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
				if err := durable.EmitDurable(event); err != nil {
					if s.logger != nil {
						s.logger.Warn("cluster: storage-retirement discharge evidence not persisted; the obligation is retained so the discharge can be retried",
							"sandbox_id", sandboxID, "node_id", nodeID, "err", err)
					}
					continue
				}
			} else {
				sink.Emit(event)
			}
		}
		if s.logger != nil {
			s.logger.Warn("cluster: secret deletion obligation discharged by storage-retirement attestation, not by an ACK",
				"sandbox_id", sandboxID, "node_id", nodeID, "generation", generation)
		}
		recorded = append(recorded, nodeID)
	}
	secretObligationsDischargedTotal.Add(int64(len(recorded)))
	return recorded
}

func secretDeleteObligationRef(sandboxID, incarnationID string) string {
	return "secret-delete:" + sandboxID + ":" + incarnationID
}

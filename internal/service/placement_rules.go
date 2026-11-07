package service

import (
	"context"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// auditKindFailoverRefused is the audit record for a failover the cluster
// declined because it would break the sandbox's placement rule (P1.5). It
// uses only fields every build already hashes, so an older reader verifies
// it like any other record.
const auditKindFailoverRefused = "failover_refused"

// checkPlacementRule normalizes req.Placement in place and refuses the
// create when this node's labels do not satisfy it.
func (s *Service) checkPlacementRule(req *models.CreateSandboxRequest) error {
	placement, err := models.NormalizePlacementRule(req.Placement)
	if err != nil {
		return err
	}
	req.Placement = placement
	want := placement.RequiredLabels()
	if len(want) == 0 || models.LabelsSatisfy(s.cfg.NodeLabels, want) {
		return nil
	}
	return models.PlacementUnsatisfiableError(want)
}

// RecordFailoverRefused writes the audit record for a failover the cluster
// refused (cluster.FailoverRefusalRecorder). The leader calls it from its
// dead-owner tick, so it never blocks on the disk: Emit queues.
func (s *Service) RecordFailoverRefused(r cluster.FailoverRefusal) {
	if s == nil {
		return
	}
	sink := s.secretAuditSink()
	if sink == nil {
		return
	}
	actor := s.auditActor()
	ev := SecretAuditEvent{
		Time:          time.Now().UTC(),
		Actor:         actor,
		NodeID:        actor,
		SandboxID:     r.SandboxID,
		IncarnationID: r.IncarnationID,
		OwnerRef:      r.OwnerRef,
		Result:        secretAuditResultFailure,
		Reason:        r.Reason,
		Kind:          auditKindFailoverRefused,
		// Destination names the rule and the node the sandbox could not
		// leave. Neither is a secret; the rule is what an auditor asks for.
		Destination: "from=" + r.FromNodeID + " rule=" + r.Rule,
	}
	// The caller field is hash-covered and gated on every member reading
	// it (§5.8); without the gate the record still lands, unattributed.
	if s.auditCallerWritesAllowed() {
		ev.Caller = AuditCallerFromContext(controlplane.ContextWithSystemCaller(context.Background(), auditSubsystemFailover))
	}
	ensureSecretAuditEventID(&ev)
	sink.Emit(ev)
}

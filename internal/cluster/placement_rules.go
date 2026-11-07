package cluster

import (
	"errors"
	"expvar"
	"strings"

	"github.com/aerol-ai/microvm/internal/scaleobs"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Placement rules (plans/placement-rules.md). Labels ride the capacity
// heartbeat (capacity.Snapshot.Labels); the rule rides the replicated spec
// (models.CreateSandboxRequest.Placement) and becomes capacity.Request.Labels
// in capacityRequestFromSpec. There is no FSM op: replaying an old entry,
// which has no rule, places exactly as it did.

// FailoverRefusalReasonPlacement names a failover refused because the
// sandbox's placement rule excludes every live candidate.
const FailoverRefusalReasonPlacement = "placement_unsatisfiable"

// clusterFailoverRefused counts failovers that found a target only by
// breaking a rule, by reason. A sandbox that hits it is orphaned instead of
// moved: its own node reclaims it when it returns.
var clusterFailoverRefused = expvar.NewMap("aerolvm_cluster_failover_refused_total")

// FailoverRefusal is one failover the cluster declined to perform because
// moving the sandbox would break a rule it was created with.
type FailoverRefusal struct {
	SandboxID     string
	IncarnationID string
	OwnerRef      string
	// FromNodeID is the dead or stuck owner the sandbox could not leave.
	FromNodeID string
	Reason     string
	// Rule is the rule as text ("gpu=a10, zone=eu-west-1a").
	Rule string
}

// FailoverRefusalRecorder is the optional half of SandboxRecreator that
// writes the audit record for a refused failover. The service implements it;
// a recreator that does not just leaves the counter and the log line.
type FailoverRefusalRecorder interface {
	RecordFailoverRefused(FailoverRefusal)
}

// reportFailoverRefused counts, logs and audits one refused failover. It runs
// on the leader's dead-owner tick and on the stuck-placement escalation, both
// bounded by the placements involved, never per create.
func (c *Cluster) reportFailoverRefused(p Placement, fromNodeID string, cause error) {
	reason := "unknown"
	if errors.Is(cause, ErrPlacementUnsatisfiable) {
		reason = FailoverRefusalReasonPlacement
	}
	scaleobs.Add(clusterFailoverRefused, reason, 1)
	rule := ""
	if p.Spec != nil {
		rule = models.FormatLabels(p.Spec.Placement.RequiredLabels())
	}
	if c.logger != nil {
		c.logger.Warn("cluster: failover refused; the sandbox's placement rule excludes every live node",
			"sandbox_id", p.SandboxID, "from_node", fromNodeID, "rule", rule)
	}
	if rec, ok := c.currentRecreator().(FailoverRefusalRecorder); ok {
		rec.RecordFailoverRefused(FailoverRefusal{
			SandboxID:     p.SandboxID,
			IncarnationID: strings.TrimSpace(p.IncarnationID),
			OwnerRef:      strings.TrimSpace(p.OwnerRef),
			FromNodeID:    fromNodeID,
			Reason:        reason,
			Rule:          rule,
		})
	}
}

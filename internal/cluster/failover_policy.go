package cluster

import "github.com/aerol-ai/microvm/pkg/models"

// reassignCauseFailover tags an opReassign issued by a failover path (dead-owner
// eviction or stuck-placement escalation) as opposed to an operator-driven or
// live-migration ReassignPlacement. Only the failover ones feed
// aerolvm_cluster_failover_reassign_total.
const reassignCauseFailover = "failover"

func placementWantsFailoverRecreate(p Placement) bool {
	return specWantsFailoverRecreate(p.Spec)
}

func specWantsFailoverRecreate(spec *models.CreateSandboxRequest) bool {
	return spec != nil && spec.ShouldRecreateOnFailover()
}

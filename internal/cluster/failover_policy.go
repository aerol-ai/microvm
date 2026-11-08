package cluster

import "github.com/aerol-ai/microvm/pkg/models"

// reassignCauseFailover tags an opReassign issued by a failover path (dead-owner
// eviction or stuck-placement escalation) as opposed to an operator-driven or
// live-migration ReassignPlacement. Only the failover ones feed
// aerolvm_cluster_failover_reassign_total.
const reassignCauseFailover = "failover"

func placementWantsFailoverRecreate(p Placement) bool {
	return !p.IsDeleting() && specWantsFailoverRecreate(p.Spec)
}

func specWantsFailoverRecreate(spec *models.CreateSandboxRequest) bool {
	return spec != nil && spec.ShouldRecreateOnFailover()
}

// placementMovableOnFailover reports whether the leader may hand p to another
// worker when its owner looks dead: the only rows a cut-off reader cannot keep
// routing by. It is placementWantsFailoverRecreate, plus the hot-row mirror
// for the paged and feed reads, which carry no Spec.
func placementMovableOnFailover(p Placement) bool {
	return placementWantsFailoverRecreate(p) || (!p.IsDeleting() && p.FailoverRecreate)
}

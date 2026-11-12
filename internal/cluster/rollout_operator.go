package cluster

import (
	"context"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Operator-driven rollout steps (C13, plans/kubernetes-v2-architecture.md
// §13; eng review SC-1 and D6).
//
// In a Kubernetes pod a node never fetches or runs a new binary: the
// operator changes the pod's agent image. Before C13 such a node answered
// its stage step "SB_REMOTE_UPGRADE=false", the walk marked it manual, and
// order, pacing and --pause-after did not apply to it. Now a node with
// SB_UPGRADE_DRIVER=operator answers operator_driven, and the leader records
// it as staged with the operator flag. When the walk reaches it, the leader
// cordons it and marks it upgrading with a deadline, as for any node, but
// calls nothing. The operator, watching the rollout, sees the flag and the
// state, swaps the image, and confirms the swap by the container's imageID;
// the leader marks the node done once it reports the target version and is
// healthy, or failed at the deadline (an image that cannot be pulled ends
// there). Everything after that (pacing, pauses, finalize, rollback) is the
// walk that already runs for VMs.

// rolloutOperatorFSMOpsVersion: the rollout node record's operator flag. An
// older server decodes the record without it and, as leader, would call the
// node's upgrader, which the node refuses: the node would fail. So the flag
// is written only once every Raft server reports this version; until then
// the node is manual, as before C13.
const rolloutOperatorFSMOpsVersion = 16

// upgradeDriverKey carries the caller's "driver" (the query parameter
// ?driver=operator on apply and rollback) to the leader's checks.
type upgradeDriverKey struct{}

// WithUpgradeDriver returns ctx carrying who drives this apply or rollback:
// "operator" when the Kubernetes operator sends it.
func WithUpgradeDriver(ctx context.Context, driver string) context.Context {
	return context.WithValue(ctx, upgradeDriverKey{}, strings.TrimSpace(driver))
}

// refuseUnlessOperator keeps AerolCluster.spec.version the one place that
// sets a Kubernetes cluster's version (eng review D6): on a leader with
// SB_UPGRADE_DRIVER=operator, an apply or rollback not sent by the operator
// is refused with a hint. A guard against two owners of one setting, not an
// access control: the caller is an admin either way. Status, stop, resume
// and finalize set no version and keep working.
func (c *Cluster) refuseUnlessOperator(ctx context.Context) error {
	if !c.cfg.UpgradesByOperator() {
		return nil
	}
	if d, _ := ctx.Value(upgradeDriverKey{}).(string); d == config.UpgradeDriverOperator {
		return nil
	}
	return rolloutErr(http.StatusConflict, upgradewire.ErrCodeKubernetesManaged,
		"this cluster runs on Kubernetes, where the AerolVM operator upgrades it",
		"change AerolCluster spec.version (helm upgrade, or edit the object); setting it back to the previous version rolls back. aerolvm upgrade status, stop, resume and finalize still work here")
}

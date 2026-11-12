package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Upgrades on Kubernetes (plans/kubernetes-v2-architecture.md §13; C13).
// AerolCluster.spec.version is the one place that sets the version (eng
// review D6). When it moves, the operator starts AerolVM's own rollout with
// source "images": the leader walks the nodes in its order, with its
// pacing, canary pause and finalize, and marks each node's turn. The
// operator is that node's hands: it swaps the node's agent image and the
// leader marks the node done once it reports the new version. Lowering
// spec.version during or after an upgrade is a rollback.

// rolloutActive reports a rollout that is walking or holding nodes.
func rolloutActive(state string) bool {
	switch state {
	case upgradewire.StateStaging, upgradewire.StateRunning, upgradewire.StatePaused, upgradewire.StateRollingBack, upgradewire.StateFinalizing:
		return true
	}
	return false
}

// rolloutVersion is where a rollout takes its nodes: the target, or the
// previous version while it rolls back.
func rolloutVersion(ro *upgradewire.Rollout) string {
	if ro.Direction == upgradewire.DirectionRollback {
		return ro.PreviousVersion
	}
	return ro.TargetVersion
}

// reconcileUpgrade starts, carries out or rolls back the rollout that
// takes the cluster to spec.version.
func (r *ClusterReconciler) reconcileUpgrade(ctx context.Context, c *v1.AerolCluster, api AerolAPI, nodes []v1.AerolNode) error {
	ro, err := api.Rollout(ctx)
	if err != nil {
		return err
	}
	if ro != nil {
		c.Status.Rollout = &v1.RolloutStatus{ID: ro.ID, State: ro.State, Target: rolloutVersion(ro)}
	}
	want := c.Spec.Version
	if ro != nil && rolloutActive(ro.State) {
		switch {
		case rolloutVersion(ro) == want:
			return r.carryOut(ctx, ro, nodes)
		case ro.Direction == upgradewire.DirectionUpgrade && ro.PreviousVersion == want:
			r.event(c, corev1.EventTypeNormal, "Rollback", fmt.Sprintf("spec.version is back to %s: rolling back", want))
			return api.Rollback(ctx)
		default:
			r.event(c, corev1.EventTypeWarning, "VersionWaits", fmt.Sprintf("spec.version %s waits for the rollout to %s to end", want, rolloutVersion(ro)))
			return nil
		}
	}
	running := c.Status.Version
	if running == "" || running == want {
		return nil
	}
	if ro != nil && ro.State == upgradewire.StateDone && rolloutVersion(ro) == want {
		// Done but some node still reports the old version (it joined or
		// was replaced meanwhile): its own pod gets the new image, below.
		return r.carryOut(ctx, ro, nodes)
	}
	r.event(c, corev1.EventTypeNormal, "Upgrade", fmt.Sprintf("upgrading from %s to %s", running, want))
	_, err = api.ApplyImages(ctx, want, upgradewire.ApplyRequest{Batch: "1", NodeTimeout: "15m"})
	return err
}

// carryOut marks each node whose turn the leader marked: the node
// controller swaps its agent image to the version.
func (r *ClusterReconciler) carryOut(ctx context.Context, ro *upgradewire.Rollout, nodes []v1.AerolNode) error {
	version := rolloutVersion(ro)
	byName := map[string]*v1.AerolNode{}
	for i := range nodes {
		byName[nodes[i].Name] = &nodes[i]
	}
	for _, rn := range ro.Nodes {
		n := byName[rn.NodeID]
		if n == nil || !rn.Operator || rn.State != upgradewire.NodeUpgrading {
			continue
		}
		if n.Annotations[AnnotationAgentVersion] == version {
			continue
		}
		patch := client.MergeFrom(n.DeepCopy())
		if n.Annotations == nil {
			n.Annotations = map[string]string{}
		}
		n.Annotations[AnnotationAgentVersion] = version
		if err := r.Patch(ctx, n, patch); err != nil {
			return err
		}
		r.event(n, corev1.EventTypeNormal, "Upgrading", "its turn: agent to "+version)
	}
	return nil
}

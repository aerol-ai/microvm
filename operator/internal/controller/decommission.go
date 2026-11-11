package controller

import (
	"context"
	"fmt"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/operator/internal/aerolapi"
)

// A worker's decommission (C9; plans/kubernetes-v2-architecture.md §10.5,
// §10.6). The rule: a machine that is going away is the signal to
// decommission its worker first. Every tool we care about cordons first;
// Karpenter, which a worker's do-not-disrupt annotation keeps from
// cordoning, marks the machine's NodeClaim Drifted instead. Each step is
// recorded on the AerolNode and safe to repeat, so an operator restart
// mid-sequence picks up where it stopped (eng review OV-E6):
//
//	cordon in AerolVM -> drain window -> evacuate passes -> deadline stop
//	-> delete the pod -> delete the AerolVM node -> delete the NodeClaim
//
// Deleting the NodeClaim returns the machine when the operator retires it
// by age itself (Karpenter's own expiry is off on worker pools, §10.6).

var nodeClaimGVK = schema.GroupVersionKind{Group: "karpenter.sh", Version: "v1", Kind: "NodeClaim"}

// decommissionTriggers starts a decommission when the worker's machine is
// cordoned or its NodeClaim drifted.
func (r *NodeReconciler) decommissionTriggers(ctx context.Context, c *v1.AerolCluster, n *v1.AerolNode, pod *corev1.Pod) (ctrl.Result, bool, error) {
	if pod == nil || pod.Spec.NodeName == "" || n.Annotations[v1.AnnotationDecommission] == "true" {
		return ctrl.Result{}, false, nil
	}
	var node corev1.Node
	if err := r.Get(ctx, types.NamespacedName{Name: pod.Spec.NodeName}, &node); err != nil {
		return ctrl.Result{}, false, client.IgnoreNotFound(err)
	}
	why := ""
	switch {
	case node.Spec.Unschedulable:
		why = "its machine " + node.Name + " was cordoned"
	case r.nodeClaimDrifted(ctx, node.Name):
		why = "its machine " + node.Name + " drifted (Karpenter)"
	}
	if why == "" {
		return ctrl.Result{}, false, nil
	}
	patch := client.MergeFrom(n.DeepCopy())
	if n.Annotations == nil {
		n.Annotations = map[string]string{}
	}
	n.Annotations[v1.AnnotationDecommission] = "true"
	if err := r.Patch(ctx, n, patch); err != nil {
		return ctrl.Result{}, true, err
	}
	if r.Recorder != nil {
		r.Recorder.Event(n, corev1.EventTypeNormal, "Decommission", "decommission started: "+why)
	}
	return ctrl.Result{Requeue: true}, true, nil
}

// nodeClaimDrifted reports whether node's Karpenter NodeClaim has
// Drifted=True. No Karpenter, no NodeClaim: false.
func (r *NodeReconciler) nodeClaimDrifted(ctx context.Context, node string) bool {
	nc := r.nodeClaim(ctx, node)
	if nc == nil {
		return false
	}
	conds, _, _ := unstructured.NestedSlice(nc.Object, "status", "conditions")
	for _, raw := range conds {
		cond, _ := raw.(map[string]any)
		if cond["type"] == "Drifted" && cond["status"] == "True" {
			return true
		}
	}
	return false
}

func (r *NodeReconciler) nodeClaim(ctx context.Context, node string) *unstructured.Unstructured {
	var list unstructured.UnstructuredList
	list.SetGroupVersionKind(nodeClaimGVK.GroupVersion().WithKind("NodeClaimList"))
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	for i := range list.Items {
		name, _, _ := unstructured.NestedString(list.Items[i].Object, "status", "nodeName")
		if name == node {
			return &list.Items[i]
		}
	}
	return nil
}

func drainWindow(p *v1.WorkerPoolSpec) time.Duration {
	if p != nil && p.Decommission.DrainWindow != nil {
		return p.Decommission.DrainWindow.Duration
	}
	if p != nil && p.Provisioner == "eks-managed" {
		// A managed node group evicts after 15 minutes whatever happens;
		// the moves need the rest (§10.6).
		return eksManagedDrain
	}
	return defaultDrainWindow
}

func decomDeadline(p *v1.WorkerPoolSpec) time.Duration {
	if p != nil && p.Decommission.Deadline != nil {
		return p.Decommission.Deadline.Duration
	}
	return defaultDecomDeadline
}

// decommission carries one worker's decommission one step further.
func (r *NodeReconciler) decommission(ctx context.Context, c *v1.AerolCluster, n *v1.AerolNode, pod *corev1.Pod, api AerolAPI) (ctrl.Result, error) {
	now := r.now()
	pool := poolOf(c, n.Spec.Pool)
	d := n.Status.Decommission
	if d == nil {
		d = &v1.DecommissionStatus{
			StartedAt:  metav1.NewTime(now),
			DrainUntil: metav1.NewTime(now.Add(drainWindow(pool))),
			Deadline:   metav1.NewTime(now.Add(decomDeadline(pool))),
		}
		n.Status.Decommission = d
	}
	if pod == nil && d.Remaining == 0 && d.Moved == 0 && n.Status.PodName == "" {
		// Never had a pod: nothing to move.
		r.setState(n, v1.StateRemoved, "decommissioned before it started")
		return ctrl.Result{Requeue: true}, nil
	}
	if !d.NodeDeleted {
		if err := api.Cordon(ctx, n.Name); err != nil && !aerolapi.IsStatus(err, http.StatusNotFound) {
			return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
		}
	}
	if now.Before(d.DrainUntil.Time) && !d.NodeDeleted {
		if node, err := api.GetNode(ctx, n.Name); err == nil && node.SandboxesOwned == 0 {
			// Nothing to wait for.
			d.DrainUntil = metav1.NewTime(now)
		} else {
			r.setState(n, v1.StateDraining, "drain window until "+d.DrainUntil.UTC().Format(time.RFC3339))
			return ctrl.Result{RequeueAfter: min(time.Until(d.DrainUntil.Time)+time.Second, time.Minute)}, nil
		}
	}
	if !d.NodeDeleted {
		r.setState(n, v1.StateDecommissioning, "")
		before := d.Moved
		res, err := api.Evacuate(ctx, n.Name, aerolapi.EvacuateRequest{
			DeadlineUnix: d.Deadline.Unix(), StopRemaining: !now.Before(d.Deadline.Time),
		})
		switch {
		case aerolapi.IsStatus(err, http.StatusConflict) && pod == nil:
			// Not alive and no pod: the dead-owner failover has it.
			return r.lost(ctx, n, api)
		case aerolapi.IsStatus(err, http.StatusNotFound):
			res.Done = true
		case err != nil:
			return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
		}
		d.Moved += int32(len(res.Moved))
		d.Remaining = int32(res.RemainingMovable + res.Remaining)
		r.progressEvent(n, before, d)
		movedAll := res.RemainingMovable == 0
		if !res.Done && !(movedAll && !now.Before(d.Deadline.Time)) {
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		// Done, or the deadline passed with every movable sandbox moved
		// and the rest stopped: the node leaves the cluster (what is left
		// is orphaned, its owners were told), then its pod goes.
		if err := api.DeleteNode(ctx, n.Name, true); err != nil {
			return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
		}
		d.NodeDeleted = true
	}
	if pod != nil {
		if err := r.Delete(ctx, pod); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}
	if n.Status.NodeName != "" {
		r.retireMachine(ctx, n.Status.NodeName)
	}
	decommissionSeconds.Observe(now.Sub(d.StartedAt.Time).Seconds())
	r.setState(n, v1.StateRemoved, fmt.Sprintf("decommissioned: %d moved", d.Moved))
	return ctrl.Result{Requeue: true}, nil
}

// progressEvent writes at most one Event per 10% of the node's sandboxes
// moved (P10).
func (r *NodeReconciler) progressEvent(n *v1.AerolNode, before int32, d *v1.DecommissionStatus) {
	total := d.Moved + d.Remaining
	if r.Recorder == nil || total == 0 || d.Moved == before {
		return
	}
	if d.Moved*10/total == before*10/total && d.Remaining != 0 {
		return
	}
	r.Recorder.Event(n, corev1.EventTypeNormal, "Decommissioning",
		fmt.Sprintf("%d of %d sandboxes moved, %d left", d.Moved, total, d.Remaining))
}

// retireMachine returns an emptied machine: its Karpenter NodeClaim is
// deleted, so Karpenter takes the empty machine. Without Karpenter the
// pool's own autoscaler does.
func (r *NodeReconciler) retireMachine(ctx context.Context, node string) {
	if nc := r.nodeClaim(ctx, node); nc != nil {
		_ = client.IgnoreNotFound(r.Delete(ctx, nc))
	}
}

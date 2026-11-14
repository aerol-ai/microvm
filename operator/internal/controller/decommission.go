package controller

import (
	"context"
	"fmt"
	"net/http"
	"sync"
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

// karpenterNodePoolLabel is on every Node Karpenter launches.
const karpenterNodePoolLabel = "karpenter.sh/nodepool"

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
	case r.nodeClaimDrifted(ctx, &node):
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
func (r *NodeReconciler) nodeClaimDrifted(ctx context.Context, node *corev1.Node) bool {
	// Only a machine Karpenter made has a NodeClaim; it labels each one
	// with its NodePool. Others never cost a NodeClaim read, and a cluster
	// without Karpenter never starts a NodeClaim informer.
	if node.Labels[karpenterNodePoolLabel] == "" {
		return false
	}
	nc := r.nodeClaim(ctx, node.Name)
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

// eksManagedDecomCap bounds a whole decommission, drain window and moves
// together, on an EKS managed node group pool (§10.6). A managed node
// group update evicts a cordoned machine's pods for 15 minutes, then stops
// with PodEvictionFailure unless someone forces it. The worker's
// PodDisruptionBudget (#1270) holds the eviction until the decommission
// deletes the pod, so the decommission must end inside those 15 minutes,
// with a minute to spare.
const eksManagedDecomCap = 14 * time.Minute

func eksManaged(p *v1.WorkerPoolSpec) bool { return p != nil && p.Provisioner == "eks-managed" }

// decommissionPool is the pool whose settings time a worker's decommission:
// the spec's, or, for a pool the spec no longer has, the settings the
// status kept for it (keepPoolDecommission). Nil: neither, so the defaults.
func decommissionPool(c *v1.AerolCluster, name string) *v1.WorkerPoolSpec {
	if p := poolOf(c, name); p != nil {
		return p
	}
	for _, k := range c.Status.PoolDecommission {
		if k.Name == name {
			return &v1.WorkerPoolSpec{Name: k.Name, Provisioner: k.Provisioner, Decommission: k.Decommission}
		}
	}
	return nil
}

func drainWindow(p *v1.WorkerPoolSpec) time.Duration {
	d := defaultDrainWindow
	switch {
	case p != nil && p.Decommission.DrainWindow != nil:
		d = p.Decommission.DrainWindow.Duration
	case eksManaged(p):
		// A managed node group evicts after 15 minutes whatever happens;
		// the moves need the rest (§10.6).
		d = eksManagedDrain
	}
	if eksManaged(p) {
		d = min(d, eksManagedDecomCap)
	}
	return d
}

func decomDeadline(p *v1.WorkerPoolSpec) time.Duration {
	d := defaultDecomDeadline
	if p != nil && p.Decommission.Deadline != nil {
		d = p.Decommission.Deadline.Duration
	}
	if eksManaged(p) {
		d = min(d, eksManagedDecomCap)
	}
	return d
}

// decommission carries one worker's decommission one step further.
func (r *NodeReconciler) decommission(ctx context.Context, c *v1.AerolCluster, n *v1.AerolNode, pod *corev1.Pod, api AerolAPI) (ctrl.Result, error) {
	now := r.now()
	pool := decommissionPool(c, n.Spec.Pool)
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
	// A pass started earlier is still running or has an answer: the
	// cordon and the drain window are behind it.
	run := r.evacuations().get(evacKey(n))
	if !d.NodeDeleted && run == nil {
		if err := api.Cordon(ctx, n.Name); err != nil && !aerolapi.IsStatus(err, http.StatusNotFound) {
			return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
		}
	}
	if run == nil && now.Before(d.DrainUntil.Time) && !d.NodeDeleted {
		if node, err := api.GetNode(ctx, n.Name); (err == nil && node.SandboxesOwned == 0) || aerolapi.IsStatus(err, http.StatusNotFound) {
			// Nothing to wait for: it owns nothing, or it never joined
			// (a worker whose pod never got a machine) and so owns
			// nothing either.
			d.DrainUntil = metav1.NewTime(now)
		} else {
			r.setState(n, v1.StateDraining, "drain window until "+d.DrainUntil.UTC().Format(time.RFC3339))
			return ctrl.Result{RequeueAfter: min(time.Until(d.DrainUntil.Time)+time.Second, time.Minute)}, nil
		}
	}
	if !d.NodeDeleted {
		r.setState(n, v1.StateDecommissioning, "")
		if run == nil {
			req := aerolapi.EvacuateRequest{DeadlineUnix: d.Deadline.Unix(), StopRemaining: !now.Before(d.Deadline.Time)}
			name := n.Name
			if run = r.evacuations().start(evacKey(n), req, func(ctx context.Context) (aerolapi.EvacuateResult, error) {
				return api.Evacuate(ctx, name, req)
			}); run == nil {
				r.setState(n, v1.StateDecommissioning, fmt.Sprintf("waiting its turn: %d evacuate passes run already", maxEvacuations))
				return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
			}
		}
		if !run.wait(r.evacuateWait()) {
			return ctrl.Result{RequeueAfter: evacuatePoll}, nil
		}
		r.evacuations().forget(evacKey(n))
		before := d.Moved
		res, err := run.res, run.err
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
		// The pass's own request says whether it stopped the rest: the
		// deadline may have passed while it ran.
		if !res.Done && !(movedAll && run.req.StopRemaining) {
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

// Decommission passes run in the background (review R3). One pass moves up
// to 8 sandboxes, each waiting for its target to pull the image (up to
// 90 s), so a pass can take minutes. A reconcile that waited for it held
// one of the node controller's workers that long, and with the default of
// one worker, every node in the cell. A reconcile now starts the pass,
// waits EvacuateWait for it (most passes answer in well under that), and
// otherwise comes back for the answer every evacuatePoll. The answer is
// handled exactly as before; the AerolNode still records every step.
const (
	defaultEvacuateWait = 2 * time.Second
	evacuatePoll        = 5 * time.Second
	// maxEvacuations bounds the passes running at once, operator-wide: with
	// many machines cordoned at once (a node group upgrade), each pass's
	// moves still land on the one leader.
	maxEvacuations = 16
	// evacuateRunTimeout bounds a pass's goroutine past its HTTP call's own
	// bound (aerolapi.EvacuateTimeout).
	evacuateRunTimeout = aerolapi.EvacuateTimeout + time.Minute
	// evacuateKeep is how long an answer nobody came back for is kept: its
	// AerolNode went away mid-pass.
	evacuateKeep = 30 * time.Minute
)

// evacuations holds the passes in flight and the answers not yet taken.
type evacuations struct {
	mu   sync.Mutex
	runs map[string]*evacRun
}

// evacRun is one pass. res and err are set before done is closed.
type evacRun struct {
	req    aerolapi.EvacuateRequest
	done   chan struct{}
	res    aerolapi.EvacuateResult
	err    error
	doneAt time.Time
}

// evacKey names a node's pass by its object, not only its name: a worker
// name is random, but a node made again under the same name must not take
// an old answer.
func evacKey(n *v1.AerolNode) string { return n.Name + "/" + string(n.UID) }

func (r *NodeReconciler) evacuations() *evacuations {
	r.evacOnce.Do(func() { r.evacs = &evacuations{runs: map[string]*evacRun{}} })
	return r.evacs
}

func (r *NodeReconciler) evacuateWait() time.Duration {
	if r.EvacuateWait > 0 {
		return r.EvacuateWait
	}
	return defaultEvacuateWait
}

// get is key's pass, running or answered; nil when there is none.
func (e *evacuations) get(key string) *evacRun {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.runs[key]
}

// start runs pass for key in the background; nil when maxEvacuations
// passes run already.
func (e *evacuations) start(key string, req aerolapi.EvacuateRequest, pass func(context.Context) (aerolapi.EvacuateResult, error)) *evacRun {
	e.mu.Lock()
	defer e.mu.Unlock()
	running := 0
	for k, run := range e.runs {
		select {
		case <-run.done:
			if time.Since(run.doneAt) > evacuateKeep {
				delete(e.runs, k)
			}
		default:
			running++
		}
	}
	if running >= maxEvacuations {
		return nil
	}
	run := &evacRun{req: req, done: make(chan struct{})}
	e.runs[key] = run
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), evacuateRunTimeout)
		defer cancel()
		res, err := pass(ctx)
		e.mu.Lock()
		run.res, run.err, run.doneAt = res, err, time.Now()
		e.mu.Unlock()
		close(run.done)
	}()
	return run
}

// forget drops key's answer once it is taken.
func (e *evacuations) forget(key string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.runs, key)
}

// wait reports whether the pass answered within d.
func (run *evacRun) wait(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-run.done:
		return true
	case <-t.C:
		return false
	}
}

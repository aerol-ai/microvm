// Package webhook holds the worker-pod delete guard (C26, eng review D5;
// plans/kubernetes-v2-architecture.md §8.6).
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
)

// Deleting a live worker pod ends every sandbox on it at once. A plain
// `kubectl delete pod`, a script or a mistaken GitOps prune would do that.
// So the guard refuses it, unless:
//
//   - the operator itself asks (its decommission and its cleanup);
//   - the pod's AerolNode is removed, dead, failed or gone, or its
//     decommission finished moving its sandboxes;
//   - the pod is not running (never started, or already failed);
//   - a person set aerolvm.io/force-delete=true on the pod. That delete is
//     logged here, with who asked, and the API server's audit log has it too.
//
// A node that is draining or decommissioning is not enough: its sandboxes
// are still moving, and the operator deletes the pod itself once they have
// moved or stopped.
//
// An eviction (kubectl drain, a node group update, Karpenter) ends the pod
// the same way, so the same rules decide it. The chart's worker
// PodDisruptionBudget refuses evictions first; this check holds if that
// budget is removed.
//
// The webhook is registered with failurePolicy: Ignore, so an operator
// outage never blocks a cluster repair; the "worker pod lost without a
// decommission" alert (aerolvm_operator_worker_pods_lost_total) still fires.

// PodGuard is the admission handler.
type PodGuard struct {
	Client client.Reader
	// OperatorUser is the operator's own service account user name,
	// system:serviceaccount:<namespace>:<name>.
	OperatorUser string
	// Namespace holds the AerolNodes.
	Namespace string
}

// gcUser is the garbage collector, which deletes what an owner left.
const gcUser = "system:serviceaccount:kube-system:generic-garbage-collector"

// Handle decides one pod delete or eviction.
func (g *PodGuard) Handle(ctx context.Context, req admission.Request) admission.Response {
	var pod *corev1.Pod
	evict := false
	switch {
	case req.Operation == admissionv1.Delete:
		pod = &corev1.Pod{}
		if err := json.Unmarshal(req.OldObject.Raw, pod); err != nil {
			// Unreadable: let it through, as an outage would.
			return admission.Allowed("unreadable pod; not guarded")
		}
	case req.Operation == admissionv1.Create && req.SubResource == "eviction":
		evict = true
		var why string
		if pod, why = g.evictedPod(ctx, req); pod == nil {
			return admission.Allowed(why)
		}
	default:
		return admission.Allowed("")
	}
	allowed, why := g.decide(ctx, pod, req.UserInfo.Username)
	if !allowed {
		if evict {
			return refuseEviction(why)
		}
		return admission.Denied(why)
	}
	if strings.HasPrefix(why, "forced") {
		verb := "deleted"
		if evict {
			verb = "evicted"
		}
		log.FromContext(ctx).Info("worker pod "+verb+" with force-delete", "pod", pod.Namespace+"/"+pod.Name, "user", req.UserInfo.Username)
		return admission.Allowed(why).WithWarnings("deleting worker pod " + pod.Name + " ends every sandbox on it; recorded")
	}
	return admission.Allowed(why)
}

// evictedPod reads the pod an eviction names. The request carries an
// Eviction, not the pod, and an Eviction has none of the pod's labels, so
// the webhook rule for it cannot select worker pods by label either.
func (g *PodGuard) evictedPod(ctx context.Context, req admission.Request) (*corev1.Pod, string) {
	key := client.ObjectKey{Namespace: req.Namespace, Name: req.Name}
	if key.Name == "" {
		var e policyv1.Eviction
		if err := json.Unmarshal(req.Object.Raw, &e); err != nil || e.Name == "" {
			return nil, "unreadable eviction; not guarded"
		}
		key.Name = e.Name
		if key.Namespace == "" {
			key.Namespace = e.Namespace
		}
	}
	var pod corev1.Pod
	if err := g.Client.Get(ctx, key, &pod); err != nil {
		// No such pod (the eviction fails by itself), or cannot tell:
		// fail open, as the webhook's failure policy does.
		return nil, "could not read the pod"
	}
	return &pod, ""
}

// refuseEviction refuses the way a PodDisruptionBudget does, with 429 Too
// Many Requests. kubectl drain, a managed node group update and Karpenter
// then wait and retry while the operator moves the worker's sandboxes; a
// 403 would make kubectl drain give up at once.
func refuseEviction(why string) admission.Response {
	resp := admission.Denied(why)
	resp.Result.Code = http.StatusTooManyRequests
	resp.Result.Reason = metav1.StatusReasonTooManyRequests
	return resp
}

func (g *PodGuard) decide(ctx context.Context, pod *corev1.Pod, user string) (bool, string) {
	if pod.Labels["app.kubernetes.io/component"] != v1.RoleWorker || pod.Labels["app.kubernetes.io/name"] != "aerolvm" {
		return true, "not a worker pod"
	}
	if user == g.OperatorUser && g.OperatorUser != "" {
		return true, "the operator"
	}
	if pod.Annotations[v1.AnnotationForceDelete] == "true" {
		return true, "forced by " + user
	}
	if pod.Status.Phase != corev1.PodRunning {
		return true, "not running"
	}
	name := pod.Labels["aerolvm.io/node"]
	var n v1.AerolNode
	err := g.Client.Get(ctx, client.ObjectKey{Namespace: g.Namespace, Name: name}, &n)
	switch {
	case client.IgnoreNotFound(err) != nil:
		// Cannot tell: fail open, as the webhook's failure policy does.
		return true, "could not read its AerolNode"
	case err != nil:
		return true, "no AerolNode"
	case n.DeletionTimestamp != nil && user == gcUser:
		return true, "its AerolNode is being deleted"
	}
	switch n.Status.State {
	case v1.StateRemoved, v1.StateDead, v1.StateFailed:
		return true, "its node is " + n.Status.State
	}
	d := n.Status.Decommission
	if n.Annotations[v1.AnnotationDecommission] == "true" && d != nil && d.Remaining == 0 && d.Moved > 0 {
		return true, "decommissioned"
	}
	force := fmt.Sprintf("kubectl annotate pod %s %s=true -n %s", pod.Name, v1.AnnotationForceDelete, pod.Namespace)
	if n.Status.State == v1.StateDraining || n.Status.State == v1.StateDecommissioning {
		left := fmt.Sprintf("%d sandboxes on it", n.Status.Sandboxes)
		if d != nil && (d.Moved > 0 || d.Remaining > 0) {
			left = fmt.Sprintf("%d moved, %d left", d.Moved, d.Remaining)
		}
		return false, fmt.Sprintf("worker pod %s is still being decommissioned (%s: %s); the operator deletes it once the rest "+
			"have moved or stopped. To delete it now anyway, ending what is left: %s",
			pod.Name, n.Status.State, left, force)
	}
	return false, fmt.Sprintf("worker pod %s runs sandboxes (%d) and is not decommissioned; deleting it ends them all. "+
		"Decommission it (kubectl annotate aerolnode %s %s=true -n %s) or, to delete it anyway, %s",
		pod.Name, n.Status.Sandboxes, name, v1.AnnotationDecommission, g.Namespace, force)
}

var _ admission.Handler = (*PodGuard)(nil)

// Path is where the chart's ValidatingWebhookConfiguration points, for
// both deletes and evictions.
const Path = "/validate-worker-pod-delete"

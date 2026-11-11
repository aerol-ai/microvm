// Package webhook holds the worker-pod delete guard (C26, eng review D5;
// plans/kubernetes-v2-architecture.md §8.6).
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
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
//   - the pod's AerolNode is decommissioning, removed or gone;
//   - the pod is not running (never started, or already failed);
//   - a person set aerolvm.io/force-delete=true on the pod. That delete is
//     logged here, with who asked, and the API server's audit log has it too.
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

// Handle decides one pod delete.
func (g *PodGuard) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation != admissionv1.Delete {
		return admission.Allowed("")
	}
	var pod corev1.Pod
	if err := json.Unmarshal(req.OldObject.Raw, &pod); err != nil {
		// Unreadable: let it through, as an outage would.
		return admission.Allowed("unreadable pod; not guarded")
	}
	allowed, why := g.decide(ctx, &pod, req.UserInfo.Username)
	if !allowed {
		return admission.Denied(why)
	}
	if strings.HasPrefix(why, "forced") {
		log.FromContext(ctx).Info("worker pod deleted with force-delete", "pod", pod.Namespace+"/"+pod.Name, "user", req.UserInfo.Username)
		return admission.Allowed(why).WithWarnings("deleting worker pod " + pod.Name + " ends every sandbox on it; recorded")
	}
	return admission.Allowed(why)
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
	case v1.StateDecommissioning, v1.StateRemoved, v1.StateDead, v1.StateFailed:
		return true, "its node is " + n.Status.State
	}
	if n.Annotations[v1.AnnotationDecommission] == "true" && n.Status.Decommission != nil && n.Status.Decommission.Remaining == 0 && n.Status.Decommission.Moved > 0 {
		return true, "decommissioned"
	}
	return false, fmt.Sprintf("worker pod %s runs sandboxes (%d) and is not decommissioned; deleting it ends them all. "+
		"Decommission it (kubectl annotate aerolnode %s %s=true -n %s) or, to delete it anyway, "+
		"kubectl annotate pod %s %s=true -n %s",
		pod.Name, n.Status.Sandboxes, name, v1.AnnotationDecommission, g.Namespace, pod.Name, v1.AnnotationForceDelete, pod.Namespace)
}

var _ admission.Handler = (*PodGuard)(nil)

// Path is where the chart's ValidatingWebhookConfiguration points.
const Path = "/validate-worker-pod-delete"

package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
)

const ns = "aerolvm-system"

func workerPod(name string, phase corev1.PodPhase, ann map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "aerolvm-workers", Annotations: ann, Labels: map[string]string{
			"app.kubernetes.io/name": "aerolvm", "app.kubernetes.io/component": "worker", "aerolvm.io/node": name}},
		Status: corev1.PodStatus{Phase: phase},
	}
}

func aerolNode(name, state string, deleting bool) *v1.AerolNode {
	n := &v1.AerolNode{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Status: v1.AerolNodeStatus{State: state, Sandboxes: 7}}
	if deleting {
		now := metav1.Now()
		n.DeletionTimestamp = &now
		n.Finalizers = []string{"test/hold"}
	}
	return n
}

func request(t *testing.T, op admissionv1.Operation, pod *corev1.Pod, user string) admission.Request {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: op, OldObject: runtime.RawExtension{Raw: raw}, UserInfo: authv1.UserInfo{Username: user}}}
}

func TestPodGuard(t *testing.T) {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(v1.AddToScheme(s))
	objs := []client.Object{
		aerolNode("w-live", v1.StateServing, false),
		aerolNode("w-draining", v1.StateDraining, false),
		aerolNode("w-gc", v1.StateServing, true),
		aerolNode("w-removed", v1.StateRemoved, false),
		aerolNode("w-dead", v1.StateDead, false),
		aerolNode("w-failed", v1.StateFailed, false),
	}
	moving := aerolNode("w-moving", v1.StateDecommissioning, false)
	moving.Annotations = map[string]string{v1.AnnotationDecommission: "true"}
	moving.Status.Decommission = &v1.DecommissionStatus{Moved: 8, Remaining: 100}
	done := aerolNode("w-done", v1.StateDecommissioning, false)
	done.Annotations = map[string]string{v1.AnnotationDecommission: "true"}
	done.Status.Decommission = &v1.DecommissionStatus{Moved: 3}
	objs = append(objs, moving, done)
	g := &PodGuard{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build(),
		OperatorUser: "system:serviceaccount:aerolvm-system:aerolvm-operator", Namespace: ns}
	cases := []struct {
		name  string
		op    admissionv1.Operation
		pod   *corev1.Pod
		user  string
		allow bool
	}{
		{"a live worker by a person: refused", admissionv1.Delete, workerPod("w-live", corev1.PodRunning, nil), "alice", false},
		{"the operator", admissionv1.Delete, workerPod("w-live", corev1.PodRunning, nil), "system:serviceaccount:aerolvm-system:aerolvm-operator", true},
		{"forced, and recorded", admissionv1.Delete, workerPod("w-live", corev1.PodRunning, map[string]string{v1.AnnotationForceDelete: "true"}), "alice", true},
		{"not running", admissionv1.Delete, workerPod("w-live", corev1.PodPending, nil), "alice", true},
		// Decommissioning means the sandboxes are still moving: a plain
		// delete would end the ones left (R12).
		{"its node is decommissioning, sandboxes left: refused", admissionv1.Delete, workerPod("w-moving", corev1.PodRunning, nil), "alice", false},
		{"its node is draining: refused", admissionv1.Delete, workerPod("w-draining", corev1.PodRunning, nil), "alice", false},
		{"decommissioning, by the operator", admissionv1.Delete, workerPod("w-moving", corev1.PodRunning, nil), "system:serviceaccount:aerolvm-system:aerolvm-operator", true},
		{"decommissioning, forced", admissionv1.Delete, workerPod("w-moving", corev1.PodRunning, map[string]string{v1.AnnotationForceDelete: "true"}), "alice", true},
		{"decommissioned: every sandbox moved", admissionv1.Delete, workerPod("w-done", corev1.PodRunning, nil), "alice", true},
		{"its node is removed", admissionv1.Delete, workerPod("w-removed", corev1.PodRunning, nil), "alice", true},
		{"its node is dead", admissionv1.Delete, workerPod("w-dead", corev1.PodRunning, nil), "alice", true},
		{"its node failed", admissionv1.Delete, workerPod("w-failed", corev1.PodRunning, nil), "alice", true},
		{"the garbage collector, its AerolNode going", admissionv1.Delete, workerPod("w-gc", corev1.PodRunning, nil), gcUser, true},
		{"no AerolNode", admissionv1.Delete, workerPod("w-none", corev1.PodRunning, nil), "alice", true},
		{"not a worker pod", admissionv1.Delete, func() *corev1.Pod {
			p := workerPod("x", corev1.PodRunning, nil)
			p.Labels["app.kubernetes.io/component"] = "server"
			return p
		}(), "alice", true},
		{"not a delete", admissionv1.Update, workerPod("w-live", corev1.PodRunning, nil), "alice", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := g.Handle(context.Background(), request(t, tc.op, tc.pod, tc.user))
			if resp.Allowed != tc.allow {
				t.Fatalf("allowed = %v (%s), want %v", resp.Allowed, resp.Result.Message, tc.allow)
			}
			if !tc.allow && resp.Result.Message == "" {
				t.Fatal("a refusal must say what to do instead")
			}
		})
	}
	bad := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Delete, OldObject: runtime.RawExtension{Raw: []byte("{")}}}
	if !g.Handle(context.Background(), bad).Allowed {
		t.Fatal("an unreadable pod must fail open")
	}
}

// A plain delete while a decommission is still moving sandboxes is refused,
// and the refusal says how far the move got and how to force it (R12).
func TestPodGuardRefusesDeleteDuringEvacuation(t *testing.T) {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(v1.AddToScheme(s))
	n := aerolNode("worker-mid-move", v1.StateDecommissioning, false)
	n.Status.Sandboxes = 100
	n.Status.Decommission = &v1.DecommissionStatus{Moved: 8, Remaining: 100}
	g := &PodGuard{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(n).Build(), Namespace: ns,
		OperatorUser: "system:serviceaccount:aerolvm-system:aerolvm-operator"}
	resp := g.Handle(context.Background(), request(t, admissionv1.Delete, workerPod(n.Name, corev1.PodRunning, nil), "alice"))
	if resp.Allowed {
		t.Fatalf("plain delete accepted with 100 sandboxes still on a decommissioning worker: %s", resp.Result.Message)
	}
	for _, want := range []string{"8 moved, 100 left", v1.AnnotationForceDelete} {
		if !strings.Contains(resp.Result.Message, want) {
			t.Errorf("refusal %q does not say %q", resp.Result.Message, want)
		}
	}
}

// evictionRequest is what the API server sends for an eviction: a CREATE on
// pods/eviction carrying an Eviction, never the pod itself.
func evictionRequest(t *testing.T, namespace, name, user string, named bool) admission.Request {
	t.Helper()
	raw, err := json.Marshal(&policyv1.Eviction{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}})
	if err != nil {
		t.Fatal(err)
	}
	req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Create, SubResource: "eviction",
		Kind:     metav1.GroupVersionKind{Group: "policy", Version: "v1", Kind: "Eviction"},
		Resource: metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
		Object:   runtime.RawExtension{Raw: raw}, UserInfo: authv1.UserInfo{Username: user}}}
	if named {
		req.Name, req.Namespace = name, namespace
	}
	return req
}

// An eviction (kubectl drain, a node group update, Karpenter) never reaches
// a DELETE rule, and the API server deletes the pod itself once no
// PodDisruptionBudget holds it. So evictions get the delete rules, and a
// refusal is a 429, the answer a PodDisruptionBudget gives, which drain and
// node group updates wait on and retry (R13).
func TestPodGuardEviction(t *testing.T) {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(v1.AddToScheme(s))
	moving := aerolNode("w-moving", v1.StateDecommissioning, false)
	moving.Annotations = map[string]string{v1.AnnotationDecommission: "true"}
	moving.Status.Decommission = &v1.DecommissionStatus{Moved: 8, Remaining: 100}
	done := aerolNode("w-done", v1.StateDecommissioning, false)
	done.Annotations = map[string]string{v1.AnnotationDecommission: "true"}
	done.Status.Decommission = &v1.DecommissionStatus{Moved: 3}
	server := workerPod("s-0", corev1.PodRunning, nil)
	server.Labels["app.kubernetes.io/component"] = "server"
	objs := []client.Object{
		aerolNode("w-live", v1.StateServing, false), moving, done,
		aerolNode("w-removed", v1.StateRemoved, false),
		workerPod("w-live", corev1.PodRunning, nil),
		workerPod("w-moving", corev1.PodRunning, nil),
		workerPod("w-done", corev1.PodRunning, nil),
		workerPod("w-removed", corev1.PodRunning, nil),
		workerPod("w-new", corev1.PodPending, nil),
		server,
	}
	forced := workerPod("w-forced", corev1.PodRunning, map[string]string{v1.AnnotationForceDelete: "true"})
	objs = append(objs, aerolNode("w-forced", v1.StateServing, false), forced)
	g := &PodGuard{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build(),
		OperatorUser: "system:serviceaccount:aerolvm-system:aerolvm-operator", Namespace: ns}
	const workers = "aerolvm-workers"
	cases := []struct {
		name, pod, user string
		named, allow    bool
	}{
		{"a live worker, kubectl drain: refused", "w-live", "alice", true, false},
		{"a managed node group update: refused", "w-live", "eks:node-manager", true, false},
		{"its sandboxes still moving: refused", "w-moving", "system:serviceaccount:karpenter:karpenter", true, false},
		{"the pod named only in the Eviction: refused", "w-live", "alice", false, false},
		{"every sandbox moved", "w-done", "alice", true, true},
		{"its node is removed", "w-removed", "alice", true, true},
		{"forced", "w-forced", "alice", true, true},
		{"not running yet", "w-new", "alice", true, true},
		{"not a worker pod", "s-0", "alice", true, true},
		{"no such pod", "w-gone", "alice", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := g.Handle(context.Background(), evictionRequest(t, workers, tc.pod, tc.user, tc.named))
			if resp.Allowed != tc.allow {
				t.Fatalf("allowed = %v (%s), want %v", resp.Allowed, resp.Result.Message, tc.allow)
			}
			if tc.allow {
				return
			}
			if resp.Result.Code != http.StatusTooManyRequests || resp.Result.Reason != metav1.StatusReasonTooManyRequests {
				t.Fatalf("refusal is %d %s, want 429 TooManyRequests so evictions retry", resp.Result.Code, resp.Result.Reason)
			}
			if !strings.Contains(resp.Result.Message, v1.AnnotationForceDelete) {
				t.Fatalf("a refusal must say what to do instead: %q", resp.Result.Message)
			}
		})
	}
	// A delete refusal stays a 403: only evictions are retried.
	if resp := g.Handle(context.Background(), request(t, admissionv1.Delete, workerPod("w-live", corev1.PodRunning, nil), "alice")); resp.Result.Code != http.StatusForbidden {
		t.Fatalf("a refused delete answered %d, want 403", resp.Result.Code)
	}
	// Creating a pod, or any other subresource, is not guarded.
	other := evictionRequest(t, workers, "w-live", "alice", true)
	other.SubResource = "binding"
	if !g.Handle(context.Background(), other).Allowed {
		t.Fatal("a CREATE that is not an eviction must pass")
	}
	bad := evictionRequest(t, workers, "w-live", "alice", false)
	bad.Object.Raw = []byte("{")
	if !g.Handle(context.Background(), bad).Allowed {
		t.Fatal("an unreadable eviction must fail open")
	}
}

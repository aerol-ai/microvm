package webhook

import (
	"context"
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
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
		aerolNode("w-decom", v1.StateDecommissioning, false),
		aerolNode("w-gc", v1.StateServing, true),
	}
	done := aerolNode("w-done", v1.StateServing, false)
	done.Annotations = map[string]string{v1.AnnotationDecommission: "true"}
	done.Status.Decommission = &v1.DecommissionStatus{Moved: 3}
	objs = append(objs, done)
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
		{"its node is decommissioning", admissionv1.Delete, workerPod("w-decom", corev1.PodRunning, nil), "alice", true},
		{"decommissioned", admissionv1.Delete, workerPod("w-done", corev1.PodRunning, nil), "alice", true},
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

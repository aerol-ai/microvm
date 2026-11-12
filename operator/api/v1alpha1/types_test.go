package v1alpha1

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// The generated deep copies are real copies: a change to the copy never
// reaches the original (controllers mutate what they read from the cache).
func TestDeepCopies(t *testing.T) {
	d := metav1.Duration{}
	class := "gp3"
	c := &AerolCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "prod"},
		Spec: AerolClusterSpec{
			Version: "v1.0.0", Zones: []string{"a"},
			Servers:     ServerSpec{Count: 3, NodeSelector: map[string]string{"k": "v"}, Storage: StorageSpec{StorageClassName: &class}},
			Gateways:    GatewaySpec{MinReplicas: 1, GatewayRef: &GatewayRef{Name: "g"}, Service: GatewayServiceSpec{Annotations: map[string]string{"a": "b"}}},
			WorkerPools: []WorkerPoolSpec{{Name: "p", Runtimes: []string{"gvisor"}, Images: []string{"x"}, Decommission: DecommissionSpec{DrainWindow: &d, Deadline: &d}}},
			Edge:        EdgeSpec{IssuerRef: &IssuerRef{Kind: "ClusterIssuer", Name: "i"}},
			Security:    SecuritySpec{ExternalCA: &ExternalCASpec{}},
		},
		Status: AerolClusterStatus{Rollout: &RolloutStatus{ID: "r"}, Conditions: []metav1.Condition{{Type: "Ready"}}},
	}
	cp := c.DeepCopy()
	if !reflect.DeepEqual(c, cp) {
		t.Fatal("copy differs")
	}
	cp.Spec.Zones[0] = "changed"
	cp.Spec.WorkerPools[0].Runtimes[0] = "changed"
	*cp.Spec.Servers.Storage.StorageClassName = "changed"
	if c.Spec.Zones[0] != "a" || c.Spec.WorkerPools[0].Runtimes[0] != "gvisor" || class != "gp3" {
		t.Fatal("the copy shares memory with the original")
	}
	n := &AerolNode{Status: AerolNodeStatus{Decommission: &DecommissionStatus{Moved: 1}, Conditions: []metav1.Condition{{Type: "X"}}}}
	if !reflect.DeepEqual(n, n.DeepCopy()) {
		t.Fatal("node copy differs")
	}
	for _, o := range []runtime.Object{c, n, &AerolClusterList{Items: []AerolCluster{*c}}, &AerolNodeList{Items: []AerolNode{*n}}} {
		if !reflect.DeepEqual(o, o.DeepCopyObject()) {
			t.Fatalf("%T DeepCopyObject differs", o)
		}
	}
	var nilC *AerolCluster
	if nilC.DeepCopy() != nil {
		t.Fatal("nil copy")
	}
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil || !s.Recognizes(GroupVersion.WithKind("AerolNode")) {
		t.Fatalf("scheme = %v", err)
	}
}

package controller

import (
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
)

// The chart's pod templates, rendered by Helm, parse strictly and stamp for
// every role: the chart and the operator agree on container and volume
// names. CI renders the chart in cluster mode and points
// AEROLVM_POD_TEMPLATES at the ConfigMap; without it the test skips.
func TestRenderedChartTemplates(t *testing.T) {
	path := os.Getenv("AEROLVM_POD_TEMPLATES")
	if path == "" {
		t.Skip("AEROLVM_POD_TEMPLATES not set: no rendered chart to check")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cm corev1.ConfigMap
	if err := yaml.Unmarshal(raw, &cm); err != nil {
		t.Fatal(err)
	}
	c := testCluster()
	for _, role := range []string{TemplateServer, TemplateGateway, TemplateWorker} {
		tm, err := ParsePodTemplate(cm.Data[role])
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		in := StampInput{Cluster: c, Node: node("prod-"+role+"-0", role, "general", "z-a"), Namespace: testNS, Version: "v0.7.2", PVC: "data-x"}
		if role == TemplateWorker {
			in.Pool = &c.Spec.WorkerPools[0]
		}
		pod, err := Stamp(tm, in)
		if err != nil {
			t.Fatalf("%s stamp: %v", role, err)
		}
		if i := containerIndex(pod.Spec.Containers, AgentContainer); i < 0 || pod.Spec.Containers[i].Image != "registry.example/aerol/aerolvm:v0.7.2" {
			t.Fatalf("%s: agent image not stamped", role)
		}
		if role == v1.RoleWorker {
			if containerIndex(pod.Spec.Containers, RuntimeContainer) < 0 || pod.Spec.PriorityClassName == "" {
				t.Fatalf("worker template lacks the runtime container or its priority class")
			}
		}
	}
}

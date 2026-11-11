package controller

import (
	"os"
	"strings"
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
			// sandboxd writes its ownership lease where the runtime's
			// supervisor reads it: without both, nothing freezes a sandbox
			// whose lease ran out with sandboxd down, and a gone machine
			// never fails over early (C7, C19).
			agentLease := envValue(pod.Spec.Containers[containerIndex(pod.Spec.Containers, AgentContainer)].Env, "SB_OWNERSHIP_LEASE_FILE")
			runtimeLease := envValue(pod.Spec.Containers[containerIndex(pod.Spec.Containers, RuntimeContainer)].Env, "SB_OWNERSHIP_LEASE_FILE")
			if agentLease == "" || agentLease != runtimeLease || !strings.HasPrefix(agentLease, "/run/aerolvm/") {
				t.Fatalf("ownership lease file: agent %q, runtime %q", agentLease, runtimeLease)
			}
			// The machine is checked before setup spends the join token
			// (P10), and the check's image is stamped with the version.
			ic := pod.Spec.InitContainers
			if len(ic) != 2 || ic[0].Name != PreflightContainer || ic[1].Name != SetupContainer ||
				ic[0].Image != "registry.example/aerol/aerolvm:v0.7.2" || ic[0].TerminationMessagePolicy != corev1.TerminationMessageFallbackToLogsOnError {
				t.Fatalf("worker init containers = %+v", ic)
			}
			// Setup writes files: no privilege, no capability, none of the
			// sandbox machinery the privileged agent mounts.
			sc := ic[1].SecurityContext
			if sc == nil || sc.Privileged == nil || *sc.Privileged || sc.Capabilities == nil || len(sc.Capabilities.Drop) != 1 ||
				sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
				t.Fatalf("worker setup security = %+v", sc)
			}
			for _, m := range ic[1].VolumeMounts {
				if m.Name != EtcVolume && m.Name != StateVolume && m.Name != JoinVolume {
					t.Fatalf("worker setup mounts %s (%s)", m.Name, m.MountPath)
				}
			}
		}
	}
}

// envValue is name's value in env (the last, as Kubernetes reads it).
func envValue(env []corev1.EnvVar, name string) string {
	v := ""
	for _, e := range env {
		if e.Name == name {
			v = e.Value
		}
	}
	return v
}

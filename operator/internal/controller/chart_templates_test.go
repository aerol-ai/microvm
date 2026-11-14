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
		in := StampInput{JoinURL: testJoinURL, JoinCA: testJoinCA, Cluster: c, Node: node("prod-"+role+"-0", role, "general", "z-a"), Namespace: testNS, Version: "v0.7.2", PVC: "data-x"}
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
				if m.Name != EtcVolume && m.Name != StateVolume && m.Name != JoinIdentityVolume {
					t.Fatalf("worker setup mounts %s (%s)", m.Name, m.MountPath)
				}
			}
		}
	}
}

// renderedWorker is the worker pod template from a pod-templates ConfigMap
// the chart rendered (scripts/chart-pod-templates.sh), named by env. CI
// renders it; without env set the test skips.
func renderedWorker(t *testing.T, env string) corev1.PodTemplateSpec {
	t.Helper()
	path := os.Getenv(env)
	if path == "" {
		t.Skip(env + " not set: no rendered chart to check")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cm corev1.ConfigMap
	if err := yaml.Unmarshal(raw, &cm); err != nil {
		t.Fatal(err)
	}
	pod, err := ParsePodTemplate(cm.Data[TemplateWorker])
	if err != nil {
		t.Fatal(err)
	}
	if containerIndex(pod.Spec.Containers, AgentContainer) < 0 || containerIndex(pod.Spec.Containers, RuntimeContainer) < 0 {
		t.Fatal("worker template lacks the agent or the runtime container")
	}
	return pod
}

// With worker.externalStorage.enabled, the rendered worker pod gives
// external storage what it needs (finding F13). The agent's mount helpers
// mount below SB_MOUNTS_ROOT, and runsc, in the runtime container, binds
// that folder into the sandbox. Without two-way propagation on both sides
// the runtime sees the empty folder under each mount: the create succeeded
// and the sandbox wrote to local disk. Kept from the 2026-11-14
// verification review (TestReviewRenderedExternalMountPropagation). That
// test checked the whole state folder, /var/lib/sandboxd; this one checks
// the volume that holds SB_MOUNTS_ROOT, wherever it is: the mounts folder
// has an emptyDir of its own, so only it propagates, and the state volume
// (the database, toolbox, jail roots) keeps no two-way propagation. CI
// renders the chart with the value on into
// AEROLVM_POD_TEMPLATES_EXTERNAL_STORAGE.
func TestRenderedExternalMountsPropagate(t *testing.T) {
	pod := renderedWorker(t, "AEROLVM_POD_TEMPLATES_EXTERNAL_STORAGE")
	agent := containerIndex(pod.Spec.Containers, AgentContainer)
	runtime := containerIndex(pod.Spec.Containers, RuntimeContainer)
	root := envValue(pod.Spec.Containers[agent].Env, "SB_MOUNTS_ROOT")
	if root == "" {
		t.Fatal("the agent has no SB_MOUNTS_ROOT")
	}
	// The mount a path is under: the deepest one whose path holds it.
	holding := func(c corev1.Container) (corev1.VolumeMount, bool) {
		var best corev1.VolumeMount
		found := false
		for _, m := range c.VolumeMounts {
			p := strings.TrimSuffix(m.MountPath, "/")
			if (root == p || strings.HasPrefix(root, p+"/")) && len(p) >= len(strings.TrimSuffix(best.MountPath, "/")) {
				best, found = m, true
			}
		}
		return best, found
	}
	am, aok := holding(pod.Spec.Containers[agent])
	rm, rok := holding(pod.Spec.Containers[runtime])
	if !aok || !rok || am.Name != rm.Name {
		t.Fatalf("SB_MOUNTS_ROOT %s is on volume %q in the agent and %q in the runtime: they must share one", root, am.Name, rm.Name)
	}
	if propagation(am) != corev1.MountPropagationBidirectional || propagation(rm) == corev1.MountPropagationNone {
		t.Fatalf("external mounts below %s (volume %s) propagate agent=%q runtime=%q; the agent needs Bidirectional and the runtime more than None",
			root, am.Name, propagation(am), propagation(rm))
	}
	// The visible-check and the pod-end unmount are wired on both sides.
	if envValue(pod.Spec.Containers[agent].Env, "SB_MOUNTS_RUNTIME_PID_FILE") == "" ||
		envValue(pod.Spec.Containers[agent].Env, "SB_MOUNTS_RUNTIME_PID_FILE") != envValue(pod.Spec.Containers[runtime].Env, "SB_RUNTIME_PID_FILE") {
		t.Fatalf("the agent checks mounts through %q, the runtime writes its pid to %q",
			envValue(pod.Spec.Containers[agent].Env, "SB_MOUNTS_RUNTIME_PID_FILE"), envValue(pod.Spec.Containers[runtime].Env, "SB_RUNTIME_PID_FILE"))
	}
	// The helpers outlive an agent restart, and that pid means anything,
	// only in one process namespace for the pod.
	if pod.Spec.ShareProcessNamespace == nil || !*pod.Spec.ShareProcessNamespace {
		t.Fatal("the worker pod does not share one process namespace: an agent restart would end every mount helper")
	}
	if envValue(pod.Spec.Containers[runtime].Env, "SB_MOUNTS_DIR") != root {
		t.Fatalf("the runtime unmounts %q when the pod ends, the agent mounts below %q",
			envValue(pod.Spec.Containers[runtime].Env, "SB_MOUNTS_DIR"), root)
	}
}

// By default the chart keeps external storage off, and the worker pod's
// process namespace unshared: shared, every container in the pod, the
// internet-facing edge among them, could read every process's command
// line. Off means no runtime pid file for the agent, so sandboxd refuses
// every mount (501 mounts_unavailable) rather than serving it from the
// worker's own disk, and no mounts volume. AEROLVM_POD_TEMPLATES is the
// default render (no WASM, V8 or Firecracker, which share it for their
// own reasons).
func TestRenderedExternalStorageOffByDefault(t *testing.T) {
	pod := renderedWorker(t, "AEROLVM_POD_TEMPLATES")
	if pod.Spec.ShareProcessNamespace != nil && *pod.Spec.ShareProcessNamespace {
		t.Fatal("the default worker pod shares one process namespace: the edge container could read every process's command line")
	}
	for _, c := range pod.Spec.Containers {
		for _, name := range []string{"SB_MOUNTS_RUNTIME_PID_FILE", "SB_RUNTIME_PID_FILE", "SB_MOUNTS_DIR"} {
			if v := envValue(c.Env, name); v != "" {
				t.Fatalf("container %s sets %s=%s with external storage off", c.Name, name, v)
			}
		}
		for _, m := range c.VolumeMounts {
			if m.Name == "mounts" {
				t.Fatalf("container %s mounts the external-storage volume with it off", c.Name)
			}
		}
	}
}

func propagation(m corev1.VolumeMount) corev1.MountPropagationMode {
	if m.MountPropagation == nil {
		return corev1.MountPropagationNone
	}
	return *m.MountPropagation
}

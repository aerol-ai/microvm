package controller

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
)

func mustTemplate(t *testing.T, role string) corev1.PodTemplateSpec {
	t.Helper()
	tm, err := ParsePodTemplate(templates(t).Data[role])
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func env(c corev1.Container, name string) string {
	for _, e := range c.Env {
		if e.Name == name {
			return e.Value
		}
	}
	return "<unset>"
}

func node(name, role, pool, zone string) *v1.AerolNode {
	return &v1.AerolNode{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNS},
		Spec: v1.AerolNodeSpec{Cluster: "prod", Role: role, Pool: pool, Zone: zone}}
}

func TestParsePodTemplate(t *testing.T) {
	if _, err := ParsePodTemplate(" "); err == nil {
		t.Fatal("empty template accepted")
	}
	if _, err := ParsePodTemplate("spec: {containers: [{name: x}]}"); err == nil || !strings.Contains(err.Error(), "agent") {
		t.Fatalf("no agent = %v", err)
	}
	if _, err := ParsePodTemplate("spec: {nope: 1}"); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestStampServer(t *testing.T) {
	c := testCluster()
	n := node("prod-server-0", v1.RoleServer, "", "z-a")
	pod, err := Stamp(mustTemplate(t, TemplateServer), StampInput{Cluster: c, Node: n, Namespace: testNS, Version: "v0.7.2", Bootstrap: true, PVC: "data-prod-server-0"})
	if err != nil {
		t.Fatal(err)
	}
	agent := pod.Spec.Containers[0]
	if agent.Image != "registry.example/aerol/aerolvm:v0.7.2" {
		t.Fatalf("image %s", agent.Image)
	}
	for k, want := range map[string]string{"SB_NODE_ID": "prod-server-0", "SB_NODE_ROLE": "server", "SB_NODE_ZONE": "z-a", "SB_CELL_ID": "3", "SB_UPGRADE_DRIVER": "operator", "SB_API_PORT": "21212"} {
		if got := env(agent, k); got != want {
			t.Fatalf("%s = %q, want %q", k, got, want)
		}
	}
	// Gossip advertises the pod IP (memberlist needs an IP), set by the
	// kubelet before the value that refers to it; Raft keeps the DNS name.
	if env(agent, "SB_GOSSIP_ADVERTISE_ADDR") != "$(POD_IP):7001" || envIndex(agent, "POD_IP") < 0 ||
		envIndex(agent, "POD_IP") > envIndex(agent, "SB_GOSSIP_ADVERTISE_ADDR") {
		t.Fatalf("server gossip address env = %v", agent.Env)
	}
	if pod.Spec.Hostname != "prod-server-0" || pod.Spec.Subdomain != "prod-servers" {
		t.Fatalf("dns name %s.%s", pod.Spec.Hostname, pod.Spec.Subdomain)
	}
	setup := pod.Spec.InitContainers[0]
	if setup.Name != SetupContainer || !strings.Contains(setup.Command[2], "sandboxd init --files-only --role server --node-id prod-server-0 --advertise \"prod-server-0.prod-servers.aerolvm-system.svc\"") {
		t.Fatalf("setup = %v", setup.Command)
	}
	podIPs := 0
	for _, e := range setup.Env {
		if e.Name == "POD_IP" {
			podIPs++
		}
	}
	if envIndex(setup, "POD_IP") != 0 || podIPs != 1 {
		t.Fatalf("setup env: POD_IP once and first: %v", setup.Env)
	}
	for _, v := range pod.Spec.Volumes {
		if (v.Name == StateVolume || v.Name == EtcVolume) && (v.PersistentVolumeClaim == nil || v.PersistentVolumeClaim.ClaimName != "data-prod-server-0") {
			t.Fatalf("volume %s not on the claim: %+v", v.Name, v.VolumeSource)
		}
	}
	for _, m := range setup.VolumeMounts {
		if m.Name == EtcVolume && m.SubPath != "etc" {
			t.Fatalf("etc subPath %q", m.SubPath)
		}
	}
	terms := pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	if len(terms) != 1 || terms[0].MatchExpressions[0].Values[0] != "z-a" {
		t.Fatalf("zone pin = %+v", terms)
	}

	// A server that joins: the token's Secret, read-only.
	joiner, err := Stamp(mustTemplate(t, TemplateServer), StampInput{Cluster: c, Node: node("prod-server-1", v1.RoleServer, "", "z-b"), Namespace: testNS, Version: "v0.7.2", PVC: "data-prod-server-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(joiner.Spec.InitContainers[0].Command[2], "sandboxd join") || joiner.Spec.Volumes[len(joiner.Spec.Volumes)-1].Secret.SecretName != "prod-server-1-join" {
		t.Fatalf("joiner setup = %v", joiner.Spec.InitContainers[0].Command)
	}
	// By key, the three a join needs (aerolvm k8s verify checks Secret
	// volumes name their keys).
	if items := joiner.Spec.Volumes[len(joiner.Spec.Volumes)-1].Secret.Items; len(items) != 3 || items[0].Key != "join_url" || items[1].Key != "token" || items[2].Key != "ca_cert_hash" {
		t.Fatalf("join volume items = %+v", items)
	}

	// Maintenance: the volume, a holding process, no setup (C22).
	held, err := Stamp(mustTemplate(t, TemplateServer), StampInput{Cluster: c, Node: n, Namespace: testNS, Version: "v0.7.2", Maintenance: true, PVC: "data-prod-server-0"})
	if err != nil || len(held.Spec.InitContainers) != 0 || !strings.Contains(strings.Join(held.Spec.Containers[0].Command, " "), "sleep") || held.Labels[v1.AnnotationMaintenance] != "true" {
		t.Fatalf("maintenance pod = %+v %v", held.Spec, err)
	}

	if _, err := Stamp(mustTemplate(t, TemplateServer), StampInput{Cluster: c, Node: n, Namespace: testNS}); err == nil {
		t.Fatal("server without a claim accepted")
	}
}

func TestStampWorkerAndGateway(t *testing.T) {
	c := testCluster()
	pool := &c.Spec.WorkerPools[0]
	pod, err := Stamp(mustTemplate(t, TemplateWorker), StampInput{Cluster: c, Node: node("prod-general-abcde", v1.RoleWorker, "general", "z-c"), Namespace: testWorkerNS, Version: "v0.7.2", Pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	if pod.Namespace != testWorkerNS || pod.Labels[LabelPool] != "general" || pod.Labels[LabelZone] != "z-c" || pod.Annotations["karpenter.sh/do-not-disrupt"] != "true" {
		t.Fatalf("worker meta = %+v", pod.ObjectMeta)
	}
	if pod.Spec.NodeSelector["aerolvm.io/pool"] != "general" {
		t.Fatalf("selector = %v", pod.Spec.NodeSelector)
	}
	rt := pod.Spec.Containers[0]
	if rt.Image != "registry.example/aerol/aerolvm-runtime:v0.7.2" || pod.Spec.Containers[2].Image != "registry.example/aerol/aerolvm-edge:v0.7.2" {
		t.Fatalf("images %s %s", rt.Image, pod.Spec.Containers[2].Image)
	}
	// 30.5 CPU and 116.7 GiB for the pod, less the agent's 1 CPU / 1 GiB
	// and the edge's 0.5 CPU / 512 MiB.
	if cpu := rt.Resources.Requests[corev1.ResourceCPU]; cpu.String() != "29" {
		t.Fatalf("runtime cpu %s", cpu.String())
	}
	if !rt.Resources.Requests.Memory().Equal(*rt.Resources.Limits.Memory()) {
		t.Fatal("request is not the limit (not Guaranteed)")
	}
	if env(pod.Spec.Containers[1], "SB_NODE_ROLE") != "worker" || env(pod.Spec.Containers[1], "SB_NODE_LABELS") != "aerolvm.io/pool=general" {
		t.Fatalf("worker env %v", pod.Spec.Containers[1].Env)
	}
	// The fake template's agent is unprivileged; setup is held to no rights
	// whatever the agent has.
	if sc := pod.Spec.InitContainers[0].SecurityContext; sc == nil || *sc.Privileged || *sc.AllowPrivilegeEscalation || !*sc.ReadOnlyRootFilesystem ||
		sc.Capabilities.Drop[0] != "ALL" {
		t.Fatalf("worker setup security = %+v", sc)
	}
	if !strings.Contains(pod.Spec.InitContainers[0].Command[2], `--advertise "$(POD_IP)"`) {
		t.Fatalf("worker advertise: %v", pod.Spec.InitContainers[0].Command)
	}
	if _, err := Stamp(mustTemplate(t, TemplateWorker), StampInput{Cluster: c, Node: node("w", v1.RoleWorker, "general", "z-a"), Namespace: testWorkerNS}); err == nil {
		t.Fatal("worker without a pool accepted")
	}
	tiny := *pool
	tiny.Machine = v1.MachineSpec{CPU: 2, MemoryGiB: 2}
	if _, err := Stamp(mustTemplate(t, TemplateWorker), StampInput{Cluster: c, Node: node("w", v1.RoleWorker, "general", "z-a"), Namespace: testWorkerNS, Pool: &tiny}); err == nil {
		t.Fatal("a machine too small for the pod accepted")
	}

	gw, err := Stamp(mustTemplate(t, TemplateGateway), StampInput{Cluster: c, Node: node("prod-gateway-x", v1.RoleGateway, "", "z-b"), Namespace: testNS, Version: "v0.7.2"})
	if err != nil || env(gw.Spec.Containers[0], "SB_NODE_ROLE") != "ingress" {
		t.Fatalf("gateway = %v %v", gw, err)
	}
	if _, err := Stamp(mustTemplate(t, TemplateGateway), StampInput{Cluster: c, Node: node("x", "nope", "", "z-a"), Namespace: testNS}); err == nil {
		t.Fatal("unknown role accepted")
	}
}

func TestWorkerPodSize(t *testing.T) {
	cpu, mem := workerPodSize(v1.MachineSpec{CPU: 32, MemoryGiB: 128})
	if cpu.String() != "30500m" {
		t.Fatalf("cpu %s", cpu.String())
	}
	gib := float64(mem.Value()) / (1 << 30)
	if gib < 116 || gib > 117.5 {
		t.Fatalf("memory %.2f GiB", gib)
	}
	cpu, mem = workerPodSize(v1.MachineSpec{CPU: 0, MemoryGiB: 0})
	if cpu.Sign() != 0 || mem.Sign() != 0 {
		t.Fatal("negative size")
	}
}

func TestImageHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"ghcr.io/aerol-ai/aerolvm:v1":       "aerolvm",
		"aerolvm-runtime":                   "aerolvm-runtime",
		"r.example:5000/x/aerolvm-edge@sha": "aerolvm-edge",
		"busybox:1.36":                      "busybox",
	} {
		if got := imageName(in); got != want {
			t.Fatalf("imageName(%s) = %s", in, got)
		}
	}
	if ReleaseImage("", "aerolvm", "v1") != "ghcr.io/aerol-ai/aerolvm:v1" {
		t.Fatal("default registry")
	}
	c := corev1.Container{Image: "busybox:1"}
	setReleaseImage(&c, "r", "v2")
	if c.Image != "busybox:1" {
		t.Fatal("a non-release image was retagged")
	}
	setReleaseImage(&c, "r", "")
	// A template's existing affinity term gains the zone, not a new term.
	spec := corev1.PodSpec{Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{
			{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "arch", Operator: corev1.NodeSelectorOpIn, Values: []string{"arm64"}}}}}}}}}
	pinZone(&spec, "z-a")
	pinZone(&spec, "")
	if got := spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms; len(got) != 1 || len(got[0].MatchExpressions) != 2 {
		t.Fatalf("terms = %+v", got)
	}
	setResources(&spec, "none", corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")}})
}

// A pool's runtimes become the worker's own: it advertises only them, and a
// default runtime outside the list becomes the pool's first.
func TestStampWorkerPoolRuntimes(t *testing.T) {
	c := testCluster()
	cases := []struct {
		name, templateDefault string
		runtimes              []string
		wantHost, wantDefault string
	}{
		{name: "gVisor only: runc is not advertised and not the default", runtimes: []string{"gvisor"}, wantHost: "gvisor", wantDefault: "gvisor"},
		{name: "runc is sandboxd's docker", runtimes: []string{"runc", "gvisor", "runc"}, wantHost: "docker,gvisor", wantDefault: "<unset>"},
		{name: "a default in the list stays", templateDefault: "gvisor", runtimes: []string{"runc", "gvisor"}, wantHost: "docker,gvisor", wantDefault: "gvisor"},
		{name: "a default outside the list is replaced", templateDefault: "docker", runtimes: []string{"gvisor"}, wantHost: "gvisor", wantDefault: "gvisor"},
		{name: "no list: the template's settings stand", templateDefault: "gvisor", wantHost: "docker,gvisor", wantDefault: "gvisor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mustTemplate(t, TemplateWorker)
			agent := &tpl.Spec.Containers[containerIndex(tpl.Spec.Containers, AgentContainer)]
			agent.Env = append(agent.Env, corev1.EnvVar{Name: "SB_HOST_RUNTIMES", Value: "docker,gvisor"})
			if tc.templateDefault != "" {
				agent.Env = append(agent.Env, corev1.EnvVar{Name: "SB_CONTAINER_RUNTIME", Value: tc.templateDefault})
			}
			pool := c.Spec.WorkerPools[0]
			pool.Runtimes = tc.runtimes
			pod, err := Stamp(tpl, StampInput{Cluster: c, Node: node("w", v1.RoleWorker, "general", "z-a"), Namespace: testWorkerNS, Version: "v0.7.2", Pool: &pool})
			if err != nil {
				t.Fatal(err)
			}
			a := pod.Spec.Containers[containerIndex(pod.Spec.Containers, AgentContainer)]
			if got := env(a, "SB_HOST_RUNTIMES"); got != tc.wantHost {
				t.Fatalf("SB_HOST_RUNTIMES = %q, want %q", got, tc.wantHost)
			}
			if got := env(a, "SB_CONTAINER_RUNTIME"); got != tc.wantDefault {
				t.Fatalf("SB_CONTAINER_RUNTIME = %q, want %q", got, tc.wantDefault)
			}
		})
	}
}

func envIndex(c corev1.Container, name string) int {
	for i, e := range c.Env {
		if e.Name == name {
			return i
		}
	}
	return -1
}

// A named create policy reaches every role's agent: the file, read-only,
// optional (sandboxd refuses creates while it is missing), and the setting
// that points at it. No policy, no volume.
func TestStampCreatePolicy(t *testing.T) {
	c := testCluster()
	c.Spec.Security.CreatePolicy = &corev1.LocalObjectReference{Name: "prod-create-policy"}
	inputs := map[string]StampInput{
		TemplateServer:  {Cluster: c, Node: node("prod-server-0", v1.RoleServer, "", "z-a"), Namespace: testNS, Version: "v0.7.2", PVC: "data-x"},
		TemplateGateway: {Cluster: c, Node: node("prod-gateway-x", v1.RoleGateway, "", "z-a"), Namespace: testNS, Version: "v0.7.2"},
		TemplateWorker:  {Cluster: c, Node: node("prod-general-x", v1.RoleWorker, "general", "z-a"), Namespace: testWorkerNS, Version: "v0.7.2", Pool: &c.Spec.WorkerPools[0]},
	}
	for role, in := range inputs {
		pod, err := Stamp(mustTemplate(t, role), in)
		if err != nil {
			t.Fatal(err)
		}
		agent := pod.Spec.Containers[containerIndex(pod.Spec.Containers, AgentContainer)]
		if env(agent, "SB_CREATE_POLICY_FILE") != "/etc/aerolvm/create-policy/policy.yaml" {
			t.Fatalf("%s: SB_CREATE_POLICY_FILE = %q", role, env(agent, "SB_CREATE_POLICY_FILE"))
		}
		var vol *corev1.Volume
		for i := range pod.Spec.Volumes {
			if pod.Spec.Volumes[i].Name == CreatePolicyVolume {
				vol = &pod.Spec.Volumes[i]
			}
		}
		if vol == nil || vol.ConfigMap == nil || vol.ConfigMap.Name != "prod-create-policy" || vol.ConfigMap.Optional == nil || !*vol.ConfigMap.Optional ||
			len(vol.ConfigMap.Items) != 1 || vol.ConfigMap.Items[0].Key != CreatePolicyKey {
			t.Fatalf("%s: volume = %+v", role, vol)
		}
		mounted := false
		for _, m := range agent.VolumeMounts {
			mounted = mounted || (m.Name == CreatePolicyVolume && m.ReadOnly && m.MountPath == "/etc/aerolvm/create-policy")
		}
		if !mounted {
			t.Fatalf("%s: not mounted read-only: %+v", role, agent.VolumeMounts)
		}
	}
	c.Spec.Security.CreatePolicy = nil
	pod, err := Stamp(mustTemplate(t, TemplateGateway), inputs[TemplateGateway])
	if err != nil {
		t.Fatal(err)
	}
	if env(pod.Spec.Containers[0], "SB_CREATE_POLICY_FILE") != "<unset>" {
		t.Fatal("a policy file with no policy named")
	}
}

func TestSetupMountsAndSecurity(t *testing.T) {
	got := setupMounts([]corev1.VolumeMount{{Name: EtcVolume}, {Name: "containerd"}, {Name: StateVolume, SubPath: "state"},
		{Name: "netns", MountPropagation: ptr(corev1.MountPropagationBidirectional)}, {Name: "tmp"}})
	if len(got) != 3 || got[0].Name != EtcVolume || got[1].SubPath != "state" || got[2].Name != "tmp" {
		t.Fatalf("mounts = %+v", got)
	}
	agent := &corev1.SecurityContext{Privileged: ptr(true), RunAsUser: ptr[int64](65532),
		Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}}}
	sc := setupSecurity(agent)
	if *sc.Privileged || *sc.RunAsUser != 65532 || len(sc.Capabilities.Add) != 0 || !*agent.Privileged {
		t.Fatalf("setup = %+v, agent changed: %v", sc, *agent.Privileged)
	}
	if sc := setupSecurity(nil); *sc.Privileged || sc.Capabilities.Drop[0] != "ALL" {
		t.Fatalf("nil agent context: %+v", sc)
	}
}

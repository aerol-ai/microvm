package controller

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
)

// Pods (plans/kubernetes-v2-architecture.md §7, §8). The chart renders one
// pod template per role into a ConfigMap, from the same Helm templates its
// single mode uses, so a pod's containers, volumes and security settings
// have one source. The operator only stamps what makes one pod this node:
// its name, labels, zone, size, images, settings and the setup container
// that gives it its cluster identity.

// Template keys in the pod-templates ConfigMap.
const (
	TemplateServer  = "server"
	TemplateGateway = "gateway"
	TemplateWorker  = "worker"
)

// Container and volume names the templates use.
const (
	// AgentContainer runs sandboxd in every role; an upgrade swaps its
	// image in place (§8.2).
	AgentContainer = "agent"
	// RuntimeContainer holds containerd and the sandboxes (workers only).
	RuntimeContainer = "runtime"
	// SetupContainer is the init container the operator adds.
	SetupContainer = "setup"
	// EtcVolume holds /etc/sandboxd: sandboxd.env and the cluster files
	// init or join writes.
	EtcVolume = "etc"
	// StateVolume holds /var/lib/sandboxd.
	StateVolume = "state"
	// JoinVolume holds the pod's join token Secret.
	JoinVolume = "join"
)

// Labels the operator puts on every pod and object it makes.
const (
	LabelName      = "app.kubernetes.io/name"
	LabelComponent = "app.kubernetes.io/component"
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelCluster   = "aerolvm.io/cluster"
	LabelNode      = "aerolvm.io/node"
	LabelPool      = "aerolvm.io/pool"
	// LabelZone is the well-known zone label every cloud sets on a Node.
	LabelZone = "topology.kubernetes.io/zone"
)

// ParsePodTemplate reads one role's template from the ConfigMap.
func ParsePodTemplate(raw string) (corev1.PodTemplateSpec, error) {
	var t corev1.PodTemplateSpec
	if strings.TrimSpace(raw) == "" {
		return t, fmt.Errorf("empty pod template")
	}
	if err := yaml.UnmarshalStrict([]byte(raw), &t); err != nil {
		return t, fmt.Errorf("pod template: %w", err)
	}
	if containerIndex(t.Spec.Containers, AgentContainer) < 0 {
		return t, fmt.Errorf("pod template has no %q container", AgentContainer)
	}
	return t, nil
}

// ServerName is server i's name, which is also its AerolVM node ID.
func ServerName(cluster string, i int) string { return fmt.Sprintf("%s-server-%d", cluster, i) }

// WorkerName is a new worker's name: a replaced worker is a new AerolVM
// node, so the suffix is fresh each time.
func WorkerName(cluster, pool, suffix string) string {
	return fmt.Sprintf("%s-%s-%s", cluster, pool, suffix)
}

// ServersService is the headless Service that gives each server a stable
// DNS name, which Raft advertises (C4).
func ServersService(cluster string) string { return cluster + "-servers" }

// APIService is the ClusterIP Service in front of the servers' API.
func APIService(cluster string) string { return cluster + "-api" }

// GatewayService is the gateways' load balancer (§7.1).
func GatewayService(cluster string) string { return cluster + "-gateway" }

// AdminSecret holds the cluster's admin token.
func AdminSecret(cluster string) string { return cluster + "-admin" }

// JoinSecret is one pod's join token Secret, deleted once it joined.
func JoinSecret(node string) string { return node + "-join" }

// ServerDNS is server node's stable DNS name.
func ServerDNS(node, cluster, namespace string) string {
	return fmt.Sprintf("%s.%s.%s.svc", node, ServersService(cluster), namespace)
}

// sandboxdRole maps an AerolNode role to SB_NODE_ROLE: the gateway is
// today's ingress role (C11).
func sandboxdRole(role string) string {
	if role == v1.RoleGateway {
		return "ingress"
	}
	return role
}

// imageNames are the release images the operator tags with the version.
var imageNames = map[string]bool{"aerolvm": true, "aerolvm-runtime": true, "aerolvm-edge": true}

// ReleaseImage is name's image at version in registry.
func ReleaseImage(registry, name, version string) string {
	if registry == "" {
		registry = "ghcr.io/aerol-ai"
	}
	return strings.TrimRight(registry, "/") + "/" + name + ":" + version
}

// imageName is the repository's last path part, without tag or digest.
func imageName(image string) string {
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndex(image, "/"); i >= 0 {
		image = image[i+1:]
	}
	if i := strings.Index(image, ":"); i >= 0 {
		image = image[:i]
	}
	return image
}

// StampInput is what makes one pod this node.
type StampInput struct {
	Cluster   *v1.AerolCluster
	Node      *v1.AerolNode
	Namespace string
	// Version is the release the pod runs; the cluster's spec.version
	// unless an upgrade is part way.
	Version string
	// Bootstrap runs `sandboxd init` instead of join: server 0 of a new
	// cluster.
	Bootstrap bool
	// Maintenance holds a server for backup, restore or recover-quorum
	// (C22): its volume, no sandboxd.
	Maintenance bool
	// Pool is the worker's pool.
	Pool *v1.WorkerPoolSpec
	// PVC is a server's volume claim.
	PVC string
}

// Stamp makes node's pod from its role's template.
func Stamp(t corev1.PodTemplateSpec, in StampInput) (*corev1.Pod, error) {
	c, n := in.Cluster, in.Node
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        n.Name,
			Namespace:   in.Namespace,
			Labels:      map[string]string{},
			Annotations: map[string]string{},
		},
		Spec: *t.Spec.DeepCopy(),
	}
	for k, v := range t.Labels {
		pod.Labels[k] = v
	}
	for k, v := range t.Annotations {
		pod.Annotations[k] = v
	}
	pod.Labels[LabelName] = "aerolvm"
	pod.Labels[LabelComponent] = n.Spec.Role
	pod.Labels[LabelManagedBy] = "aerolvm-operator"
	pod.Labels[LabelCluster] = c.Name
	pod.Labels[LabelNode] = n.Name
	if n.Spec.Pool != "" {
		pod.Labels[LabelPool] = n.Spec.Pool
	}
	if n.Spec.Zone != "" {
		// Dashboards and the headroom alert group by zone (P9).
		pod.Labels[LabelZone] = n.Spec.Zone
	}

	for i := range pod.Spec.Containers {
		setReleaseImage(&pod.Spec.Containers[i], c.Spec.Images.Registry, in.Version)
	}
	for i := range pod.Spec.InitContainers {
		setReleaseImage(&pod.Spec.InitContainers[i], c.Spec.Images.Registry, in.Version)
	}
	if c.Spec.Images.PullPolicy != "" {
		for i := range pod.Spec.Containers {
			pod.Spec.Containers[i].ImagePullPolicy = c.Spec.Images.PullPolicy
		}
	}
	pod.Spec.ImagePullSecrets = append(pod.Spec.ImagePullSecrets, c.Spec.Images.PullSecrets...)

	pinZone(&pod.Spec, n.Spec.Zone)
	switch n.Spec.Role {
	case v1.RoleServer:
		mergeSelector(&pod.Spec, c.Spec.Servers.NodeSelector)
		pod.Spec.Tolerations = append(pod.Spec.Tolerations, c.Spec.Servers.Tolerations...)
		setResources(&pod.Spec, AgentContainer, c.Spec.Servers.Resources)
		// A stable DNS name under the servers' headless Service (C4).
		pod.Spec.Hostname = n.Name
		pod.Spec.Subdomain = ServersService(c.Name)
		if in.PVC == "" {
			return nil, fmt.Errorf("server %s has no volume claim", n.Name)
		}
		usePVC(&pod.Spec, in.PVC)
	case v1.RoleGateway:
		mergeSelector(&pod.Spec, c.Spec.Gateways.NodeSelector)
		pod.Spec.Tolerations = append(pod.Spec.Tolerations, c.Spec.Gateways.Tolerations...)
		setResources(&pod.Spec, AgentContainer, c.Spec.Gateways.Resources)
	case v1.RoleWorker:
		if in.Pool == nil {
			return nil, fmt.Errorf("worker %s has no pool", n.Name)
		}
		mergeSelector(&pod.Spec, in.Pool.NodeSelector)
		pod.Spec.Tolerations = append(pod.Spec.Tolerations, in.Pool.Tolerations...)
		if err := sizeWorker(&pod.Spec, in.Pool.Machine); err != nil {
			return nil, err
		}
		// Karpenter must never take a worker's machine by itself: the
		// operator decommissions first (§10.6).
		pod.Annotations["karpenter.sh/do-not-disrupt"] = "true"
	default:
		return nil, fmt.Errorf("unknown role %q", n.Spec.Role)
	}

	setEnv(&pod.Spec, AgentContainer, nodeEnv(in))
	if in.Maintenance {
		holdServer(&pod.Spec)
		pod.Labels[v1.AnnotationMaintenance] = "true"
		return pod, nil
	}
	addSetup(&pod.Spec, in)
	return pod, nil
}

// nodeEnv is the agent's settings that make it this node.
func nodeEnv(in StampInput) []corev1.EnvVar {
	n := in.Node
	env := []corev1.EnvVar{
		{Name: "SB_NODE_ID", Value: n.Name},
		{Name: "SB_NODE_NAME", Value: n.Name},
		{Name: "SB_NODE_ROLE", Value: sandboxdRole(n.Spec.Role)},
		{Name: "SB_NODE_ZONE", Value: n.Spec.Zone},
		{Name: "SB_CELL_ID", Value: strconv.Itoa(int(max(in.Cluster.Spec.Cell, 1)))},
		// The operator upgrades it: the rollout waits for the operator
		// in order (C13), and on a server a manual apply is refused (D6).
		{Name: "SB_UPGRADE_DRIVER", Value: "operator"},
	}
	if n.Spec.Role == v1.RoleWorker && in.Pool != nil && len(in.Pool.Runtimes) > 0 {
		env = append(env, corev1.EnvVar{Name: "SB_NODE_LABELS", Value: "aerolvm.io/pool=" + in.Pool.Name})
	}
	return env
}

// advertise is the address the node gives the cluster: a server's stable
// DNS name (C4), anyone else's pod IP.
func advertise(in StampInput) string {
	if in.Node.Spec.Role == v1.RoleServer {
		return ServerDNS(in.Node.Name, in.Cluster.Name, in.Namespace)
	}
	return "$(POD_IP)"
}

// setupScript writes sandboxd.env from the pod's own SB_ settings, then
// runs init or join with --files-only (F14): sandboxd loads both files at
// start, as systemd loads them on a VM. A re-run on a server whose volume
// already holds its files changes nothing, so a server pod that comes back
// keeps its identity.
const setupScript = `set -eu
umask 077
env | grep '^SB_' | grep -v '^SB_JOIN_' > /etc/sandboxd/sandboxd.env
if [ -s /etc/sandboxd/cluster.env ]; then
  echo "cluster files already here"; exit 0
fi
`

func addSetup(spec *corev1.PodSpec, in StampInput) {
	agent := spec.Containers[containerIndex(spec.Containers, AgentContainer)]
	n := in.Node
	role := sandboxdRole(n.Spec.Role)
	var cmd string
	if in.Bootstrap {
		cmd = fmt.Sprintf(`exec sandboxd init --files-only --role %s --node-id %s --advertise "%s"`, role, n.Name, advertise(in))
	} else {
		cmd = fmt.Sprintf(`exec sandboxd join "$(cat /var/run/aerolvm-join/join_url)" --token "$(cat /var/run/aerolvm-join/token)" --ca-cert-hash "$(cat /var/run/aerolvm-join/ca_cert_hash)" --role %s --node-id %s --advertise "%s" --files-only`, role, n.Name, advertise(in))
		spec.Volumes = append(spec.Volumes, corev1.Volume{Name: JoinVolume, VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{SecretName: JoinSecret(n.Name), DefaultMode: ptr[int32](0o400)},
		}})
	}
	setup := corev1.Container{
		Name:            SetupContainer,
		Image:           agent.Image,
		ImagePullPolicy: agent.ImagePullPolicy,
		Command:         []string{"/bin/sh", "-c", setupScript + cmd},
		Env: append([]corev1.EnvVar{{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"},
		}}}, agent.Env...),
		EnvFrom:         agent.EnvFrom,
		VolumeMounts:    agent.VolumeMounts,
		SecurityContext: agent.SecurityContext,
	}
	if !in.Bootstrap {
		setup.VolumeMounts = append(append([]corev1.VolumeMount{}, setup.VolumeMounts...),
			corev1.VolumeMount{Name: JoinVolume, MountPath: "/var/run/aerolvm-join", ReadOnly: true})
	}
	spec.InitContainers = append([]corev1.Container{setup}, spec.InitContainers...)
}

// holdServer swaps sandboxd for a process that holds the pod (C22), so a
// person can `kubectl exec` into it and run backup, restore or
// recover-quorum on the server's own volume.
func holdServer(spec *corev1.PodSpec) {
	i := containerIndex(spec.Containers, AgentContainer)
	c := &spec.Containers[i]
	c.Command = []string{"/bin/sh", "-c", "trap 'exit 0' TERM; while :; do sleep 3600 & wait $!; done"}
	c.Args = nil
	c.ReadinessProbe = nil
	c.LivenessProbe = nil
	c.StartupProbe = nil
}

// sizeWorker gives the worker pod nearly the whole machine (§8.1): request
// equals limit (Guaranteed), the runtime container taking all that the
// other containers do not.
func sizeWorker(spec *corev1.PodSpec, m v1.MachineSpec) error {
	cpu, mem := workerPodSize(m)
	i := containerIndex(spec.Containers, RuntimeContainer)
	if i < 0 {
		return fmt.Errorf("worker template has no %q container", RuntimeContainer)
	}
	for j := range spec.Containers {
		if j == i {
			continue
		}
		lim := spec.Containers[j].Resources.Limits
		cpu.Sub(lim[corev1.ResourceCPU])
		mem.Sub(lim[corev1.ResourceMemory])
	}
	if cpu.Sign() <= 0 || mem.Sign() <= 0 {
		return fmt.Errorf("machine %d CPU / %d GiB is too small for a worker pod", m.CPU, m.MemoryGiB)
	}
	rl := corev1.ResourceList{corev1.ResourceCPU: cpu, corev1.ResourceMemory: mem}
	spec.Containers[i].Resources = corev1.ResourceRequirements{Requests: rl, Limits: rl.DeepCopy()}
	return nil
}

// workerPodSize is what the worker pod asks for on machine m: allocatable
// (the machine less the kubelet's reserve, about 3% CPU and 8% memory on
// EKS and AKS) less what the per-machine add-ons take (0.5 CPU, 1 GiB),
// rounded down. On 32 CPU and 128 GiB that is 30.5 CPU and about 116.7
// GiB, the plan's example.
func workerPodSize(m v1.MachineSpec) (resource.Quantity, resource.Quantity) {
	milli := int64(math.Floor(float64(m.CPU)*970-500)/100) * 100
	mib := int64(float64(m.MemoryGiB)*1024*0.92) - 1024
	return *resource.NewMilliQuantity(max(milli, 0), resource.DecimalSI),
		*resource.NewQuantity(max(mib, 0)*1024*1024, resource.BinarySI)
}

func setReleaseImage(c *corev1.Container, registry, version string) {
	if version == "" {
		return
	}
	if name := imageName(c.Image); imageNames[name] {
		c.Image = ReleaseImage(registry, name, version)
	}
}

// pinZone adds "in zone" to every required node-affinity term (or makes
// the one term), so the pod lands in its zone whatever else it asks for.
func pinZone(spec *corev1.PodSpec, zone string) {
	if zone == "" {
		return
	}
	req := corev1.NodeSelectorRequirement{Key: LabelZone, Operator: corev1.NodeSelectorOpIn, Values: []string{zone}}
	if spec.Affinity == nil {
		spec.Affinity = &corev1.Affinity{}
	}
	if spec.Affinity.NodeAffinity == nil {
		spec.Affinity.NodeAffinity = &corev1.NodeAffinity{}
	}
	na := spec.Affinity.NodeAffinity
	if na.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		na.RequiredDuringSchedulingIgnoredDuringExecution = &corev1.NodeSelector{}
	}
	terms := na.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	if len(terms) == 0 {
		terms = []corev1.NodeSelectorTerm{{}}
	}
	for i := range terms {
		terms[i].MatchExpressions = append(terms[i].MatchExpressions, req)
	}
	na.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms = terms
}

func mergeSelector(spec *corev1.PodSpec, sel map[string]string) {
	if len(sel) == 0 {
		return
	}
	if spec.NodeSelector == nil {
		spec.NodeSelector = map[string]string{}
	}
	for k, v := range sel {
		spec.NodeSelector[k] = v
	}
}

func setResources(spec *corev1.PodSpec, name string, r corev1.ResourceRequirements) {
	if len(r.Requests) == 0 && len(r.Limits) == 0 {
		return
	}
	if i := containerIndex(spec.Containers, name); i >= 0 {
		spec.Containers[i].Resources = r
	}
}

// setEnv sets each of env on container name, replacing a value the
// template set.
func setEnv(spec *corev1.PodSpec, name string, env []corev1.EnvVar) {
	i := containerIndex(spec.Containers, name)
	c := &spec.Containers[i]
	for _, e := range env {
		replaced := false
		for j := range c.Env {
			if c.Env[j].Name == e.Name {
				c.Env[j] = e
				replaced = true
				break
			}
		}
		if !replaced {
			c.Env = append(c.Env, e)
		}
	}
}

// usePVC puts the server's claim behind its etc and state volumes, so its
// cluster files and Raft log survive the pod.
func usePVC(spec *corev1.PodSpec, claim string) {
	src := corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim}}
	found := false
	for i := range spec.Volumes {
		switch spec.Volumes[i].Name {
		case StateVolume:
			spec.Volumes[i].VolumeSource = src
			found = true
		case EtcVolume:
			// One claim, two folders: etc lives at etc/ on it.
			spec.Volumes[i].VolumeSource = src
		}
	}
	if !found {
		spec.Volumes = append(spec.Volumes, corev1.Volume{Name: StateVolume, VolumeSource: src})
	}
	for _, list := range [][]corev1.Container{spec.Containers, spec.InitContainers} {
		for i := range list {
			for j := range list[i].VolumeMounts {
				vm := &list[i].VolumeMounts[j]
				switch vm.Name {
				case EtcVolume:
					vm.SubPath = "etc"
				case StateVolume:
					vm.SubPath = "state"
				}
			}
		}
	}
}

func containerIndex(cs []corev1.Container, name string) int {
	for i := range cs {
		if cs[i].Name == name {
			return i
		}
	}
	return -1
}

func ptr[T any](v T) *T { return &v }

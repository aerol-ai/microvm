package controller

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/operator/internal/aerolapi"
)

// The node controller (plans/kubernetes-v2-architecture.md §10.2): one
// AerolNode becomes its pod and follows it through its life. Servers keep
// their name and volume across pods. A gateway or worker is one pod's life:
// when its pod ends for good the node is removed and the cluster controller
// makes a new one, so a replaced worker is a new AerolVM node with a fresh
// identity, never a second copy of an old one.

// Timing.
const (
	// joinTokenTTL bounds a minted token; the pod uses it within seconds
	// of its machine starting, and Karpenter can take two minutes.
	joinTokenTTL = "30m"
	// statusEvery spaces the counters' writes (G4: a few writes per
	// machine per minute at most).
	statusEvery = time.Minute
	// failAfter is how long a setup container may crash before the node
	// counts as Failed.
	failAfter            = 5 * time.Minute
	defaultDrainWindow   = 15 * time.Minute
	eksManagedDrain      = 5 * time.Minute
	defaultDecomDeadline = 45 * time.Minute
)

// NodeReconciler reconciles AerolNodes.
type NodeReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	API      APIFactory
	// Namespace holds the AerolClusters, AerolNodes, servers and gateways.
	Namespace string
	// WorkerNamespace holds the worker pods: the one namespace where a
	// privileged pod is allowed (§8.7).
	WorkerNamespace string
	// Templates is the chart's pod-templates ConfigMap.
	Templates string
	Now       func() time.Time
	// Reader reads past the manager's cache, which holds only AerolVM's
	// namespaces: the API server's Service and addresses in default, and
	// the ServiceCIDRs (C24). Nil uses the client.
	Reader client.Reader
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=karpenter.sh,resources=nodeclaims,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",namespace=default,resources=services,resourceNames=kubernetes,verbs=get
// +kubebuilder:rbac:groups=discovery.k8s.io,namespace=default,resources=endpointslices,resourceNames=kubernetes,verbs=get
// +kubebuilder:rbac:groups=networking.k8s.io,resources=servicecidrs,verbs=list
// The operator's client caches unstructured reads (main.go), so reading a
// Certificate starts an informer: list and watch, in its two namespaces.
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create;delete

func (r *NodeReconciler) podNamespace(role string) string {
	if role == v1.RoleWorker && r.WorkerNamespace != "" {
		return r.WorkerNamespace
	}
	return r.Namespace
}

// Reconcile follows one AerolNode.
func (r *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	defer func() {
		if err != nil {
			reconcileErrors.WithLabelValues("aerolnode").Inc()
		}
	}()
	var n v1.AerolNode
	if err := r.Get(ctx, req.NamespacedName, &n); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, r.sweepGone(ctx, req.Name)
		}
		return ctrl.Result{}, err
	}
	if n.DeletionTimestamp != nil {
		return ctrl.Result{}, r.cleanup(ctx, &n)
	}
	var c v1.AerolCluster
	if err := r.Get(ctx, types.NamespacedName{Namespace: n.Namespace, Name: n.Spec.Cluster}, &c); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if n.Status.State == v1.StateRemoved {
		// Nothing left: the object goes too, which also tells the cluster
		// controller the slot is free. Every way a node leaves comes
		// here, so its certificate goes here too: the next node gets a
		// new name and a new certificate.
		if externalCA(&c) {
			if err := r.removeNodeCert(ctx, r.podNamespace(n.Spec.Role), n.Name); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, client.IgnoreNotFound(r.Delete(ctx, &n))
	}
	token, err := r.adminToken(ctx, &c)
	if err != nil {
		return ctrl.Result{}, err
	}
	api := r.API(apiURL(&c), token)
	before := n.Status.DeepCopy()
	defer func() {
		if err == nil && !statusEqual(before, &n.Status) {
			err = r.Status().Update(ctx, &n)
		}
	}()

	pod, err := r.pod(ctx, &n)
	if err != nil {
		return ctrl.Result{}, err
	}

	if n.Spec.Role == v1.RoleServer {
		if res, done, err := r.maintenance(ctx, &c, &n, pod); done || err != nil {
			return res, err
		}
	}
	if n.Spec.Role == v1.RoleWorker {
		if res, done, err := r.decommissionTriggers(ctx, &c, &n, pod); done || err != nil {
			return res, err
		}
		if n.Annotations[v1.AnnotationDecommission] == "true" {
			return r.decommission(ctx, &c, &n, pod, api)
		}
	}
	if pod != nil {
		if gone, err := r.machineGone(ctx, &n, pod, api); err != nil || gone {
			return ctrl.Result{RequeueAfter: 10 * time.Second}, err
		}
	}
	if pod == nil && n.Status.PodName != "" && n.Spec.Role != v1.RoleServer {
		return r.lost(ctx, &n, api)
	}
	if pod == nil {
		return r.createPod(ctx, &c, &n, api)
	}
	if want := n.Annotations[AnnotationAgentVersion]; want != "" {
		if err := r.swapAgent(ctx, &c, &n, pod, want); err != nil {
			upgradeStepFailures.Inc()
			return ctrl.Result{}, err
		}
	}
	return r.observe(ctx, &c, &n, pod, api)
}

func statusEqual(a, b *v1.AerolNodeStatus) bool {
	return a.State == b.State && a.Reason == b.Reason && a.PodName == b.PodName && a.NodeName == b.NodeName &&
		a.Version == b.Version && a.Sandboxes == b.Sandboxes && a.FreeCPU == b.FreeCPU && a.FreeMemory == b.FreeMemory &&
		a.AgentImage == b.AgentImage && a.AgentImageID == b.AgentImageID && a.LastUpdated.Equal(&b.LastUpdated) &&
		decomEqual(a.Decommission, b.Decommission) && len(a.Conditions) == len(b.Conditions)
}

func decomEqual(a, b *v1.DecommissionStatus) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (r *NodeReconciler) adminToken(ctx context.Context, c *v1.AerolCluster) (string, error) {
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: AdminSecret(c.Name)}, &s); err != nil {
		return "", err
	}
	return string(s.Data["token"]), nil
}

func (r *NodeReconciler) pod(ctx context.Context, n *v1.AerolNode) (*corev1.Pod, error) {
	var p corev1.Pod
	err := r.Get(ctx, types.NamespacedName{Namespace: r.podNamespace(n.Spec.Role), Name: n.Name}, &p)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *NodeReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// setState records a state change, with an Event.
func (r *NodeReconciler) setState(n *v1.AerolNode, state, reason string) {
	if n.Status.State != state && r.Recorder != nil {
		msg := state
		if reason != "" {
			msg += ": " + reason
		}
		r.Recorder.Event(n, corev1.EventTypeNormal, state, msg)
	}
	n.Status.State, n.Status.Reason = state, reason
}

// createPod makes the node's pod: its identity first (C23), a join token
// or, in external-CA mode, its certificate; then the pod from its role's
// template.
func (r *NodeReconciler) createPod(ctx context.Context, c *v1.AerolCluster, n *v1.AerolNode, api AerolAPI) (ctrl.Result, error) {
	bootstrap := n.Spec.Role == v1.RoleServer && n.Name == ServerName(c.Name, 0) &&
		!meta.IsStatusConditionTrue(c.Status.Conditions, CondBootstrapped)
	ns := r.podNamespace(n.Spec.Role)
	maint := n.Spec.Role == v1.RoleServer && n.Annotations[v1.AnnotationMaintenance] == "true"
	// A maintenance pod runs no setup, so it needs no token: it is how a
	// cluster that lost quorum is repaired, when no token can be minted.
	switch {
	case externalCA(c) && !maint:
		// Every pod, server 0 too, starts with its certificate in place:
		// init and join read it, and nothing else can make one.
		why, err := r.ensureNodeCert(ctx, c, n, ns)
		if err != nil {
			return ctrl.Result{}, err
		}
		if why != "" {
			r.certificatePending(n, why)
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		meta.RemoveStatusCondition(&n.Status.Conditions, CondCertificatePending)
	case externalCA(c):
		// A maintenance pod runs no sandboxd: it mounts the certificate
		// if it is there and never waits for the issuer.
	case !bootstrap && !maint:
		if err := r.ensureJoinSecret(ctx, c, n, ns, api); err != nil {
			joinTokenErrors.Inc()
			if n.Spec.Role != v1.RoleServer {
				r.setState(n, v1.StatePending, "waiting for a join token: "+err.Error())
				return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
			}
			// Minting needs a leader. A server pod made again (moved, or
			// its pod lost) keeps its identity on its disk, and its setup
			// then needs no token: waiting here would keep a cluster that
			// lost two of three servers from ever getting them back. The
			// token volume is optional for servers; one that has no
			// identity waits in setup until observe can mint it a token.
			log.FromContext(ctx).Info("no join token for a server; making its pod without one", "node", n.Name, "error", err.Error())
		}
	}
	t, err := r.template(ctx, n.Spec.Role)
	if err != nil {
		r.setState(n, v1.StateFailed, err.Error())
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	// The version last ordered for this node (its rollout turn), else the
	// cluster's: a pod made again during an upgrade, before its turn, keeps
	// its version, so swapAgent never moves it back down and the leader's
	// order holds. A node new to the cluster has no turn and takes the target.
	version := c.Spec.Version
	if v := n.Annotations[AnnotationAgentVersion]; v != "" {
		version = v
	}
	in := StampInput{Cluster: c, Node: n, Namespace: ns, Version: version, Bootstrap: bootstrap, Maintenance: maint}
	if n.Spec.Role == v1.RoleServer {
		in.PVC = PVCName(n.Name)
	}
	if n.Spec.Role == v1.RoleWorker {
		in.Pool = poolOf(c, n.Spec.Pool)
		if in.Pool == nil {
			r.setState(n, v1.StateFailed, "pool "+n.Spec.Pool+" is not in the AerolCluster")
			return ctrl.Result{}, nil
		}
		in.Addresses = readClusterAddresses(ctx, r.apiReader(), r.Client)
	}
	pod, err := Stamp(t, in)
	if err != nil {
		r.setState(n, v1.StateFailed, err.Error())
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	if ns == n.Namespace {
		if err := controllerutil.SetControllerReference(n, pod, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}
	}
	if err := r.Create(ctx, pod); err != nil && !apierrors.IsAlreadyExists(err) {
		return ctrl.Result{}, err
	}
	n.Status.PodName = pod.Name
	r.setState(n, v1.StatePending, "pod made")
	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

func poolOf(c *v1.AerolCluster, name string) *v1.WorkerPoolSpec {
	for i := range c.Spec.WorkerPools {
		if c.Spec.WorkerPools[i].Name == name {
			return &c.Spec.WorkerPools[i]
		}
	}
	return nil
}

func (r *NodeReconciler) template(ctx context.Context, role string) (corev1.PodTemplateSpec, error) {
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: r.Templates}, &cm); err != nil {
		return corev1.PodTemplateSpec{}, fmt.Errorf("pod templates %s: %w", r.Templates, err)
	}
	return ParsePodTemplate(cm.Data[role])
}

// ensureJoinSecret mints the pod's single-use join token and stores it in
// a Secret only that pod mounts; it is deleted once the node serves. The
// operator made the pod itself, after the scheduler bound nothing yet, so
// no other pod can claim the token: the Secret's name is the pod's.
func (r *NodeReconciler) ensureJoinSecret(ctx context.Context, c *v1.AerolCluster, n *v1.AerolNode, ns string, api AerolAPI) error {
	var s corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: JoinSecret(n.Name)}, &s)
	if err == nil || !apierrors.IsNotFound(err) {
		return err
	}
	tok, err := api.MintJoinToken(ctx, sandboxdRole(n.Spec.Role), joinTokenTTL, "aerolvm-operator:"+n.Name)
	if err != nil {
		return err
	}
	// The answering server's join listener; servers advertise their stable
	// DNS names (C4), so it outlives any pod IP.
	joinURL := fmt.Sprintf("https://%s:%d", ServerDNS(ServerName(c.Name, 0), c.Name, c.Namespace), JoinPort)
	if len(tok.JoinURLs) > 0 {
		joinURL = tok.JoinURLs[0]
	}
	s = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: JoinSecret(n.Name), Namespace: ns, Labels: map[string]string{
			LabelName: "aerolvm", LabelCluster: c.Name, LabelNode: n.Name, LabelManagedBy: "aerolvm-operator",
		}},
		Data: map[string][]byte{
			"token": []byte(tok.Token), "ca_cert_hash": []byte(tok.CACertHash), "join_url": []byte(joinURL),
		},
	}
	if ns == n.Namespace {
		if err := controllerutil.SetControllerReference(n, &s, r.Scheme); err != nil {
			return err
		}
	}
	return r.Create(ctx, &s)
}

// observe sets the node's state from its pod and from AerolVM.
func (r *NodeReconciler) observe(ctx context.Context, c *v1.AerolCluster, n *v1.AerolNode, pod *corev1.Pod, api AerolAPI) (ctrl.Result, error) {
	n.Status.PodName, n.Status.NodeName = pod.Name, pod.Spec.NodeName
	if n.Spec.Role == v1.RoleServer && setupHasFailed(pod) && !externalCA(c) {
		// A server made without a token (createPod) whose disk held no
		// identity: mint one now that a leader may be back. The kubelet
		// puts it in the pod's optional volume before setup's next try.
		// In external-CA mode its certificate is its identity, and setup
		// retries the join with it by itself.
		if err := r.ensureJoinSecret(ctx, c, n, pod.Namespace, api); err != nil {
			joinTokenErrors.Inc()
		}
	}
	if why := preflightFailed(pod); why != "" {
		// The machine is wrong, not the pod: a new pod would only land on
		// a machine like it. This one stays, holding its machine out of
		// service with the reason, and its slot is free for a worker on
		// another machine. The kubelet retries the check, so a machine
		// fixed in place joins by itself.
		r.setState(n, v1.StateFailed, why)
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	if why := setupFailing(pod, r.now()); why != "" {
		r.setState(n, v1.StateFailed, why)
		if n.Spec.Role != v1.RoleServer {
			// A gateway or worker that cannot join is replaced by a new
			// node with a new token.
			return ctrl.Result{}, r.endPod(ctx, n, pod, "it never joined: "+why)
		}
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	if pod.Spec.NodeName == "" {
		r.setState(n, v1.StatePending, waitingForMachine(pod))
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}
	if !agentReady(pod) {
		state := v1.StateJoining
		if n.Status.State == v1.StateServing || n.Status.State == v1.StateRestarting {
			state = v1.StateRestarting
		}
		r.setState(n, state, "")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	node, err := api.GetNode(ctx, n.Name)
	switch {
	case aerolapi.IsStatus(err, http.StatusNotFound):
		r.setState(n, v1.StateJoining, "not a cluster member yet")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	case err != nil:
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	switch {
	case !node.Alive:
		r.setState(n, v1.StateSuspect, "gossip does not see it")
	case node.Restarting:
		r.setState(n, v1.StateRestarting, "")
	case node.Drained && n.Spec.Role == v1.RoleWorker:
		r.setState(n, v1.StateDraining, "cordoned")
	default:
		r.setState(n, v1.StateServing, "")
	}
	if n.Status.State == v1.StateServing {
		// The token was single use and is spent. Deleted once: the cached
		// read keeps every later pass, on every serving node, from sending
		// the API server a delete that only finds nothing.
		var s corev1.Secret
		if err := r.Get(ctx, types.NamespacedName{Name: JoinSecret(n.Name), Namespace: r.podNamespace(n.Spec.Role)}, &s); err == nil {
			_ = client.IgnoreNotFound(r.Delete(ctx, &s))
		}
	}
	if r.now().Sub(n.Status.LastUpdated.Time) >= statusEvery {
		n.Status.Version = node.Version
		n.Status.Sandboxes = int32(node.SandboxesRunning)
		n.Status.FreeCPU = fmt.Sprintf("%.1f", node.Capacity.FreeCPU())
		n.Status.FreeMemory = fmt.Sprintf("%dMi", node.Capacity.FreeMemoryMB())
		n.Status.AgentImage, n.Status.AgentImageID = containerImage(pod, AgentContainer)
		n.Status.LastUpdated = metav1.NewTime(r.now())
	}
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func agentReady(pod *corev1.Pod) bool {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == AgentContainer {
			return cs.Ready
		}
	}
	return false
}

func containerImage(pod *corev1.Pod, name string) (string, string) {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == name {
			return cs.Image, cs.ImageID
		}
	}
	return "", ""
}

// preflightFailed is the worker preflight's reason when its last run
// failed: the last line of its termination message, which names each
// failed check and its fix (sandboxd preflight --pod).
// waitingForMachine is a Pending node's reason: the scheduler's own word
// when it found no machine (a server that does not fit its zone's node
// says "Insufficient cpu" here, on `kubectl get aerolnodes`, instead of
// only in the pod's events).
func waitingForMachine(pod *corev1.Pod) string {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason == corev1.PodReasonUnschedulable && c.Message != "" {
			msg := c.Message
			if len(msg) > 240 {
				msg = msg[:240] + "..."
			}
			return "waiting for a machine: " + msg
		}
	}
	return "waiting for a machine"
}

func preflightFailed(pod *corev1.Pod) string {
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.Name != PreflightContainer {
			continue
		}
		t := cs.State.Terminated
		if t == nil {
			t = cs.LastTerminationState.Terminated
		}
		if t == nil || t.ExitCode == 0 || cs.State.Running != nil {
			return ""
		}
		msg := strings.TrimSpace(t.Message)
		if i := strings.LastIndexByte(msg, '\n'); i >= 0 {
			msg = strings.TrimSpace(msg[i+1:])
		}
		if msg == "" {
			msg = fmt.Sprintf("preflight failed (exit %d)", t.ExitCode)
		}
		const max = 1024
		if len(msg) > max {
			msg = msg[:max]
		}
		return msg
	}
	return ""
}

// setupHasFailed reports that the pod's setup container has exited with
// an error at least once.
func setupHasFailed(pod *corev1.Pod) bool {
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.Name != SetupContainer {
			continue
		}
		for _, t := range []*corev1.ContainerStateTerminated{cs.State.Terminated, cs.LastTerminationState.Terminated} {
			if t != nil && t.ExitCode != 0 {
				return true
			}
		}
	}
	return false
}

// setupFailing names why the pod cannot start: its setup container keeps
// failing, or an image cannot be pulled, past failAfter.
func setupFailing(pod *corev1.Pod, now time.Time) string {
	if now.Sub(pod.CreationTimestamp.Time) < failAfter {
		return ""
	}
	for _, list := range [][]corev1.ContainerStatus{pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses} {
		for _, cs := range list {
			w := cs.State.Waiting
			if w == nil {
				continue
			}
			switch w.Reason {
			case "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError", "InvalidImageName":
				if cs.Name == SetupContainer || w.Reason != "CrashLoopBackOff" {
					return fmt.Sprintf("%s: %s %s", cs.Name, w.Reason, strings.TrimSpace(w.Message))
				}
			}
		}
	}
	return ""
}

// swapAgent changes the agent container's image in place when the rollout
// reached this node (C13): only that container restarts, sandboxes keep
// running (§8.2). The edge container, when the pod has one, moves with it.
// The swap is done once the kubelet reports a new image ID (eng review
// SC-1); the leader marks the node done once it reports the new version.
func (r *NodeReconciler) swapAgent(ctx context.Context, c *v1.AerolCluster, n *v1.AerolNode, pod *corev1.Pod, version string) error {
	want := ReleaseImage(c.Spec.Images.Registry, "aerolvm", version)
	i := containerIndex(pod.Spec.Containers, AgentContainer)
	if i < 0 || pod.Spec.Containers[i].Image == want {
		return nil
	}
	_, oldID := containerImage(pod, AgentContainer)
	patch := client.MergeFrom(pod.DeepCopy())
	pod.Spec.Containers[i].Image = want
	if j := containerIndex(pod.Spec.Containers, "edge"); j >= 0 {
		pod.Spec.Containers[j].Image = ReleaseImage(c.Spec.Images.Registry, "aerolvm-edge", version)
	}
	if err := r.Patch(ctx, pod, patch); err != nil {
		return err
	}
	n.Status.AgentImage, n.Status.AgentImageID = want, oldID
	r.setState(n, v1.StateRestarting, "agent to "+version)
	return nil
}

// maintenance holds a server for backup, restore or recover-quorum (C22):
// with the annotation set, its pod is made again with its volume and a
// holding process in place of sandboxd; without it, as a server again.
func (r *NodeReconciler) maintenance(ctx context.Context, c *v1.AerolCluster, n *v1.AerolNode, pod *corev1.Pod) (ctrl.Result, bool, error) {
	want := n.Annotations[v1.AnnotationMaintenance] == "true"
	if pod == nil {
		return ctrl.Result{}, false, nil
	}
	has := pod.Labels[v1.AnnotationMaintenance] == "true"
	if want == has {
		if want {
			r.setState(n, v1.StateMaintenance, "held for backup, restore or recover-quorum")
			return ctrl.Result{RequeueAfter: time.Minute}, true, nil
		}
		return ctrl.Result{}, false, nil
	}
	if err := r.Delete(ctx, pod); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, true, err
	}
	if want {
		r.setState(n, v1.StateMaintenance, "pod made again in maintenance mode")
	} else {
		r.setState(n, v1.StateJoining, "back from maintenance")
	}
	return ctrl.Result{RequeueAfter: 5 * time.Second}, true, nil
}

// machineGone reports a pod whose machine left (its Node object was
// deleted) and tells the leader (C19). The leader may then fail the node
// over at its ownership lease limit, never sooner.
func (r *NodeReconciler) machineGone(ctx context.Context, n *v1.AerolNode, pod *corev1.Pod, api AerolAPI) (bool, error) {
	if pod.Spec.NodeName == "" || n.Spec.Role == v1.RoleServer {
		return false, nil
	}
	var node corev1.Node
	err := r.Get(ctx, types.NamespacedName{Name: pod.Spec.NodeName}, &node)
	if !apierrors.IsNotFound(err) {
		return false, client.IgnoreNotFound(err)
	}
	if err := api.Gone(ctx, n.Name); err != nil {
		log.FromContext(ctx).Info("telling the leader the machine is gone failed; retrying", "node", n.Name, "err", err)
	}
	if !meta.IsStatusConditionTrue(n.Status.Conditions, "MachineGone") {
		meta.SetStatusCondition(&n.Status.Conditions, metav1.Condition{Type: "MachineGone", Status: metav1.ConditionTrue,
			Reason: "NodeDeleted", Message: "the Kubernetes Node " + pod.Spec.NodeName + " was deleted"})
		r.setState(n, v1.StateSuspect, "its machine is gone")
		if n.Spec.Role == v1.RoleWorker && n.Annotations[v1.AnnotationDecommission] != "true" {
			workerPodsLost.Inc()
		}
	}
	// The pod object goes with its Node; lost() takes it from there.
	return true, nil
}

// lost handles a gateway or worker whose pod ended without a decommission:
// its sandboxes are the dead-owner failover's. Once gossip sees the node
// dead and it owns nothing, it leaves the cluster and the AerolNode is
// removed; the cluster controller makes a replacement.
func (r *NodeReconciler) lost(ctx context.Context, n *v1.AerolNode, api AerolAPI) (ctrl.Result, error) {
	if n.Status.State != v1.StateDead && n.Status.State != v1.StateSuspect {
		if n.Spec.Role == v1.RoleWorker {
			workerPodsLost.Inc()
		}
		r.setState(n, v1.StateSuspect, "its pod is gone")
	}
	_ = api.Gone(ctx, n.Name)
	node, err := api.GetNode(ctx, n.Name)
	switch {
	case aerolapi.IsStatus(err, http.StatusNotFound):
	case err != nil:
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	case node.Alive:
		// Its machine still runs it (a partition): nothing to remove.
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	case node.SandboxesOwned > 0:
		r.setState(n, v1.StateDead, fmt.Sprintf("failover moving its %d sandboxes", node.SandboxesOwned))
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}
	if err := api.DeleteNode(ctx, n.Name, false); err != nil {
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	_ = client.IgnoreNotFound(r.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: JoinSecret(n.Name), Namespace: r.podNamespace(n.Spec.Role)}}))
	r.setState(n, v1.StateRemoved, "its pod ended; replaced")
	return ctrl.Result{Requeue: true}, nil
}

// endPod deletes a pod the operator gave up on; the node is then lost.
func (r *NodeReconciler) endPod(ctx context.Context, n *v1.AerolNode, pod *corev1.Pod, why string) error {
	if r.Recorder != nil {
		r.Recorder.Event(n, corev1.EventTypeWarning, "PodEnded", why)
	}
	return client.IgnoreNotFound(r.Delete(ctx, pod))
}

// cleanup deletes what lives outside the AerolNode's namespace: a worker's
// pod, join token and certificate in the worker namespace, which no owner
// reference can reach across namespaces.
func (r *NodeReconciler) cleanup(ctx context.Context, n *v1.AerolNode) error {
	if r.podNamespace(n.Spec.Role) == n.Namespace {
		return nil
	}
	ns := r.podNamespace(n.Spec.Role)
	if err := client.IgnoreNotFound(r.Delete(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: n.Name, Namespace: ns}})); err != nil {
		return err
	}
	if err := client.IgnoreNotFound(r.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: JoinSecret(n.Name), Namespace: ns}})); err != nil {
		return err
	}
	return r.sweepCert(ctx, ns, n.Name)
}

// sweepCert removes a worker's certificate from the worker namespace when
// its Secret is there (read from the cache, so a token-mode cluster makes
// no API call for it).
func (r *NodeReconciler) sweepCert(ctx context.Context, ns, name string) error {
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: NodeCert(name)}, &s); err != nil {
		return client.IgnoreNotFound(err)
	}
	return r.removeNodeCert(ctx, ns, name)
}

// sweepGone removes a deleted worker AerolNode's pod, join Secret and
// certificate. They live in the worker namespace, where no owner reference
// reaches (an owner must share its namespace), so the garbage collector
// never takes them.
// No finalizer: helm uninstall deletes the operator and the AerolCluster at
// once, and a finalizer would then hold every AerolNode's deletion forever.
// The pod watch maps each worker pod back here when the operator starts,
// so a node deleted while it was down is swept then.
func (r *NodeReconciler) sweepGone(ctx context.Context, name string) error {
	ns := r.WorkerNamespace
	if ns == "" || ns == r.Namespace {
		return nil // owner references take them
	}
	var pod corev1.Pod
	podLeft := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &pod) == nil &&
		pod.Labels[LabelNode] == name && pod.DeletionTimestamp == nil
	var secret, cert corev1.Secret
	secretLeft := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: JoinSecret(name)}, &secret) == nil
	certLeft := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: NodeCert(name)}, &cert) == nil &&
		cert.Labels[LabelNode] == name
	if !podLeft && !secretLeft && !certLeft {
		return nil // the usual case: costs no API call
	}
	// The cache can be behind: only the API server may say the node is gone.
	if err := r.apiReader().Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: name}, &v1.AerolNode{}); !apierrors.IsNotFound(err) {
		return err
	}
	if podLeft {
		uid := pod.UID
		if err := client.IgnoreNotFound(r.Delete(ctx, &pod, client.Preconditions{UID: &uid})); err != nil {
			return err
		}
		log.FromContext(ctx).Info("removed the pod of a deleted AerolNode", "pod", ns+"/"+name)
	}
	if secretLeft {
		if err := client.IgnoreNotFound(r.Delete(ctx, &secret)); err != nil {
			return err
		}
	}
	if certLeft {
		return r.removeNodeCert(ctx, ns, name)
	}
	return nil
}

// apiReader reads straight from the API server (see Reader).
func (r *NodeReconciler) apiReader() client.Reader {
	if r.Reader != nil {
		return r.Reader
	}
	return r.Client
}

// SetupWithManager registers the controller and maps pods and Nodes back
// to their AerolNodes.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.API == nil {
		r.API = DefaultAPIFactory
	}
	toNode := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		name := o.GetLabels()[LabelNode]
		if name == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: r.Namespace, Name: name}}}
	})
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.AerolNode{}).
		Watches(&corev1.Pod{}, toNode).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(r.nodeToAerolNodes)).
		Named("aerolnode").
		Complete(r)
}

// nodeToAerolNodes wakes the AerolNodes whose pods run on a Kubernetes Node
// that changed: cordoned, drifted or deleted.
func (r *NodeReconciler) nodeToAerolNodes(ctx context.Context, o client.Object) []reconcile.Request {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.MatchingLabels{LabelName: "aerolvm"}, client.MatchingFields{"spec.nodeName": o.GetName()}); err != nil {
		return nil
	}
	var out []reconcile.Request
	for _, p := range pods.Items {
		if name := p.Labels[LabelNode]; name != "" {
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: r.Namespace, Name: name}})
		}
	}
	return out
}

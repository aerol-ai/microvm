package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/operator/internal/aerolapi"
)

type nodeRig struct {
	t   *testing.T
	r   *NodeReconciler
	api *fakeAPI
	cl  client.Client
	now time.Time
}

func newNodeRig(t *testing.T, c *v1.AerolCluster, objs ...client.Object) *nodeRig {
	t.Helper()
	all := append([]client.Object{c, adminSecret(), templates(t)}, objs...)
	// A server's data claim, as the cluster controller makes it before the
	// server's AerolNode (ensurePVC), unless the test brings its own.
	claims := map[string]bool{}
	for _, o := range objs {
		if pvc, ok := o.(*corev1.PersistentVolumeClaim); ok {
			claims[pvc.Name] = true
		}
	}
	for _, o := range objs {
		if n, ok := o.(*v1.AerolNode); ok && n.Spec.Role == v1.RoleServer && !claims[PVCName(n.Name)] {
			all = append(all, &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: c.Namespace, Name: PVCName(n.Name)}})
		}
	}
	cl := newFakeClient(t, all...)
	api := newFakeAPI()
	g := &nodeRig{t: t, api: api, cl: cl, now: time.Unix(2_000_000_000, 0)}
	g.r = &NodeReconciler{Client: cl, Scheme: cl.Scheme(), Recorder: record.NewFakeRecorder(200), API: api.factory,
		Namespace: testNS, WorkerNamespace: testWorkerNS, Templates: "aerolvm-pod-templates", Now: func() time.Time { return g.now }}
	return g
}

func (g *nodeRig) reconcile(name string) ctrl.Result {
	g.t.Helper()
	res, err := g.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNS, Name: name}})
	if err != nil {
		g.t.Fatalf("reconcile %s: %v", name, err)
	}
	return res
}

func (g *nodeRig) node(name string) *v1.AerolNode {
	g.t.Helper()
	var n v1.AerolNode
	if err := g.cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: name}, &n); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		g.t.Fatal(err)
	}
	return &n
}

func (g *nodeRig) pod(ns, name string) *corev1.Pod {
	g.t.Helper()
	var p corev1.Pod
	if err := g.cl.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &p); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		g.t.Fatal(err)
	}
	return &p
}

// running makes p scheduled on machine with the agent ready (or not).
func (g *nodeRig) running(p *corev1.Pod, machine string, ready bool) {
	g.t.Helper()
	p.Spec.NodeName = machine
	if err := g.cl.Update(context.Background(), p); err != nil {
		g.t.Fatal(err)
	}
	p.Status.Phase = corev1.PodRunning
	p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: AgentContainer, Ready: ready, Image: p.Spec.Containers[containerIndex(p.Spec.Containers, AgentContainer)].Image, ImageID: "sha256:old"}}
	if err := g.cl.Status().Update(context.Background(), p); err != nil {
		g.t.Fatal(err)
	}
}

func machine(name string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{LabelZone: "z-a"}}}
}

func TestNodeServerZeroBootstrapsThenServes(t *testing.T) {
	g := newNodeRig(t, testCluster(), node("prod-server-0", v1.RoleServer, "", "z-a"), machine("m1"))
	g.reconcile("prod-server-0")
	p := g.pod(testNS, "prod-server-0")
	if p == nil || !strings.Contains(p.Spec.InitContainers[0].Command[2], "sandboxd init --files-only") {
		t.Fatalf("server-0 pod = %+v", p)
	}
	if len(p.OwnerReferences) != 1 || p.OwnerReferences[0].Name != "prod-server-0" {
		t.Fatalf("owner = %+v", p.OwnerReferences)
	}
	if len(g.api.minted) != 0 {
		t.Fatal("server 0 of a new cluster minted a join token")
	}
	if n := g.node("prod-server-0"); n.Status.State != v1.StatePending {
		t.Fatalf("state %s", n.Status.State)
	}
	// Scheduled, agent not ready: joining.
	g.running(p, "m1", false)
	g.reconcile("prod-server-0")
	if n := g.node("prod-server-0"); n.Status.State != v1.StateJoining {
		t.Fatalf("state %s", n.Status.State)
	}
	// Ready, but not a member yet: still joining.
	p = g.pod(testNS, "prod-server-0")
	g.running(p, "m1", true)
	g.reconcile("prod-server-0")
	if n := g.node("prod-server-0"); n.Status.State != v1.StateJoining {
		t.Fatalf("state %s", n.Status.State)
	}
	g.api.nodes["prod-server-0"] = aerolapi.Node{Alive: true, Version: "v0.7.2", SandboxesRunning: 0,
		Capacity: aerolapi.Capacity{CPUBudget: 4, ReservedCPU: 1, MemoryBudgetMB: 4096, ReservedMemoryMB: 1024}}
	g.reconcile("prod-server-0")
	n := g.node("prod-server-0")
	if n.Status.State != v1.StateServing || n.Status.Version != "v0.7.2" || n.Status.FreeCPU != "3.0" || n.Status.FreeMemory != "3072Mi" {
		t.Fatalf("serving status = %+v", n.Status)
	}
	// Gossip loses it: suspect. It restarts: restarting.
	g.now = g.now.Add(2 * time.Minute)
	g.api.nodes["prod-server-0"] = aerolapi.Node{Alive: false}
	g.reconcile("prod-server-0")
	if n := g.node("prod-server-0"); n.Status.State != v1.StateSuspect {
		t.Fatalf("state %s", n.Status.State)
	}
	g.api.nodes["prod-server-0"] = aerolapi.Node{Alive: true, Restarting: true}
	g.reconcile("prod-server-0")
	if n := g.node("prod-server-0"); n.Status.State != v1.StateRestarting {
		t.Fatalf("state %s", n.Status.State)
	}
}

func TestNodeWorkerJoinsWithItsOwnToken(t *testing.T) {
	c := bootstrapped(testCluster())
	g := newNodeRig(t, c, node("prod-general-aaaaa", v1.RoleWorker, "general", "z-a"), machine("m1"))
	g.api.mintErr = errors.New("leader down")
	g.reconcile("prod-general-aaaaa")
	if n := g.node("prod-general-aaaaa"); n.Status.State != v1.StatePending || !strings.Contains(n.Status.Reason, "join token") {
		t.Fatalf("no token: %+v", n.Status)
	}
	if g.pod(testWorkerNS, "prod-general-aaaaa") != nil {
		t.Fatal("pod made without its token")
	}
	g.api.mintErr = nil
	g.reconcile("prod-general-aaaaa")
	var s corev1.Secret
	if err := g.cl.Get(context.Background(), types.NamespacedName{Namespace: testWorkerNS, Name: "prod-general-aaaaa-join"}, &s); err != nil {
		t.Fatal(err)
	}
	if string(s.Data["token"]) != "tok-worker" || string(s.Data["join_url"]) != "https://s0:7003" || len(g.api.minted) != 1 {
		t.Fatalf("join secret = %v minted %v", s.Data, g.api.minted)
	}
	p := g.pod(testWorkerNS, "prod-general-aaaaa")
	if p == nil || len(p.OwnerReferences) != 0 {
		t.Fatalf("worker pod = %+v (no owner reference across namespaces)", p)
	}
	g.running(p, "m1", true)
	g.api.nodes["prod-general-aaaaa"] = aerolapi.Node{Alive: true, SandboxesRunning: 4}
	g.reconcile("prod-general-aaaaa")
	if n := g.node("prod-general-aaaaa"); n.Status.State != v1.StateServing || n.Status.Sandboxes != 4 {
		t.Fatalf("status = %+v", n.Status)
	}
	// The spent token is gone.
	if err := g.cl.Get(context.Background(), types.NamespacedName{Namespace: testWorkerNS, Name: "prod-general-aaaaa-join"}, &s); !apierrors.IsNotFound(err) {
		t.Fatalf("join secret after serving: %v", err)
	}
	// Spent once: later passes over a serving node send no delete at all
	// (at 2,000 nodes that is a delete per node per pass).
	deletes := 0
	g.r.Client = interceptor.NewClient(g.cl.(client.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				deletes++
			}
			return c.Delete(ctx, obj, opts...)
		},
	})
	g.reconcile("prod-general-aaaaa")
	if deletes != 0 {
		t.Fatalf("%d Secret deletes on a pass after the token was spent", deletes)
	}
	g.r.Client = g.cl
	// Cordoned in AerolVM: draining.
	g.api.nodes["prod-general-aaaaa"] = aerolapi.Node{Alive: true, Drained: true}
	g.reconcile("prod-general-aaaaa")
	if n := g.node("prod-general-aaaaa"); n.Status.State != v1.StateDraining {
		t.Fatalf("state %s", n.Status.State)
	}
}

// A worker whose setup keeps failing is ended and replaced; a server
// stays Failed for a person.
func TestNodeSetupFailing(t *testing.T) {
	c := bootstrapped(testCluster())
	g := newNodeRig(t, c, node("prod-general-bbbbb", v1.RoleWorker, "general", "z-a"), node("prod-server-1", v1.RoleServer, "", "z-b"), machine("m1"))
	g.reconcile("prod-general-bbbbb")
	g.reconcile("prod-server-1")
	for _, ref := range []types.NamespacedName{{Namespace: testWorkerNS, Name: "prod-general-bbbbb"}, {Namespace: testNS, Name: "prod-server-1"}} {
		p := g.pod(ref.Namespace, ref.Name)
		p.Spec.NodeName = "m1"
		if err := g.cl.Update(context.Background(), p); err != nil {
			t.Fatal(err)
		}
		p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: SetupContainer,
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff", Message: "join refused"}}}}
		if err := g.cl.Status().Update(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	g.now = time.Now().Add(10 * time.Minute)
	g.reconcile("prod-general-bbbbb")
	if n := g.node("prod-general-bbbbb"); n.Status.State != v1.StateFailed || g.pod(testWorkerNS, "prod-general-bbbbb") != nil {
		t.Fatalf("worker: %+v", n.Status)
	}
	g.reconcile("prod-server-1")
	if n := g.node("prod-server-1"); n.Status.State != v1.StateFailed || g.pod(testNS, "prod-server-1") == nil {
		t.Fatalf("server: %+v", n.Status)
	}
}

// Its turn in the rollout: the agent (and edge) image swaps in place.
func TestNodeSwapsAgentOnItsTurn(t *testing.T) {
	c := bootstrapped(testCluster())
	n := node("prod-general-ccccc", v1.RoleWorker, "general", "z-a")
	g := newNodeRig(t, c, n, machine("m1"))
	g.reconcile(n.Name)
	p := g.pod(testWorkerNS, n.Name)
	g.running(p, "m1", true)
	g.api.nodes[n.Name] = aerolapi.Node{Alive: true}
	cur := g.node(n.Name)
	cur.Annotations = map[string]string{AnnotationAgentVersion: "v0.7.3"}
	if err := g.cl.Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	g.reconcile(n.Name)
	p = g.pod(testWorkerNS, n.Name)
	if p.Spec.Containers[1].Image != "registry.example/aerol/aerolvm:v0.7.3" || p.Spec.Containers[2].Image != "registry.example/aerol/aerolvm-edge:v0.7.3" {
		t.Fatalf("images %s %s", p.Spec.Containers[1].Image, p.Spec.Containers[2].Image)
	}
	if p.Spec.Containers[0].Image != "registry.example/aerol/aerolvm-runtime:v0.7.2" {
		t.Fatal("the runtime container's image changed in place: every sandbox would end")
	}
	if got := g.node(n.Name); got.Status.AgentImageID != "sha256:old" {
		t.Fatalf("old image id not kept: %+v", got.Status)
	}
	// Again: already swapped, nothing to do.
	g.reconcile(n.Name)
}

// Maintenance mode (C22): the server's pod is made again holding its
// volume, and back as a server when the annotation goes.
func TestNodeServerMaintenance(t *testing.T) {
	c := bootstrapped(testCluster())
	n := node("prod-server-2", v1.RoleServer, "", "z-c")
	g := newNodeRig(t, c, n)
	g.reconcile(n.Name)
	if g.pod(testNS, n.Name) == nil {
		t.Fatal("no pod")
	}
	set := func(on bool) {
		cur := g.node(n.Name)
		cur.Annotations = map[string]string{}
		if on {
			cur.Annotations[v1.AnnotationMaintenance] = "true"
		}
		if err := g.cl.Update(context.Background(), cur); err != nil {
			t.Fatal(err)
		}
	}
	set(true)
	g.reconcile(n.Name) // deletes the server pod
	if g.pod(testNS, n.Name) != nil || g.node(n.Name).Status.State != v1.StateMaintenance {
		t.Fatal("server pod not replaced for maintenance")
	}
	g.reconcile(n.Name) // makes the held pod
	p := g.pod(testNS, n.Name)
	if p == nil || p.Labels[v1.AnnotationMaintenance] != "true" || len(p.Spec.InitContainers) != 0 {
		t.Fatalf("held pod = %+v", p)
	}
	g.reconcile(n.Name)
	if g.node(n.Name).Status.State != v1.StateMaintenance {
		t.Fatal("not held")
	}
	set(false)
	g.reconcile(n.Name)
	if g.pod(testNS, n.Name) != nil {
		t.Fatal("held pod kept after maintenance")
	}
	g.reconcile(n.Name)
	if p := g.pod(testNS, n.Name); p == nil || p.Labels[v1.AnnotationMaintenance] == "true" {
		t.Fatal("server not back")
	}
}

// A worker's machine is gone (its Node deleted): the leader hears it, and
// once failover is done the node leaves and the AerolNode goes.
func TestNodeMachineGoneThenRemoved(t *testing.T) {
	c := bootstrapped(testCluster())
	n := node("prod-general-ddddd", v1.RoleWorker, "general", "z-a")
	g := newNodeRig(t, c, n, machine("m1"))
	g.reconcile(n.Name)
	p := g.pod(testWorkerNS, n.Name)
	g.running(p, "m-gone", true)
	before := testutilCounter(workerPodsLost)
	g.reconcile(n.Name)
	if len(g.api.gone) != 1 || g.node(n.Name).Status.State != v1.StateSuspect || testutilCounter(workerPodsLost) != before+1 {
		t.Fatalf("gone %v state %s", g.api.gone, g.node(n.Name).Status.State)
	}
	// The pod goes with its Node.
	if err := g.cl.Delete(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	g.api.nodes[n.Name] = aerolapi.Node{Alive: true}
	g.reconcile(n.Name) // partition: still alive in gossip, nothing removed
	if len(g.api.deleted) != 0 {
		t.Fatal("deleted a live node")
	}
	g.api.nodes[n.Name] = aerolapi.Node{Alive: false, SandboxesOwned: 3}
	g.reconcile(n.Name)
	if g.node(n.Name).Status.State != v1.StateDead {
		t.Fatalf("state %s", g.node(n.Name).Status.State)
	}
	g.api.nodes[n.Name] = aerolapi.Node{Alive: false}
	g.reconcile(n.Name)
	if len(g.api.deleted) != 1 || g.node(n.Name).Status.State != v1.StateRemoved {
		t.Fatalf("deleted %v state %s", g.api.deleted, g.node(n.Name).Status.State)
	}
	g.reconcile(n.Name)
	if g.node(n.Name) != nil {
		t.Fatal("removed AerolNode kept")
	}
}

// The machine is cordoned: the worker decommissions, waits its drain
// window, moves what it can, and leaves.
func TestNodeDecommission(t *testing.T) {
	c := bootstrapped(testCluster())
	short := metav1.Duration{Duration: time.Minute}
	c.Spec.WorkerPools[0].Decommission = v1.DecommissionSpec{DrainWindow: &short}
	n := node("prod-general-eeeee", v1.RoleWorker, "general", "z-a")
	m := machine("m1")
	g := newNodeRig(t, c, n, m)
	g.reconcile(n.Name)
	p := g.pod(testWorkerNS, n.Name)
	g.running(p, "m1", true)
	g.api.nodes[n.Name] = aerolapi.Node{Alive: true, SandboxesOwned: 4}
	m.Spec.Unschedulable = true
	if err := g.cl.Update(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	g.reconcile(n.Name) // trigger
	if g.node(n.Name).Annotations[v1.AnnotationDecommission] != "true" {
		t.Fatal("a cordoned machine did not start a decommission")
	}
	g.reconcile(n.Name) // drain window
	got := g.node(n.Name)
	if got.Status.State != v1.StateDraining || got.Status.Decommission == nil || len(g.api.cordoned) != 1 {
		t.Fatalf("draining = %+v cordoned %v", got.Status, g.api.cordoned)
	}
	passes := 0
	g.api.evacuate = func(id string, req aerolapi.EvacuateRequest) (aerolapi.EvacuateResult, error) {
		passes++
		if passes == 1 {
			return aerolapi.EvacuateResult{Moved: []string{"a", "b"}, RemainingMovable: 1, Remaining: 1}, nil
		}
		return aerolapi.EvacuateResult{Moved: []string{"c"}, Remaining: 1, Stopped: 1, Done: !req.StopRemaining && false || req.StopRemaining}, nil
	}
	g.now = g.now.Add(2 * time.Minute)
	g.reconcile(n.Name)
	if got := g.node(n.Name); got.Status.State != v1.StateDecommissioning || got.Status.Decommission.Moved != 2 || got.Status.Decommission.Remaining != 2 {
		t.Fatalf("pass 1 = %+v", got.Status)
	}
	g.now = g.now.Add(time.Hour) // past the deadline: stop the rest
	g.reconcile(n.Name)
	if g.pod(testWorkerNS, n.Name) != nil {
		t.Fatal("pod kept after the decommission ended")
	}
	got = g.node(n.Name)
	if got.Status.State != v1.StateRemoved || !got.Status.Decommission.NodeDeleted || got.Status.Decommission.Moved != 3 || len(g.api.deleted) != 1 {
		t.Fatalf("after = %+v deleted %v", got.Status, g.api.deleted)
	}
}

// A worker whose pod never got a machine, decommissioned by the scaler (it
// is not needed once its zone serves again): it never joined, so it owns
// nothing and does not sit out the drain window.
func TestDecommissionOfAWorkerThatNeverJoined(t *testing.T) {
	c := bootstrapped(testCluster())
	long := metav1.Duration{Duration: time.Hour}
	c.Spec.WorkerPools[0].Decommission = v1.DecommissionSpec{DrainWindow: &long}
	n := node("prod-general-ggggg", v1.RoleWorker, "general", "z-a")
	g := newNodeRig(t, c, n)
	g.reconcile(n.Name) // its pod, which no machine takes
	if g.pod(testWorkerNS, n.Name) == nil {
		t.Fatal("no pod")
	}
	got := g.node(n.Name)
	got.Annotations = map[string]string{v1.AnnotationDecommission: "true"}
	if err := g.cl.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	g.reconcile(n.Name)
	if g.pod(testWorkerNS, n.Name) != nil {
		t.Fatal("pod kept: the decommission waited out the drain window for a worker that owns nothing")
	}
	if got := g.node(n.Name); got.Status.State != v1.StateRemoved {
		t.Fatalf("state = %s (%s), want Removed in one pass", got.Status.State, got.Status.Reason)
	}
}

// The webhook's twin: deleting an AerolNode cleans up its worker pod and
// token in the worker namespace, which owner references cannot reach.
func TestNodeCleanupAcrossNamespaces(t *testing.T) {
	c := bootstrapped(testCluster())
	n := node("prod-general-fffff", v1.RoleWorker, "general", "z-a")
	n.Finalizers = []string{"test/hold"}
	g := newNodeRig(t, c, n)
	g.reconcile(n.Name)
	if g.pod(testWorkerNS, n.Name) == nil {
		t.Fatal("no pod")
	}
	if err := g.cl.Delete(context.Background(), g.node(n.Name)); err != nil {
		t.Fatal(err)
	}
	g.reconcile(n.Name)
	if g.pod(testWorkerNS, n.Name) != nil {
		t.Fatal("worker pod left behind")
	}
}

// A worker AerolNode deleted outright (no finalizer held it): its pod and
// join Secret in the worker namespace, where no owner reference reaches,
// go with it. Pods of nodes that still exist are left alone, even while
// the cache has not seen them yet.
func TestNodeSweepsAGoneWorker(t *testing.T) {
	c := bootstrapped(testCluster())
	n := node("prod-general-hhhhh", v1.RoleWorker, "general", "z-a")
	g := newNodeRig(t, c, n)
	g.reconcile(n.Name)
	if g.pod(testWorkerNS, n.Name) == nil {
		t.Fatal("no pod")
	}
	var s corev1.Secret
	if err := g.cl.Get(context.Background(), types.NamespacedName{Namespace: testWorkerNS, Name: JoinSecret(n.Name)}, &s); err != nil {
		t.Fatal(err)
	}

	// The cache does not have the node yet; the API server does.
	behind := newFakeClient(t)
	g.r.Client = interceptor.NewClient(g.cl.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*v1.AerolNode); ok {
				return behind.Get(ctx, key, obj, opts...)
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	g.r.Reader = g.cl
	g.reconcile(n.Name)
	if g.pod(testWorkerNS, n.Name) == nil {
		t.Fatal("a live node's pod was swept on a stale cache")
	}
	g.r.Client, g.r.Reader = g.cl, nil

	if err := g.cl.Delete(context.Background(), g.node(n.Name)); err != nil {
		t.Fatal(err)
	}
	g.reconcile(n.Name)
	if g.pod(testWorkerNS, n.Name) != nil {
		t.Fatal("worker pod left behind")
	}
	if err := g.cl.Get(context.Background(), types.NamespacedName{Namespace: testWorkerNS, Name: JoinSecret(n.Name)}, &s); !apierrors.IsNotFound(err) {
		t.Fatalf("join secret left behind: %v", err)
	}
	g.reconcile(n.Name) // nothing left: a no-op

	// A pod by that name that is not this node's is not touched.
	other := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "prod-general-iiiii", Namespace: testWorkerNS}}
	if err := g.cl.Create(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	g.reconcile("prod-general-iiiii")
	if g.pod(testWorkerNS, "prod-general-iiiii") == nil {
		t.Fatal("swept a pod the operator did not make")
	}
	// One namespace: owner references do it.
	g.r.WorkerNamespace = testNS
	if err := g.r.sweepGone(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
}

func TestDecommissionDefaultsAndDrift(t *testing.T) {
	if drainWindow(nil) != defaultDrainWindow || drainWindow(&v1.WorkerPoolSpec{Provisioner: "eks-managed"}) != eksManagedDrain {
		t.Fatal("drain window defaults")
	}
	if decomDeadline(nil) != defaultDecomDeadline {
		t.Fatal("deadline default")
	}
	c := bootstrapped(testCluster())
	n := node("prod-general-ggggg", v1.RoleWorker, "general", "z-a")
	m7 := machine("m7")
	m7.Labels[karpenterNodePoolLabel] = "general"
	g := newNodeRig(t, c, n, m7)
	nc := &unstructured.Unstructured{}
	nc.SetGroupVersionKind(nodeClaimGVK)
	nc.SetName("nc-1")
	_ = unstructured.SetNestedField(nc.Object, "m7", "status", "nodeName")
	_ = unstructured.SetNestedSlice(nc.Object, []any{map[string]any{"type": "Drifted", "status": "True"}}, "status", "conditions")
	if err := g.cl.Create(context.Background(), nc); err != nil {
		t.Skipf("the fake client cannot hold a NodeClaim: %v", err)
	}
	m8 := machine("m8")
	m8.Labels[karpenterNodePoolLabel] = "general"
	if !g.r.nodeClaimDrifted(context.Background(), m7) || g.r.nodeClaimDrifted(context.Background(), m8) {
		t.Fatal("drift not read")
	}
	// A machine Karpenter did not make (no NodePool label) has no NodeClaim:
	// it is not read, even when one names it.
	reads := 0
	g.r.Client = interceptor.NewClient(g.cl.(client.WithWatch), interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*unstructured.UnstructuredList); ok {
				reads++
			}
			return c.List(ctx, list, opts...)
		},
	})
	if g.r.nodeClaimDrifted(context.Background(), machine("m7")) || reads != 0 {
		t.Fatalf("an unlabeled machine read NodeClaims (%d reads)", reads)
	}
	g.r.Client = g.cl
	g.r.retireMachine(context.Background(), "m7")
	if g.r.nodeClaim(context.Background(), "m7") != nil {
		t.Fatal("NodeClaim not deleted")
	}
}

// A worker whose machine fails the preflight (P10) stays out of service with
// the check's own reason, keeps its pod (and so its machine), and serves
// once a retry passes.
func TestNodePreflightFailed(t *testing.T) {
	c := bootstrapped(testCluster())
	g := newNodeRig(t, c, node("prod-general-ccccc", v1.RoleWorker, "general", "z-a"), machine("m1"))
	g.reconcile("prod-general-ccccc")
	p := g.pod(testWorkerNS, "prod-general-ccccc")
	p.Spec.NodeName = "m1"
	if err := g.cl.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	why := "preflight failed: br_netfilter: the br_netfilter kernel module is not loaded (fix: load it)"
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: PreflightContainer,
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
		LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1,
			Message: "CHECK  STATUS  DETAIL\nbr_netfilter  fail  not loaded\n" + why + "\n"}}}}
	if err := g.cl.Status().Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	g.reconcile("prod-general-ccccc")
	if n := g.node("prod-general-ccccc"); n.Status.State != v1.StateFailed || n.Status.Reason != why {
		t.Fatalf("status = %s %q, want Failed %q", n.Status.State, n.Status.Reason, why)
	}
	if g.pod(testWorkerNS, "prod-general-ccccc") == nil {
		t.Fatal("the pod holding the bad machine was deleted")
	}
	// The machine is fixed: the kubelet's retry passes and the agent runs.
	p = g.pod(testWorkerNS, "prod-general-ccccc")
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: PreflightContainer,
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}}}
	if err := g.cl.Status().Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	g.running(p, "m1", true)
	g.api.nodes["prod-general-ccccc"] = aerolapi.Node{Alive: true, Version: "v0.7.2"}
	g.reconcile("prod-general-ccccc")
	if n := g.node("prod-general-ccccc"); n.Status.State != v1.StateServing {
		t.Fatalf("after the fix: %s %q", n.Status.State, n.Status.Reason)
	}
}

func TestPreflightFailedReason(t *testing.T) {
	term := func(code int32, msg string) *corev1.ContainerStateTerminated {
		return &corev1.ContainerStateTerminated{ExitCode: code, Message: msg}
	}
	long := strings.Repeat("x", 2000)
	cases := []struct {
		name string
		cs   corev1.ContainerStatus
		want string
	}{
		{name: "failed now", cs: corev1.ContainerStatus{Name: PreflightContainer, State: corev1.ContainerState{Terminated: term(1, "a\nlast line\n")}}, want: "last line"},
		{name: "no message", cs: corev1.ContainerStatus{Name: PreflightContainer, State: corev1.ContainerState{Terminated: term(2, "")}}, want: "preflight failed (exit 2)"},
		{name: "passed", cs: corev1.ContainerStatus{Name: PreflightContainer, State: corev1.ContainerState{Terminated: term(0, "")}}},
		{name: "running again after a failure", cs: corev1.ContainerStatus{Name: PreflightContainer,
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}, LastTerminationState: corev1.ContainerState{Terminated: term(1, "old")}}},
		{name: "not started", cs: corev1.ContainerStatus{Name: PreflightContainer}},
		{name: "another container", cs: corev1.ContainerStatus{Name: SetupContainer, State: corev1.ContainerState{Terminated: term(1, "x")}}},
		{name: "kept short", cs: corev1.ContainerStatus{Name: PreflightContainer, State: corev1.ContainerState{Terminated: term(1, long)}}, want: long[:1024]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{Status: corev1.PodStatus{InitContainerStatuses: []corev1.ContainerStatus{tc.cs}}}
			if got := preflightFailed(pod); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Without a leader no join token can be minted. A server pod made again
// keeps its identity on its disk, so it is made without one (its token
// volume optional); a worker waits for its token. The maintenance pod, how
// a cluster that lost quorum is repaired, never needs one.
func TestNodeServersComeBackWithoutQuorum(t *testing.T) {
	c := bootstrapped(testCluster())
	srv, wrk := node("prod-server-1", v1.RoleServer, "", "z-b"), node("prod-general-eeeee", v1.RoleWorker, "general", "z-a")
	g := newNodeRig(t, c, srv, wrk, machine("m1"))
	g.api.mintErr = errors.New("no leader")

	g.reconcile(srv.Name)
	p := g.pod(testNS, srv.Name)
	if p == nil {
		t.Fatal("a server pod was not made without a token")
	}
	var join *corev1.SecretVolumeSource
	for _, v := range p.Spec.Volumes {
		if v.Name == JoinVolume {
			join = v.Secret
		}
	}
	if join == nil || join.Optional == nil || !*join.Optional {
		t.Fatalf("server join volume = %+v, want optional", join)
	}
	g.reconcile(wrk.Name)
	if g.pod(testWorkerNS, wrk.Name) != nil || g.node(wrk.Name).Status.State != v1.StatePending {
		t.Fatalf("a worker was made without a token: %+v", g.node(wrk.Name).Status)
	}

	// Its setup failed (no identity on the disk): a token is minted once a
	// leader is back, for the optional volume.
	p.Spec.NodeName = "m1"
	if err := g.cl.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: SetupContainer,
		LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 2}},
		State:                corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}
	if err := g.cl.Status().Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	g.reconcile(srv.Name) // still no leader: nothing to mint, no error
	var s corev1.Secret
	if err := g.cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: JoinSecret(srv.Name)}, &s); !apierrors.IsNotFound(err) {
		t.Fatalf("a token without a leader: %v", err)
	}
	g.api.mintErr = nil
	g.reconcile(srv.Name)
	if err := g.cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: JoinSecret(srv.Name)}, &s); err != nil {
		t.Fatalf("no token minted once a leader is back: %v", err)
	}
}

func TestNodeMaintenanceWithoutQuorum(t *testing.T) {
	c := bootstrapped(testCluster())
	n := node("prod-server-2", v1.RoleServer, "", "z-c")
	n.Annotations = map[string]string{v1.AnnotationMaintenance: "true"}
	g := newNodeRig(t, c, n)
	g.api.mintErr = errors.New("no leader")
	g.reconcile(n.Name)
	p := g.pod(testNS, n.Name)
	if p == nil || p.Labels[v1.AnnotationMaintenance] != "true" || len(p.Spec.InitContainers) != 0 {
		t.Fatalf("held pod without a leader = %+v", p)
	}
}

// A pod made again during an upgrade keeps the version last ordered for its
// node, so the image swap that follows never moves it back down; a node
// with no turn yet takes spec.version.
func TestNodePodMadeAgainKeepsItsVersion(t *testing.T) {
	c := bootstrapped(testCluster()) // spec.version v0.7.2
	held := node("prod-general-fffff", v1.RoleWorker, "general", "z-a")
	held.Annotations = map[string]string{AnnotationAgentVersion: "v0.7.1"}
	fresh := node("prod-general-ggggg", v1.RoleWorker, "general", "z-b")
	g := newNodeRig(t, c, held, fresh, machine("m1"))
	g.reconcile(held.Name)
	g.reconcile(fresh.Name)
	image := func(name string) string {
		p := g.pod(testWorkerNS, name)
		return p.Spec.Containers[containerIndex(p.Spec.Containers, AgentContainer)].Image
	}
	if got := image(held.Name); got != "registry.example/aerol/aerolvm:v0.7.1" {
		t.Fatalf("pod made before its turn runs %s", got)
	}
	if got := image(fresh.Name); got != "registry.example/aerol/aerolvm:v0.7.2" {
		t.Fatalf("a new node runs %s", got)
	}
	p := g.pod(testWorkerNS, held.Name)
	g.running(p, "m1", false)
	g.reconcile(held.Name) // swapAgent with the same version: no patch back
	if got := image(held.Name); got != "registry.example/aerol/aerolvm:v0.7.1" || g.node(held.Name).Status.State == v1.StateRestarting {
		t.Fatalf("swapped to %s, state %s", got, g.node(held.Name).Status.State)
	}
}

// A pod the scheduler cannot place says why on its AerolNode, so `kubectl
// get aerolnodes` shows "Insufficient cpu" instead of a bare Pending.
func TestNodePendingSaysWhy(t *testing.T) {
	c := bootstrapped(testCluster())
	g := newNodeRig(t, c, node("prod-general-jjjjj", v1.RoleWorker, "general", "z-a"))
	g.reconcile("prod-general-jjjjj") // makes the pod
	g.reconcile("prod-general-jjjjj")
	if n := g.node("prod-general-jjjjj"); n.Status.State != v1.StatePending || n.Status.Reason != "waiting for a machine" {
		t.Fatalf("before the scheduler says anything: %+v", n.Status)
	}
	p := g.pod(testWorkerNS, "prod-general-jjjjj")
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonUnschedulable,
		Message: "0/6 nodes are available: 1 Insufficient cpu, 5 node(s) didn't match Pod's node affinity/selector."}}
	if err := g.cl.Status().Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	g.reconcile("prod-general-jjjjj")
	if n := g.node("prod-general-jjjjj"); n.Status.State != v1.StatePending || !strings.Contains(n.Status.Reason, "Insufficient cpu") {
		t.Fatalf("unschedulable pod: %+v", n.Status)
	}
	long := &corev1.Pod{Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse,
		Reason: corev1.PodReasonUnschedulable, Message: strings.Repeat("x", 500)}}}}
	if got := waitingForMachine(long); len(got) > 300 || !strings.HasSuffix(got, "...") {
		t.Fatalf("a long message is not cut: %d chars", len(got))
	}
}

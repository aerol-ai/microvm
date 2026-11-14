package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/operator/internal/aerolapi"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

func clusterRig(t *testing.T, c *v1.AerolCluster, objs ...client.Object) (*ClusterReconciler, *fakeAPI, client.Client) {
	t.Helper()
	cl := newFakeClient(t, append([]client.Object{c}, objs...)...)
	api := newFakeAPI()
	return &ClusterReconciler{Client: cl, Scheme: cl.Scheme(), Recorder: record.NewFakeRecorder(100), API: api.factory, Now: time.Now}, api, cl
}

func reconcileCluster(t *testing.T, r *ClusterReconciler) *v1.AerolCluster {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNS, Name: "prod"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var c v1.AerolCluster
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: "prod"}, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func nodesByRole(t *testing.T, cl client.Client) map[string][]v1.AerolNode {
	t.Helper()
	var list v1.AerolNodeList
	if err := cl.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	out := map[string][]v1.AerolNode{}
	for _, n := range list.Items {
		out[n.Spec.Role] = append(out[n.Spec.Role], n)
	}
	for _, v := range out {
		sort.Slice(v, func(i, j int) bool { return v[i].Name < v[j].Name })
	}
	return out
}

// A new cluster: server 0 alone until it leads, then the rest.
func TestClusterBootstrapThenEverything(t *testing.T) {
	r, api, cl := clusterRig(t, testCluster())
	api.ready = false
	c := reconcileCluster(t, r)
	nodes := nodesByRole(t, cl)
	if len(nodes[v1.RoleServer]) != 1 || nodes[v1.RoleServer][0].Name != "prod-server-0" || len(nodes[v1.RoleGateway]) != 0 {
		t.Fatalf("before bootstrap: %v", nodes)
	}
	if c.Status.Phase != "Bootstrapping" || meta.IsStatusConditionTrue(c.Status.Conditions, CondBootstrapped) {
		t.Fatalf("status = %+v", c.Status)
	}
	var s corev1.Secret
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: "prod-admin"}, &s); err != nil || len(s.Data["token"]) != 40 {
		t.Fatalf("admin secret = %v %v", s.Data, err)
	}
	tok := string(s.Data["token"])
	for _, name := range []string{"prod-servers", "prod-api", "prod-gateway"} {
		var svc corev1.Service
		if err := cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: name}, &svc); err != nil {
			t.Fatalf("service %s: %v", name, err)
		}
		if name == "prod-servers" && (!svc.Spec.PublishNotReadyAddresses || svc.Spec.ClusterIP != corev1.ClusterIPNone) {
			t.Fatalf("headless = %+v", svc.Spec)
		}
		if name == "prod-gateway" && (svc.Spec.Type != corev1.ServiceTypeLoadBalancer || svc.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal) {
			t.Fatalf("gateway service = %+v", svc.Spec)
		}
	}

	// Adopt fails once: retried, nothing else made.
	api.ready, api.adoptErr = true, errors.New("not leader yet")
	reconcileCluster(t, r)
	api.adoptErr = nil
	c = reconcileCluster(t, r)
	if !meta.IsStatusConditionTrue(c.Status.Conditions, CondBootstrapped) || api.adopted != 2 {
		t.Fatalf("bootstrapped = %v, adopted %d", c.Status.Conditions, api.adopted)
	}
	c = reconcileCluster(t, r)
	nodes = nodesByRole(t, cl)
	zones := func(ns []v1.AerolNode) string {
		var z []string
		for _, n := range ns {
			z = append(z, n.Spec.Zone)
		}
		sort.Strings(z)
		return strings.Join(z, ",")
	}
	if len(nodes[v1.RoleServer]) != 3 || zones(nodes[v1.RoleServer]) != "z-a,z-b,z-c" {
		t.Fatalf("servers = %v", nodes[v1.RoleServer])
	}
	if len(nodes[v1.RoleGateway]) != 3 || zones(nodes[v1.RoleGateway]) != "z-a,z-b,z-c" {
		t.Fatalf("gateways = %v", nodes[v1.RoleGateway])
	}
	if len(nodes[v1.RoleWorker]) != 3 || zones(nodes[v1.RoleWorker]) != "z-a,z-b,z-c" {
		t.Fatalf("workers = %v", nodes[v1.RoleWorker])
	}
	var pvcs corev1.PersistentVolumeClaimList
	if err := cl.List(context.Background(), &pvcs); err != nil || len(pvcs.Items) != 3 {
		t.Fatalf("pvcs = %d %v", len(pvcs.Items), err)
	}
	// The token is made once.
	reconcileCluster(t, r)
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: "prod-admin"}, &s); err != nil || string(s.Data["token"]) != tok {
		t.Fatal("admin token changed")
	}
	if c.Status.Servers.Desired != 3 {
		t.Fatalf("server tier = %+v", c.Status.Servers)
	}
}

func TestRefuseSpec(t *testing.T) {
	for _, tc := range []struct {
		edit func(c *v1.AerolCluster)
		want string
	}{
		{func(c *v1.AerolCluster) { c.Spec.Security.ExternalCA = &v1.ExternalCASpec{} }, "externalCA"},
		{func(c *v1.AerolCluster) { c.Spec.Zones = nil }, "zones"},
		{func(c *v1.AerolCluster) { c.Spec.Servers.Count = 4 }, "3 or 5"},
		{func(c *v1.AerolCluster) { c.Spec.WorkerPools = append(c.Spec.WorkerPools, c.Spec.WorkerPools[0]) }, "twice"},
		{func(c *v1.AerolCluster) { c.Spec.WorkerPools[0].MinWorkers = 20 }, "above maxWorkers"},
		{func(c *v1.AerolCluster) { c.Spec.Gateways.MinReplicas, c.Spec.Gateways.MaxReplicas = 6, 4 }, "maxReplicas (4) is below the 6 gateways"},
		{func(c *v1.AerolCluster) { c.Spec.Gateways.MinReplicas, c.Spec.Gateways.MaxReplicas = 1, 2 }, "maxReplicas (2) is below the 3 gateways"},
		{func(c *v1.AerolCluster) { c.Spec.Federation = &v1.FederationSpec{} }, "idKeySecret.name is empty"},
		{fed(map[string]string{"0": "https://a.example.com"}), "0 is not a cell number"},
		{fed(map[string]string{"256": "https://a.example.com"}), "256 is not a cell number"},
		{fed(map[string]string{"two": "https://a.example.com"}), "two is not a cell number"},
		{fed(map[string]string{"3": "https://a.example.com"}), "3 is this cell"},
		{fed(map[string]string{"2": "ftp://a.example.com"}), "2 is not an http(s) address"},
		{fed(map[string]string{"2": "https://"}), "2 is not an http(s) address"},
	} {
		c := testCluster()
		tc.edit(c)
		if got := refuseSpec(c); !strings.Contains(got, tc.want) {
			t.Fatalf("refuseSpec = %q, want %q", got, tc.want)
		}
	}
	if got := refuseSpec(federated(testCluster())); got != "" {
		t.Fatalf("a good federation is refused: %s", got)
	}
	capped := testCluster()
	capped.Spec.Gateways.MaxReplicas = 3
	if got := refuseSpec(capped); got != "" {
		t.Fatalf("maxReplicas equal to the gateways kept is refused: %s", got)
	}
	c := testCluster()
	c.Spec.Security.ExternalCA = &v1.ExternalCASpec{}
	r, _, _ := clusterRig(t, c)
	got := reconcileCluster(t, r)
	if got.Status.Phase != "Refused" || !meta.IsStatusConditionTrue(got.Status.Conditions, CondRefused) {
		t.Fatalf("refused status = %+v", got.Status)
	}
}

func bootstrapped(c *v1.AerolCluster) *v1.AerolCluster {
	meta.SetStatusCondition(&c.Status.Conditions, metavCond(CondBootstrapped))
	return c
}

// A Gateway API Gateway in front: a plain Service, no load balancer.
func TestGatewayServiceBehindGatewayRef(t *testing.T) {
	c := testCluster()
	c.Spec.Gateways.GatewayRef = &v1.GatewayRef{Name: "bank-gw"}
	r, api, cl := clusterRig(t, bootstrapped(c))
	api.membersErr = errors.New("down")
	reconcileCluster(t, r)
	var svc corev1.Service
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: "prod-gateway"}, &svc); err != nil || svc.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Fatalf("gateway service = %+v %v", svc.Spec, err)
	}
}

// The gateway Service's ports follow the edge: Caddy's 443 and 80 with it,
// sandboxd's API port without it (nothing listens on 443 then).
func TestGatewayServicePorts(t *testing.T) {
	names := func(svc corev1.Service) string {
		var out []string
		for _, p := range svc.Spec.Ports {
			out = append(out, fmt.Sprintf("%s:%d", p.Name, p.Port))
		}
		return strings.Join(out, ",")
	}
	for _, tc := range []struct {
		name, domain, want string
	}{
		{name: "no edge", want: "api:21212,ssh:2220"},
		{name: "edge", domain: "sandboxes.bank.example", want: "https:443,http:80,ssh:2220"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testCluster()
			c.Spec.Edge.Domain = tc.domain
			r, api, cl := clusterRig(t, bootstrapped(c))
			api.membersErr = errors.New("down")
			reconcileCluster(t, r)
			var svc corev1.Service
			if err := cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: "prod-gateway"}, &svc); err != nil {
				t.Fatal(err)
			}
			if got := names(svc); got != tc.want {
				t.Fatalf("ports = %s, want %s", got, tc.want)
			}
		})
	}
}

// A leader that refuses the rollout: the AerolCluster gets a Warning with
// its reason, and no "upgrading" event, until the rollout starts.
func TestClusterUpgradeNotStartedSaysWhy(t *testing.T) {
	c := bootstrapped(testCluster())
	r, api, cl := clusterRig(t, c)
	reconcileCluster(t, r) // makes the nodes
	var list v1.AerolNodeList
	if err := cl.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	for i := range list.Items {
		list.Items[i].Status.State, list.Items[i].Status.Version = v1.StateServing, "v0.7.1"
		if err := cl.Status().Update(context.Background(), &list.Items[i]); err != nil {
			t.Fatal(err)
		}
	}
	events := r.Recorder.(*record.FakeRecorder).Events
	drain := func() []string {
		var out []string
		for {
			select {
			case e := <-events:
				out = append(out, e)
			default:
				return out
			}
		}
	}
	drain()
	api.applyErr = errors.New("aerolvm: 400 bad_request: files has no sandboxd for linux/arm64")
	reconcileCluster(t, r)
	got := strings.Join(drain(), "\n")
	if !strings.Contains(got, "Warning UpgradeNotStarted the upgrade from v0.7.1 to v0.7.2 did not start: aerolvm: 400 bad_request: files has no sandboxd") {
		t.Fatalf("events after a refusal:\n%s", got)
	}
	if strings.Contains(got, "Normal Upgrade ") {
		t.Fatalf("an upgrading event for an upgrade that did not start:\n%s", got)
	}
	api.applyErr = nil
	reconcileCluster(t, r)
	if got := strings.Join(drain(), "\n"); !strings.Contains(got, "Normal Upgrade upgrading from v0.7.1 to v0.7.2") || strings.Contains(got, "UpgradeNotStarted") {
		t.Fatalf("events once the rollout starts:\n%s", got)
	}
}

// Upgrades: spec.version moves, the operator starts the images rollout,
// marks each node's turn, and rolls back when the version goes back.
func TestClusterUpgradeFlow(t *testing.T) {
	c := bootstrapped(testCluster())
	r, api, cl := clusterRig(t, c)
	reconcileCluster(t, r) // makes the nodes
	var list v1.AerolNodeList
	if err := cl.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	for i := range list.Items {
		list.Items[i].Status.State, list.Items[i].Status.Version = v1.StateServing, "v0.7.1"
		if err := cl.Status().Update(context.Background(), &list.Items[i]); err != nil {
			t.Fatal(err)
		}
	}
	reconcileCluster(t, r) // status.version = v0.7.1, spec v0.7.2: apply
	if strings.Join(api.applied, ",") != "v0.7.2" {
		t.Fatalf("applied = %v", api.applied)
	}

	api.rollout = &upgradewire.Rollout{ID: "r1", State: upgradewire.StateRunning, Direction: upgradewire.DirectionUpgrade,
		TargetVersion: "v0.7.2", PreviousVersion: "v0.7.1", Nodes: []upgradewire.RolloutNode{
			{NodeID: "prod-server-1", State: upgradewire.NodeUpgrading, Operator: true},
			{NodeID: "prod-server-2", State: upgradewire.NodeStaged, Operator: true},
		}}
	got := reconcileCluster(t, r)
	if got.Status.Phase != "Upgrading" || got.Status.Rollout.ID != "r1" {
		t.Fatalf("status = %+v", got.Status)
	}
	var s1, s2 v1.AerolNode
	_ = cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: "prod-server-1"}, &s1)
	_ = cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: "prod-server-2"}, &s2)
	if s1.Annotations[AnnotationAgentVersion] != "v0.7.2" || s2.Annotations[AnnotationAgentVersion] != "" {
		t.Fatalf("turns: s1 %q s2 %q", s1.Annotations[AnnotationAgentVersion], s2.Annotations[AnnotationAgentVersion])
	}
	if len(api.applied) != 1 {
		t.Fatal("applied again during the rollout")
	}

	// A third version waits; the previous one rolls back.
	got.Spec.Version = "v0.8.0"
	if err := cl.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	reconcileCluster(t, r)
	if api.rolledBack != 0 || len(api.applied) != 1 {
		t.Fatal("a third version did something mid-rollout")
	}
	got = reconcileCluster(t, r)
	got.Spec.Version = "v0.7.1"
	if err := cl.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	reconcileCluster(t, r)
	if api.rolledBack != 1 {
		t.Fatal("no rollback")
	}
	// Rolling back: nodes upgrading go to the previous version.
	api.rollout.Direction, api.rollout.State = upgradewire.DirectionRollback, upgradewire.StateRollingBack
	api.rollout.Nodes[1].State = upgradewire.NodeUpgrading
	reconcileCluster(t, r)
	_ = cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: "prod-server-2"}, &s2)
	if s2.Annotations[AnnotationAgentVersion] != "v0.7.1" {
		t.Fatalf("rollback turn: %q", s2.Annotations[AnnotationAgentVersion])
	}
	api.rolloutErr = errors.New("leader down")
	reconcileCluster(t, r) // a failed read is retried, not fatal
}

// Workers follow AerolVM's numbers: a short zone gets one more.
func TestClusterAddsWorkerWhereRoomIsShort(t *testing.T) {
	c := bootstrapped(testCluster())
	r, api, cl := clusterRig(t, c)
	reconcileCluster(t, r)
	nodes := nodesByRole(t, cl)
	for _, n := range nodes[v1.RoleWorker] {
		n := n
		n.Status.State = v1.StateServing
		if err := cl.Status().Update(context.Background(), &n); err != nil {
			t.Fatal(err)
		}
		free := 0.5
		if n.Spec.Zone == "z-a" {
			free = 0.02
		}
		api.members = append(api.members, aerolapi.Node{NodeID: n.Name, Alive: true, Capacity: aerolapi.Capacity{
			CPUBudget: 30, ReservedCPU: 30 * (1 - free), MemoryBudgetMB: 1000, ReservedMemoryMB: int(1000 * (1 - free))}})
	}
	reconcileCluster(t, r)
	byZone := map[string]int{}
	for _, n := range nodesByRole(t, cl)[v1.RoleWorker] {
		byZone[n.Spec.Zone]++
	}
	if byZone["z-a"] != 2 || byZone["z-b"] != 1 || byZone["z-c"] != 1 {
		t.Fatalf("workers by zone = %v", byZone)
	}
}

func TestClusterNotFoundAndHelpers(t *testing.T) {
	r, _, _ := clusterRig(t, testCluster())
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNS, Name: "nope"}}); err != nil {
		t.Fatal(err)
	}
	if leastZone([]string{"a", "b"}, map[string]int{"a": 2, "b": 1}) != "b" {
		t.Fatal("leastZone")
	}
	if !rolloutActive(upgradewire.StatePaused) || rolloutActive(upgradewire.StateDone) {
		t.Fatal("rolloutActive")
	}
	if apiURL(testCluster()) != "http://prod-api.aerolvm-system.svc:21212" {
		t.Fatal(apiURL(testCluster()))
	}
}

// The sandbox-link certificate reaches the worker namespace, its
// certificate and key only (C25): no other key (a DNS token) follows it.
func TestClusterCopiesEdgeCertificate(t *testing.T) {
	c := bootstrapped(testCluster())
	c.Spec.Edge = v1.EdgeSpec{Domain: "sbx.example.com", TLSSecret: "aerolvm-edge-tls"}
	src := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "aerolvm-edge-tls", Namespace: testNS},
		Data: map[string][]byte{"tls.crt": []byte("CERT"), "tls.key": []byte("KEY"), "dns-token": []byte("secret")}}
	r, api, cl := clusterRig(t, c)
	r.WorkerNamespace = testWorkerNS
	api.membersErr = errors.New("down")
	reconcileCluster(t, r) // not issued yet: nothing to copy, no error
	if err := cl.Create(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	reconcileCluster(t, r)
	var dst corev1.Secret
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: testWorkerNS, Name: "aerolvm-edge-tls"}, &dst); err != nil {
		t.Fatal(err)
	}
	if len(dst.Data) != 2 || string(dst.Data["tls.key"]) != "KEY" || dst.Type != corev1.SecretTypeTLS {
		t.Fatalf("copy = %v (%s)", dst.Data, dst.Type)
	}
}

// The create policy's ConfigMap reaches the worker namespace, its policy
// key only, and follows a change.
func TestClusterCopiesCreatePolicy(t *testing.T) {
	c := bootstrapped(testCluster())
	c.Spec.Security.CreatePolicy = &corev1.LocalObjectReference{Name: "prod-create-policy"}
	r, api, cl := clusterRig(t, c)
	r.WorkerNamespace = testWorkerNS
	api.membersErr = errors.New("down")
	reconcileCluster(t, r) // not made yet: nothing to copy, no error
	ctx := context.Background()
	src := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "prod-create-policy", Namespace: testNS},
		Data: map[string]string{CreatePolicyKey: "version: 1\nruntimes: [gvisor]\n", "notes": "not copied"}}
	if err := cl.Create(ctx, src); err != nil {
		t.Fatal(err)
	}
	reconcileCluster(t, r)
	var dst corev1.ConfigMap
	if err := cl.Get(ctx, types.NamespacedName{Namespace: testWorkerNS, Name: "prod-create-policy"}, &dst); err != nil {
		t.Fatal(err)
	}
	if len(dst.Data) != 1 || dst.Data[CreatePolicyKey] != "version: 1\nruntimes: [gvisor]\n" {
		t.Fatalf("copy = %v", dst.Data)
	}
	src.Data[CreatePolicyKey] = "version: 1\nruntimes: [gvisor]\nallow_gpu: false\n"
	if err := cl.Update(ctx, src); err != nil {
		t.Fatal(err)
	}
	reconcileCluster(t, r)
	if err := cl.Get(ctx, types.NamespacedName{Namespace: testWorkerNS, Name: "prod-create-policy"}, &dst); err != nil || !strings.Contains(dst.Data[CreatePolicyKey], "allow_gpu") {
		t.Fatalf("after a change: %v %v", dst.Data, err)
	}
}

// federated makes testCluster (cell 3) one of three cells.
func federated(c *v1.AerolCluster) *v1.AerolCluster {
	c.Spec.Federation = &v1.FederationSpec{
		IDKeySecret: corev1.LocalObjectReference{Name: "prod-federation"},
		Cells:       map[string]string{"2": "https://cell2.example.com", "1": "http://10.0.0.1:8080"},
	}
	return c
}

func fed(cells map[string]string) func(c *v1.AerolCluster) {
	return func(c *v1.AerolCluster) {
		federated(c).Spec.Federation.Cells = cells
	}
}

// Worker pods read the federation's key from a copy in their namespace.
func TestClusterCopiesFederationKey(t *testing.T) {
	c := federated(bootstrapped(testCluster()))
	r, api, cl := clusterRig(t, c)
	r.WorkerNamespace = testWorkerNS
	api.membersErr = errors.New("down")
	reconcileCluster(t, r) // not made yet: nothing to copy, no error
	ctx := context.Background()
	src := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "prod-federation", Namespace: testNS},
		Data: map[string][]byte{FederationKeyKey: []byte("a-key"), "notes": []byte("not copied")}}
	if err := cl.Create(ctx, src); err != nil {
		t.Fatal(err)
	}
	reconcileCluster(t, r)
	var dst corev1.Secret
	if err := cl.Get(ctx, types.NamespacedName{Namespace: testWorkerNS, Name: "prod-federation"}, &dst); err != nil {
		t.Fatal(err)
	}
	if len(dst.Data) != 1 || string(dst.Data[FederationKeyKey]) != "a-key" {
		t.Fatalf("copy = %v", dst.Data)
	}
}

// Lowering minReplicas retires the surplus gateways (review R7), keeping
// one in every zone and taking the ones not serving first; a retired
// gateway is not counted, so it is not replaced.
func TestGatewayScaleDown(t *testing.T) {
	c := bootstrapped(testCluster())
	c.Spec.Gateways.MinReplicas, c.Spec.Gateways.MaxReplicas = 3, 3
	var objs []client.Object
	var nodes []v1.AerolNode
	states := []string{v1.StateServing, v1.StateServing, v1.StateServing, v1.StateServing, v1.StateJoining, v1.StateServing}
	for i := 0; i < 6; i++ {
		// z-a holds three, z-b two, z-c one.
		zone := []string{"z-a", "z-a", "z-a", "z-b", "z-b", "z-c"}[i]
		n := node(fmt.Sprintf("prod-gateway-%d", i), v1.RoleGateway, "", zone)
		n.Labels = map[string]string{LabelCluster: "prod"}
		n.Status.State = states[i]
		nodes = append(nodes, *n)
		objs = append(objs, n)
	}
	r, _, cl := clusterRig(t, c, objs...)
	for range 2 {
		if err := r.ensureGateways(context.Background(), c, nodes); err != nil {
			t.Fatal(err)
		}
		var err error
		if nodes, err = listNodes(context.Background(), cl, c); err != nil {
			t.Fatal(err)
		}
	}
	kept := map[string]int{}
	var retired []string
	for _, n := range nodesByRole(t, cl)[v1.RoleGateway] {
		if n.Annotations[v1.AnnotationDecommission] == "true" {
			retired = append(retired, n.Name)
			continue
		}
		kept[n.Spec.Zone]++
	}
	sort.Strings(retired)
	// The joining one in z-b, then two of z-a's three.
	if strings.Join(retired, ",") != "prod-gateway-1,prod-gateway-2,prod-gateway-4" {
		t.Fatalf("retired %v", retired)
	}
	if kept["z-a"] != 1 || kept["z-b"] != 1 || kept["z-c"] != 1 {
		t.Fatalf("kept per zone %v", kept)
	}
}

// surplusGateway's order: out of the spec's zones, then not serving, then
// the fullest zone, then the last name.
func TestSurplusGateway(t *testing.T) {
	gw := func(name, zone, state string) v1.AerolNode {
		n := node(name, v1.RoleGateway, "", zone)
		n.Status.State = state
		return *n
	}
	zones := []string{"z-a", "z-b"}
	for _, tc := range []struct {
		live []v1.AerolNode
		want string
	}{
		{[]v1.AerolNode{gw("g1", "z-a", v1.StateServing), gw("g2", "z-old", v1.StateServing), gw("g3", "z-a", v1.StateJoining)}, "g2"},
		{[]v1.AerolNode{gw("g1", "z-a", v1.StateServing), gw("g3", "z-b", v1.StateJoining), gw("g2", "z-a", v1.StateServing)}, "g3"},
		{[]v1.AerolNode{gw("g1", "z-b", v1.StateServing), gw("g2", "z-a", v1.StateServing), gw("g3", "z-a", v1.StateServing)}, "g3"},
		{[]v1.AerolNode{gw("g9", "z-a", v1.StateServing), gw("g2", "z-b", v1.StateServing)}, "g9"},
	} {
		per := map[string]int{}
		for _, n := range tc.live {
			per[n.Spec.Zone]++
		}
		if got := tc.live[surplusGateway(zones, per, tc.live)].Name; got != tc.want {
			t.Errorf("picked %s, want %s", got, tc.want)
		}
	}
}

package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/yaml"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
)

func apiServerObjects() []client.Object {
	return []client.Object{
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"},
			Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.1", ClusterIPs: []string{"10.96.0.1", "fd00:10:96::1"}}},
		&discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"}, AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"172.18.0.2"}}, {Addresses: []string{"172.18.0.3", "172.18.0.2"}}}},
		// Pod ranges outside RFC 1918 (EKS custom networking uses 100.64.0.0/10),
		// so sandboxd's own default does not already cover them.
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}, Spec: corev1.NodeSpec{PodCIDR: "100.96.0.0/24", PodCIDRs: []string{"100.96.0.0/24"}}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n2"}, Spec: corev1.NodeSpec{PodCIDRs: []string{"100.96.1.0/24", "fd00:10:244:1::/64"}}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n3"}}, // a VPC CNI node: no pod range
		&networkingv1.ServiceCIDR{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes"}, Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.96.0.0/12"}}},
	}
}

// The operator finds the API server (deny floor) and the pod and Service
// ranges (private default), each once, in CIDR form.
func TestReadClusterAddresses(t *testing.T) {
	cl := newFakeClient(t, apiServerObjects()...)
	got := readClusterAddresses(context.Background(), cl, cl)
	if want := "10.96.0.1/32,fd00:10:96::1/128,172.18.0.2/32,172.18.0.3/32"; strings.Join(got.DenyFloor, ",") != want {
		t.Fatalf("deny floor = %v, want %s", got.DenyFloor, want)
	}
	if want := "100.96.0.0/24,100.96.1.0/24,fd00:10:244:1::/64,10.96.0.0/12"; strings.Join(got.Private, ",") != want {
		t.Fatalf("private = %v, want %s", got.Private, want)
	}
	// Nothing readable: empty lists, no panic; the in-pod private block
	// and the NetworkPolicy still stand.
	denied := newFakeClientWith(t, interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errors.New("forbidden")
		},
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errors.New("forbidden")
		},
	})
	if got := readClusterAddresses(context.Background(), denied, denied); len(got.DenyFloor)+len(got.Private) != 0 || got.FloorErr == nil {
		t.Fatalf("unreadable cluster: %+v", got)
	}
	// Half a floor is no floor: the Service without its addresses.
	half := newFakeClient(t, apiServerObjects()[0])
	if floor, err := readDenyFloor(context.Background(), half); err == nil || floor != nil || !strings.Contains(err.Error(), "the API server's addresses") {
		t.Fatalf("half a floor = %v, %v", floor, err)
	}
}

func TestAppendAddr(t *testing.T) {
	var l []string
	for _, s := range []string{"10.0.0.1", " 10.0.0.1/32 ", "10.1.2.3/16", "None", "", "nope", "10.0.0.0/33", "::1"} {
		l = appendAddr(l, s)
	}
	if strings.Join(l, ",") != "10.0.0.1/32,10.1.0.0/16,::1/128" {
		t.Fatalf("list = %v", l)
	}
}

// stampWithEnv stamps a worker whose template agent has env (the chart's
// worker settings) and an egress container, with the found addresses.
func stampWithEnv(t *testing.T, addrs clusterAddresses, env ...corev1.EnvVar) *corev1.Pod {
	t.Helper()
	c := testCluster()
	tpl := mustTemplate(t, TemplateWorker)
	agent := &tpl.Spec.Containers[containerIndex(tpl.Spec.Containers, AgentContainer)]
	agent.Env = append(agent.Env, env...)
	tpl.Spec.Containers = append(tpl.Spec.Containers, corev1.Container{Name: "egress"})
	pod, err := Stamp(tpl, StampInput{JoinURL: testJoinURL, JoinCA: testJoinCA, Cluster: c, Node: node("w", v1.RoleWorker, "general", "z-a"), Namespace: testWorkerNS,
		Version: "v0.7.2", Pool: &c.Spec.WorkerPools[0], Addresses: addrs})
	if err != nil {
		t.Fatal(err)
	}
	return pod
}

func envOn(n, v string) corev1.EnvVar { return corev1.EnvVar{Name: n, Value: v} }

// A worker gets the found lists on its agent and egress containers, added
// to what the chart's values set, and only within what sandboxd accepts at
// start: a found range must never stop a worker from starting.
func TestStampWorkerEgressRanges(t *testing.T) {
	rules, block := envOn("SB_ENABLE_NETWORK_RULES", "true"), envOn("SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT", "true")
	found := clusterAddresses{
		DenyFloor: []string{"10.96.0.1/32", "172.18.0.2/32"},
		// Two halves of 100.96.0.0/23, a range inside the first, an RFC 1918
		// pod range sandboxd's default already covers, and a range that
		// overlaps the sandboxes' subnet.
		Private: []string{"100.96.0.0/24", "100.96.1.0/24", "100.96.0.128/25", "10.244.0.0/16", "10.88.4.0/24"},
	}
	cases := []struct {
		name                   string
		env                    []corev1.EnvVar
		wantFloor, wantPrivate string
		// The chart sets its own values on the agent here only.
		wantEgressPrivate string
	}{
		{name: "both on: merged, covered and overlapping ranges left out", env: []corev1.EnvVar{rules, block},
			wantFloor: "10.96.0.1/32,172.18.0.2/32", wantPrivate: "100.96.0.0/23"},
		{name: "the chart's own values stay", env: []corev1.EnvVar{rules, block, envOn(envPrivate, "100.64.0.0/10")},
			wantFloor: "10.96.0.1/32,172.18.0.2/32", wantPrivate: "100.64.0.0/10,100.96.0.0/23", wantEgressPrivate: "100.96.0.0/23"},
		{name: "private block off: no private list, which sandboxd would refuse", env: []corev1.EnvVar{rules, envOn("SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT", "false")},
			wantFloor: "10.96.0.1/32,172.18.0.2/32", wantPrivate: "<unset>"},
		{name: "network rules off: neither list, which sandboxd would refuse", env: []corev1.EnvVar{envOn("SB_ENABLE_NETWORK_RULES", "false"), block},
			wantFloor: "<unset>", wantPrivate: "<unset>"},
		{name: "a floor address inside the sandboxes' subnet is left out", env: []corev1.EnvVar{rules, block, envOn("SB_CONTAINERD_BRIDGE_SUBNET", "172.18.0.0/16")},
			wantFloor: "10.96.0.1/32", wantPrivate: "100.96.0.0/23"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := stampWithEnv(t, found, tc.env...)
			for _, name := range []string{AgentContainer, "egress"} {
				c := pod.Spec.Containers[containerIndex(pod.Spec.Containers, name)]
				if got := env(c, envDenyFloor); got != tc.wantFloor {
					t.Fatalf("%s floor = %q, want %q", name, got, tc.wantFloor)
				}
				want := tc.wantPrivate
				if name == "egress" && tc.wantEgressPrivate != "" {
					want = tc.wantEgressPrivate
				}
				if got := env(c, envPrivate); got != want {
					t.Fatalf("%s private = %q, want %q", name, got, want)
				}
			}
		})
	}
	c := testCluster()
	gw, err := Stamp(mustTemplate(t, TemplateGateway), StampInput{JoinURL: testJoinURL, JoinCA: testJoinCA, Cluster: c, Node: node("g", v1.RoleGateway, "", "z-a"), Namespace: testNS, Version: "v0.7.2", Addresses: found})
	if err != nil || env(gw.Spec.Containers[0], envDenyFloor) != "<unset>" {
		t.Fatalf("gateway got the worker's lists: %v", err)
	}
}

// 2,000 nodes each with its own RFC 1918 pod range add nothing to a
// sandbox's rules; outside RFC 1918, contiguous ranges collapse.
func TestAggregateAtScale(t *testing.T) {
	var rfc1918, cgnat []string
	for i := 0; i < 2000; i++ {
		rfc1918 = append(rfc1918, fmt.Sprintf("10.%d.%d.0/24", 100+i/256, i%256))
	}
	for i := 0; i < 256; i++ {
		cgnat = append(cgnat, fmt.Sprintf("100.96.%d.0/24", i))
	}
	pod := stampWithEnv(t, clusterAddresses{Private: append(rfc1918, cgnat...)},
		envOn("SB_ENABLE_NETWORK_RULES", "true"), envOn("SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT", "true"))
	if got := env(pod.Spec.Containers[containerIndex(pod.Spec.Containers, AgentContainer)], envPrivate); got != "100.96.0.0/16" {
		t.Fatalf("private = %q, want one range", got)
	}
	if got := aggregate(nil); len(got) != 0 {
		t.Fatalf("aggregate(nil) = %v", got)
	}
}

// Through the node controller: a new worker pod carries the cluster's
// addresses, read past the cache.
func TestNodeWorkerPodGetsClusterAddresses(t *testing.T) {
	c := bootstrapped(testCluster())
	g := newNodeRig(t, c, append(apiServerObjects(), node("prod-general-ddddd", v1.RoleWorker, "general", "z-a"))...)
	g.r.Reader = g.cl
	g.reconcile("prod-general-ddddd")
	p := g.pod(testWorkerNS, "prod-general-ddddd")
	a := p.Spec.Containers[containerIndex(p.Spec.Containers, AgentContainer)]
	// 172.18.0.2 and .3 merge into one /31; the IPv6 pod range is outside
	// sandboxd's default, so it stays.
	if env(a, envDenyFloor) != "10.96.0.1/32,172.18.0.2/31,fd00:10:96::1/128" || env(a, envPrivate) != "100.96.0.0/23,fd00:10:244:1::/64" {
		t.Fatalf("worker env: floor %q private %q", env(a, envDenyFloor), env(a, envPrivate))
	}
}

// A worker whose agent has the host firewall on mounts the deny-floor
// ConfigMap whole into sandboxd and the egress gateway and points both at
// the file (review R4); one with it off takes neither.
func TestUseEgressFloorFile(t *testing.T) {
	p := stampWithEnv(t, clusterAddresses{DenyFloor: []string{"10.96.0.1/32"}})
	if !podHasConfigMap(p, EgressFloorConfigMap("prod")) {
		t.Fatal("no deny-floor volume")
	}
	for _, name := range []string{AgentContainer, "egress"} {
		c := p.Spec.Containers[containerIndex(p.Spec.Containers, name)]
		if env(c, envFloorFile) != "/etc/aerolvm-egress-floor/deny-floor" {
			t.Fatalf("%s: %s = %q", name, envFloorFile, env(c, envFloorFile))
		}
		mounted := false
		for _, m := range c.VolumeMounts {
			if m.Name == EgressFloorVolume {
				mounted = m.ReadOnly && m.SubPath == "" && m.MountPath == "/etc/aerolvm-egress-floor"
			}
		}
		if !mounted {
			t.Fatalf("%s: the floor volume is not mounted whole and read-only: %+v", name, c.VolumeMounts)
		}
	}
	off := stampWithEnv(t, clusterAddresses{DenyFloor: []string{"10.96.0.1/32"}}, corev1.EnvVar{Name: "SB_ENABLE_NETWORK_RULES", Value: "false"})
	if podHasConfigMap(off, EgressFloorConfigMap("prod")) || env(off.Spec.Containers[containerIndex(off.Spec.Containers, AgentContainer)], envFloorFile) != "<unset>" {
		t.Fatal("a worker without the host firewall took the floor file")
	}
}

func podHasConfigMap(p *corev1.Pod, name string) bool {
	for _, v := range p.Spec.Volumes {
		if v.ConfigMap != nil && v.ConfigMap.Name == name && v.ConfigMap.Optional == nil {
			return true
		}
	}
	return false
}

// floorConfigMap reads the deny-floor ConfigMap's body, "" when it is not
// there.
func floorConfigMap(t *testing.T, cl client.Client) string {
	t.Helper()
	var cm corev1.ConfigMap
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: testWorkerNS, Name: EgressFloorConfigMap("prod")}, &cm); err != nil {
		if apierrors.IsNotFound(err) {
			return ""
		}
		t.Fatal(err)
	}
	return cm.Data[EgressFloorKey]
}

// The API server moves to a new address: the deny-floor ConfigMap, which
// a worker made before the move mounts, gets it on the next cluster pass
// (review R4). sandboxd and the egress gateway then add it to their floor
// as the kubelet updates the file (pkg/egresspolicy WatchFloorFile).
func TestAPIEndpointRotationReachesExistingWorker(t *testing.T) {
	const name = "prod-general-endpoint"
	g := newNodeRig(t, bootstrapped(testCluster()), node(name, v1.RoleWorker, "general", "z-a"), machine("m1"))
	g.reconcile(name)
	p := g.pod(testWorkerNS, name)
	if p == nil || !podHasConfigMap(p, EgressFloorConfigMap("prod")) {
		t.Fatal("the worker does not mount the deny-floor ConfigMap")
	}
	r := &ClusterReconciler{Client: g.cl, Scheme: g.cl.Scheme(), WorkerNamespace: testWorkerNS, Templates: "aerolvm-pod-templates", Now: time.Now}
	c := testCluster()
	if err := r.syncEgressFloor(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if got := floorConfigMap(t, g.cl); got != "10.96.0.1/32\n172.18.0.2/31\nfd00:10:96::1/128\n" {
		t.Fatalf("floor = %q", got)
	}
	var ep discoveryv1.EndpointSlice
	if err := g.cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "kubernetes"}, &ep); err != nil {
		t.Fatal(err)
	}
	ep.Endpoints = []discoveryv1.Endpoint{{Addresses: []string{"172.18.0.44"}}}
	if err := g.cl.Update(context.Background(), &ep); err != nil {
		t.Fatal(err)
	}
	if err := r.syncEgressFloor(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if got := floorConfigMap(t, g.cl); !strings.Contains(got, "172.18.0.44/32") {
		t.Fatalf("the existing worker's floor file lacks the API server's new address: %q", got)
	}
	if again := g.pod(testWorkerNS, name); again == nil || again.UID != p.UID {
		t.Fatal("the worker was replaced; its running pod must follow the file")
	}
}

// Fail closed (review R4): with the API server's addresses unreadable, no
// floor ConfigMap is made (new worker pods wait for it), one that exists
// keeps the last good addresses, and no worker pod is made.
func TestEgressFloorFailsClosed(t *testing.T) {
	denyDefault := interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if key.Namespace == "default" {
			return errors.New("forbidden")
		}
		return c.Get(ctx, key, obj, opts...)
	}}
	cl := newFakeClient(t, testCluster(), templates(t))
	denied := interceptor.NewClient(cl.(client.WithWatch), denyDefault)
	r := &ClusterReconciler{Client: cl, Scheme: cl.Scheme(), WorkerNamespace: testWorkerNS, Templates: "aerolvm-pod-templates", Reader: denied, Now: time.Now}
	before := testutilCounter(egressFloorReadErrors)
	if err := r.syncEgressFloor(context.Background(), testCluster()); err != nil {
		t.Fatal(err)
	}
	if floorConfigMap(t, cl) != "" || testutilCounter(egressFloorReadErrors) != before+1 {
		t.Fatal("a floor ConfigMap was made without the API server's addresses")
	}
	// A good read, then a failed one: the last good addresses stay.
	for _, o := range apiServerObjects()[:2] {
		if err := cl.Create(context.Background(), o); err != nil {
			t.Fatal(err)
		}
	}
	r.Reader = cl
	if err := r.syncEgressFloor(context.Background(), testCluster()); err != nil {
		t.Fatal(err)
	}
	good := floorConfigMap(t, cl)
	r.Reader = denied
	if err := r.syncEgressFloor(context.Background(), testCluster()); err != nil {
		t.Fatal(err)
	}
	if got := floorConfigMap(t, cl); got != good || !strings.Contains(got, "172.18.0.2/31") {
		t.Fatalf("a failed read changed the floor: %q, was %q", got, good)
	}

	const name = "prod-general-nofloor"
	g := newNodeRig(t, bootstrapped(testCluster()), node(name, v1.RoleWorker, "general", "z-a"))
	g.r.Reader = interceptor.NewClient(g.cl.(client.WithWatch), denyDefault)
	g.reconcile(name)
	if g.pod(testWorkerNS, name) != nil {
		t.Fatal("a worker pod was made without the API server on its deny floor")
	}
	if got := g.node(name); got.Status.State != v1.StatePending || !strings.Contains(got.Status.Reason, "API server's addresses") {
		t.Fatalf("state %s (%s)", got.Status.State, got.Status.Reason)
	}
	// Workers without the host firewall need no floor: nothing is written.
	off := templates(t)
	tpl, err := ParsePodTemplate(off.Data[TemplateWorker])
	if err != nil {
		t.Fatal(err)
	}
	setEnv(&tpl.Spec, AgentContainer, []corev1.EnvVar{envOn("SB_ENABLE_NETWORK_RULES", "false")})
	raw, err := yaml.Marshal(tpl)
	if err != nil {
		t.Fatal(err)
	}
	off.Data[TemplateWorker] = string(raw)
	cl2 := newFakeClient(t, testCluster(), off)
	r2 := &ClusterReconciler{Client: cl2, Scheme: cl2.Scheme(), WorkerNamespace: testWorkerNS, Templates: "aerolvm-pod-templates", Now: time.Now}
	if err := r2.syncEgressFloor(context.Background(), testCluster()); err != nil {
		t.Fatal(err)
	}
	if floorConfigMap(t, cl2) != "" {
		t.Fatal("a floor ConfigMap for workers without the host firewall")
	}
}

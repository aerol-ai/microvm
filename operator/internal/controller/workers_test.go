package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/operator/internal/aerolapi"
)

func serving(name string, sandboxes int32) v1.AerolNode {
	n := *node(name, v1.RoleWorker, "general", "")
	n.Status.State, n.Status.Sandboxes = v1.StateServing, sandboxes
	return n
}

// waiting is a worker whose pod has no machine yet.
func waiting(name string) v1.AerolNode {
	n := *node(name, v1.RoleWorker, "general", "")
	n.Status.State = v1.StatePending
	return n
}

// withWaiting adds a worker with no machine to a zone.
func withWaiting(z *zoneWorkers, name string) *zoneWorkers {
	z.live = append(z.live, waiting(name))
	z.pending++
	z.unplaced = append(z.unplaced, name)
	return z
}

// withFailed marks a zone as holding a worker stopped by its preflight.
func withFailed(z *zoneWorkers) *zoneWorkers {
	z.failed++
	return z
}

// zw builds one zone's workers: serving ones with the given free share.
func zw(free float64, live ...v1.AerolNode) *zoneWorkers {
	z := &zoneWorkers{live: live}
	if len(live) > 0 {
		z.known = true
		z.budgetCPU, z.budgetMem = 100, 100
		z.freeCPU, z.freeMem = free*100, int(free*100)
	}
	return z
}

func TestWantedWorkers(t *testing.T) {
	zones := []string{"a", "b", "c"}
	pool := &v1.WorkerPoolSpec{MinWorkers: 3, MaxWorkers: 9, HeadroomPercent: 15}
	cases := []struct {
		name        string
		zones       map[string]*zoneWorkers
		total       int
		haveMembers bool
		pool        *v1.WorkerPoolSpec
		wantAdd     map[string]int
		wantRemove  string
		wantWhy     string
	}{
		{
			name: "the floor, one per zone", zones: map[string]*zoneWorkers{"a": zw(0), "b": zw(0), "c": zw(0)},
			haveMembers: false, wantAdd: map[string]int{"a": 1, "b": 1, "c": 1},
		},
		{
			name:  "a zone short of room gets one more",
			zones: map[string]*zoneWorkers{"a": zw(0.05, serving("a1", 9)), "b": zw(0.5, serving("b1", 2)), "c": zw(0.5, serving("c1", 2))},
			total: 3, haveMembers: true, wantAdd: map[string]int{"a": 1},
		},
		{
			name:  "one already on its way: wait for it",
			zones: map[string]*zoneWorkers{"a": func() *zoneWorkers { z := zw(0.05, serving("a1", 9)); z.pending = 1; return z }(), "b": zw(0.5, serving("b1", 2)), "c": zw(0.5, serving("c1", 2))},
			total: 4, haveMembers: true, wantAdd: map[string]int{},
		},
		{
			name:  "at the pool's maximum: nothing more",
			zones: map[string]*zoneWorkers{"a": zw(0.05, serving("a1", 9)), "b": zw(0.5, serving("b1", 2)), "c": zw(0.5, serving("c1", 2))},
			total: 3, haveMembers: true, pool: &v1.WorkerPoolSpec{MinWorkers: 3, MaxWorkers: 3, HeadroomPercent: 15}, wantAdd: map[string]int{},
		},
		{
			name: "twice the room and above the floor: the emptiest goes",
			zones: map[string]*zoneWorkers{"a": zw(0.2, serving("a1", 3)), "b": zw(0.9, serving("b1", 5), serving("b2", 1)),
				"c": zw(0.2, serving("c1", 3))},
			total: 4, haveMembers: true, wantAdd: map[string]int{}, wantRemove: "b2", wantWhy: whyScaleDown,
		},
		// Rotation drill, run p3-drills-2: minWorkers = maxWorkers = 3. z-a's
		// replacement failed its preflight; z-b serves; z-c's worker left.
		// The last slot goes to z-c, which has nothing, not to z-a, whose
		// worker can come back in place.
		{
			name:  "the last slot goes to an empty zone before a zone whose worker failed",
			zones: map[string]*zoneWorkers{"a": withFailed(zw(0)), "b": zw(0.5, serving("b1", 2)), "c": zw(0)},
			total: 2, haveMembers: true, pool: &v1.WorkerPoolSpec{MinWorkers: 3, MaxWorkers: 3, HeadroomPercent: 15},
			wantAdd: map[string]int{"c": 1},
		},
		{
			name:  "with room for both, the failed worker's zone still gets one",
			zones: map[string]*zoneWorkers{"a": withFailed(zw(0)), "b": zw(0.5, serving("b1", 2)), "c": zw(0)},
			total: 2, haveMembers: true, wantAdd: map[string]int{"a": 1, "c": 1},
		},
		// The failed worker came back: the replacement made for it never got
		// a machine and holds the pool's last slot.
		{
			name: "a worker with no machine goes once its zone has its workers and room",
			zones: map[string]*zoneWorkers{"a": withWaiting(zw(0.9, serving("a1", 0)), "a2"), "b": zw(0.5, serving("b1", 2)),
				"c": zw(0)},
			total: 3, haveMembers: true, pool: &v1.WorkerPoolSpec{MinWorkers: 3, MaxWorkers: 3, HeadroomPercent: 15},
			wantAdd: map[string]int{}, wantRemove: "a2", wantWhy: whyUnplaced,
		},
		{
			name:  "a worker with no machine in a zone short of room stays",
			zones: map[string]*zoneWorkers{"a": withWaiting(zw(0.05, serving("a1", 9)), "a2"), "b": zw(0.5, serving("b1", 2)), "c": zw(0.5, serving("c1", 2))},
			total: 4, haveMembers: true, wantAdd: map[string]int{},
		},
		{
			name:  "a worker with no machine that is its zone's only one stays",
			zones: map[string]*zoneWorkers{"a": withWaiting(&zoneWorkers{}, "a1"), "b": zw(0.5, serving("b1", 2)), "c": zw(0.5, serving("c1", 2))},
			total: 3, haveMembers: true, wantAdd: map[string]int{},
		},
		{
			name:  "without the member list nothing is taken away",
			zones: map[string]*zoneWorkers{"a": withWaiting(zw(0.9, serving("a1", 0)), "a2"), "b": zw(0.5, serving("b1", 2)), "c": zw(0.5, serving("c1", 2))},
			total: 4, haveMembers: false, wantAdd: map[string]int{},
		},
		{
			name: "no scale-down while another zone is short",
			zones: map[string]*zoneWorkers{"a": zw(0.05, serving("a1", 9)), "b": zw(0.9, serving("b1", 5), serving("b2", 1)),
				"c": zw(0.2, serving("c1", 3))},
			total: 4, haveMembers: true, wantAdd: map[string]int{"a": 1},
		},
		{
			name: "no scale-down below the floor",
			zones: map[string]*zoneWorkers{"a": zw(0.9, serving("a1", 0)), "b": zw(0.9, serving("b1", 0)),
				"c": zw(0.9, serving("c1", 0))},
			total: 3, haveMembers: true, wantAdd: map[string]int{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := pool
			if tc.pool != nil {
				p = tc.pool
			}
			got := wantedWorkers(zones, p, tc.zones, tc.total, tc.haveMembers)
			for _, z := range zones {
				if got.add[z] != tc.wantAdd[z] {
					t.Fatalf("add = %v, want %v", got.add, tc.wantAdd)
				}
			}
			if got.remove != tc.wantRemove {
				t.Fatalf("remove = %q, want %q", got.remove, tc.wantRemove)
			}
			if got.why != tc.wantWhy {
				t.Fatalf("why = %q, want %q", got.why, tc.wantWhy)
			}
		})
	}
	if ceilDiv(5, 0) != 5 || ceilDiv(4, 3) != 2 {
		t.Fatal("ceilDiv")
	}
	if (zoneWorkers{}).freeShare() != 0 {
		t.Fatal("empty zone has room")
	}
}

func TestOldMachines(t *testing.T) {
	now := time.Now()
	cutoff := now.Add(-30 * 24 * time.Hour)
	old, older, young := now.Add(-40*24*time.Hour), now.Add(-50*24*time.Hour), now.Add(-time.Hour)
	starting := serving("a3", 0)
	starting.Status.State = v1.StateJoining
	cases := []struct {
		name   string
		zones  map[string]*zoneWorkers
		adding map[string]int
		born   map[string]time.Time
		want   []string
	}{
		{
			name:  "the oldest machine per zone, past the cutoff only",
			zones: map[string]*zoneWorkers{"a": zw(0.3, serving("a1", 2), serving("a2", 2)), "b": zw(0.3, serving("b1", 2)), "c": zw(0.3, serving("c1", 2))},
			born:  map[string]time.Time{"a1": old, "a2": older, "b1": young, "c1": old},
			want:  []string{"a2", "c1"},
		},
		{
			name: "a zone with one already leaving waits",
			zones: map[string]*zoneWorkers{"a": func() *zoneWorkers { z := zw(0.3, serving("a1", 2)); z.leaving = 1; return z }(),
				"b": zw(0.3, serving("b1", 2)), "c": zw(0.3, serving("c1", 2))},
			born: map[string]time.Time{"a1": old, "b1": old, "c1": young},
			want: []string{"b1"},
		},
		{
			name: "a zone still starting or topped up this pass waits",
			zones: map[string]*zoneWorkers{"a": func() *zoneWorkers { z := zw(0.3, serving("a1", 2), starting); z.pending = 1; return z }(),
				"b": zw(0.3, serving("b1", 2)), "c": zw(0.3, serving("c1", 2))},
			adding: map[string]int{"b": 1},
			born:   map[string]time.Time{"a1": old, "b1": old, "c1": old},
			want:   []string{"c1"},
		},
		{
			name:  "an unreadable machine is never retired",
			zones: map[string]*zoneWorkers{"a": zw(0.3, serving("a1", 2)), "b": zw(0.3, serving("b1", 2)), "c": zw(0.3, serving("c1", 2))},
			born:  map[string]time.Time{"a1": old},
			want:  []string{"a1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := oldMachines([]string{"a", "b", "c"}, tc.zones, tc.adding, tc.born, cutoff)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("retire = %v, want %v", got, tc.want)
			}
		})
	}
	// Only a calm pass retires: a short zone, or no member list, is not.
	pool := &v1.WorkerPoolSpec{MinWorkers: 3, MaxWorkers: 9, HeadroomPercent: 15}
	short := map[string]*zoneWorkers{"a": zw(0.05, serving("a1", 9)), "b": zw(0.3, serving("b1", 2)), "c": zw(0.3, serving("c1", 2))}
	if wantedWorkers([]string{"a", "b", "c"}, pool, short, 3, true).calm {
		t.Fatal("a short zone counted as calm")
	}
	fine := map[string]*zoneWorkers{"a": zw(0.2, serving("a1", 2)), "b": zw(0.2, serving("b1", 2)), "c": zw(0.2, serving("c1", 2))}
	if !wantedWorkers([]string{"a", "b", "c"}, pool, fine, 3, true).calm {
		t.Fatal("a fine pool not calm")
	}
	if wantedWorkers([]string{"a", "b", "c"}, pool, fine, 3, false).calm {
		t.Fatal("no member list counted as calm")
	}
}

// Through a reconcile: workers on machines older than maxMachineAge start
// their decommission, one per zone; young machines stay.
func TestClusterRetiresOldMachines(t *testing.T) {
	c := bootstrapped(testCluster())
	c.Spec.WorkerPools[0].MaxMachineAge = &metav1.Duration{Duration: 30 * 24 * time.Hour}
	r, api, cl := clusterRig(t, c)
	reconcileCluster(t, r)
	ctx := context.Background()
	age := map[string]time.Duration{"z-a": 40 * 24 * time.Hour, "z-b": time.Hour, "z-c": 31 * 24 * time.Hour}
	for _, n := range nodesByRole(t, cl)[v1.RoleWorker] {
		n := n
		machine := "m-" + n.Spec.Zone
		if err := cl.Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: machine,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age[n.Spec.Zone]))}}); err != nil {
			t.Fatal(err)
		}
		n.Status.State, n.Status.NodeName = v1.StateServing, machine
		if err := cl.Status().Update(ctx, &n); err != nil {
			t.Fatal(err)
		}
		api.members = append(api.members, aerolapi.Node{NodeID: n.Name, Alive: true, Capacity: aerolapi.Capacity{
			CPUBudget: 30, ReservedCPU: 24, MemoryBudgetMB: 1000, ReservedMemoryMB: 800}})
	}
	reconcileCluster(t, r)
	leaving := map[string]bool{}
	for _, n := range nodesByRole(t, cl)[v1.RoleWorker] {
		if n.Annotations[v1.AnnotationDecommission] == "true" {
			leaving[n.Spec.Zone] = true
		}
	}
	if !leaving["z-a"] || leaving["z-b"] || !leaving["z-c"] {
		t.Fatalf("decommissioning by zone = %v, want z-a and z-c", leaving)
	}
}

// Workers held by a failed preflight count toward the pool's maximum: a bad
// node image cannot buy machines without end.
func TestClusterCountsFailedWorkersTowardMax(t *testing.T) {
	c := bootstrapped(testCluster())
	c.Spec.WorkerPools[0].MaxWorkers = 4
	r, _, cl := clusterRig(t, c)
	reconcileCluster(t, r)
	ctx := context.Background()
	for _, n := range nodesByRole(t, cl)[v1.RoleWorker] {
		n := n
		n.Status.State, n.Status.Reason = v1.StateFailed, "preflight failed: kernel"
		if err := cl.Status().Update(ctx, &n); err != nil {
			t.Fatal(err)
		}
	}
	reconcileCluster(t, r)
	if got := len(nodesByRole(t, cl)[v1.RoleWorker]); got != 4 {
		t.Fatalf("workers = %d, want 3 failed + 1 new, at the maximum of 4", got)
	}
}

// The rotation drill on EKS (Phase 3, run p3-drills-2), through the
// reconciler: minWorkers = maxWorkers = 3, z-a's worker stopped by its
// preflight, z-c's worker gone. The new worker goes to z-c. Then z-a's
// failed worker comes back while a replacement made for it still has no
// machine: that one is decommissioned, so its slot is free again.
func TestClusterRotationKeepsEveryZoneServed(t *testing.T) {
	c := bootstrapped(testCluster())
	c.Spec.WorkerPools[0].MaxWorkers = 3
	r, api, cl := clusterRig(t, c)
	reconcileCluster(t, r)
	ctx := context.Background()
	byZone := func() map[string][]v1.AerolNode {
		out := map[string][]v1.AerolNode{}
		for _, n := range nodesByRole(t, cl)[v1.RoleWorker] {
			out[n.Spec.Zone] = append(out[n.Spec.Zone], n)
		}
		return out
	}
	set := func(n v1.AerolNode, state, machine string) {
		t.Helper()
		n.Status.State, n.Status.NodeName = state, machine
		if err := cl.Status().Update(ctx, &n); err != nil {
			t.Fatal(err)
		}
	}
	member := func(name string) aerolapi.Node {
		return aerolapi.Node{NodeID: name, Alive: true, Capacity: aerolapi.Capacity{CPUBudget: 30, MemoryBudgetMB: 1000}}
	}
	zones := byZone()
	set(zones["z-a"][0], v1.StateFailed, "m-a")
	set(zones["z-b"][0], v1.StateServing, "m-b")
	api.members = []aerolapi.Node{member(zones["z-b"][0].Name)}
	gone := zones["z-c"][0]
	if err := cl.Delete(ctx, &gone); err != nil {
		t.Fatal(err)
	}
	reconcileCluster(t, r)
	zones = byZone()
	if len(zones["z-c"]) != 1 || len(zones["z-a"]) != 1 {
		t.Fatalf("workers by zone: z-a %d, z-c %d; want z-c's new worker, nothing more in z-a", len(zones["z-a"]), len(zones["z-c"]))
	}

	// z-a's worker is fixed in place; a replacement made for it before the
	// fix waits for a machine that will not come.
	set(zones["z-a"][0], v1.StateServing, "m-a")
	set(zones["z-c"][0], v1.StateServing, "m-c")
	extra := &v1.AerolNode{}
	if err := r.createNode(ctx, reconcileCluster(t, r), "prod-general-extra", v1.RoleWorker, "general", "z-a"); err != nil {
		t.Fatal(err)
	}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: testNS, Name: "prod-general-extra"}, extra); err != nil {
		t.Fatal(err)
	}
	set(*extra, v1.StatePending, "")
	api.members = []aerolapi.Node{member(zones["z-a"][0].Name), member(zones["z-b"][0].Name), member(zones["z-c"][0].Name)}
	reconcileCluster(t, r)
	var got v1.AerolNode
	if err := cl.Get(ctx, client.ObjectKey{Namespace: testNS, Name: extra.Name}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Annotations[v1.AnnotationDecommission] != "true" {
		t.Fatalf("the worker with no machine was kept (annotations %v); want it decommissioned", got.Annotations)
	}
	for _, n := range nodesByRole(t, cl)[v1.RoleWorker] {
		if n.Name != extra.Name && n.Annotations[v1.AnnotationDecommission] == "true" {
			t.Fatalf("serving worker %s decommissioned", n.Name)
		}
	}
}

// The workers of a pool removed from the spec leave through decommission
// (review R6): one that never served at once, the others one per zone at
// a time. The pools still in the spec are left alone.
func TestRemovedWorkerPoolDecommissions(t *testing.T) {
	c := bootstrapped(testCluster())
	mk := func(name, pool, zone, state string) *v1.AerolNode {
		n := node(name, v1.RoleWorker, pool, zone)
		n.Labels = map[string]string{LabelCluster: "prod"}
		n.Status.State = state
		return n
	}
	objs := []client.Object{
		mk("prod-oldpool-a1", "oldpool", "z-a", v1.StateServing),
		mk("prod-oldpool-a2", "oldpool", "z-a", v1.StateServing),
		mk("prod-oldpool-b1", "oldpool", "z-b", v1.StateRestarting),
		mk("prod-oldpool-c1", "oldpool", "z-c", v1.StatePending),
		mk("prod-oldpool-c2", "oldpool", "z-c", v1.StateFailed),
		mk("prod-oldpool-c3", "oldpool", "z-c", v1.StateDead),
		mk("prod-oldpool-c4", "oldpool", "z-c", v1.StateSuspect),
		mk("prod-general-a1", "general", "z-a", v1.StateServing),
	}
	r, _, cl := clusterRig(t, c, objs...)
	decommissioned := func() map[string]bool {
		var list v1.AerolNodeList
		if err := cl.List(context.Background(), &list); err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, n := range list.Items {
			if n.Annotations[v1.AnnotationDecommission] == "true" {
				out[n.Name] = true
			}
		}
		return out
	}
	pass := func() {
		t.Helper()
		nodes, err := listNodes(context.Background(), cl, c)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.ensureWorkers(context.Background(), c, nodes, nil, false); err != nil {
			t.Fatal(err)
		}
	}
	pass()
	got := decommissioned()
	for _, want := range []string{"prod-oldpool-a1", "prod-oldpool-b1", "prod-oldpool-c1", "prod-oldpool-c2"} {
		if !got[want] {
			t.Errorf("%s was not decommissioned", want)
		}
	}
	for _, kept := range []string{"prod-oldpool-a2", "prod-oldpool-c3", "prod-oldpool-c4", "prod-general-a1"} {
		if got[kept] {
			t.Errorf("%s was decommissioned", kept)
		}
	}
	// Its zone's first one still leaving: the second waits.
	pass()
	if decommissioned()["prod-oldpool-a2"] {
		t.Fatal("two serving workers of a removed pool left one zone at once")
	}
	// The first one gone: the second goes.
	var gone v1.AerolNode
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: testNS, Name: "prod-oldpool-a1"}, &gone); err != nil {
		t.Fatal(err)
	}
	if err := cl.Delete(context.Background(), &gone); err != nil {
		t.Fatal(err)
	}
	pass()
	if !decommissioned()["prod-oldpool-a2"] {
		t.Fatal("the zone's next worker of a removed pool never went")
	}
}

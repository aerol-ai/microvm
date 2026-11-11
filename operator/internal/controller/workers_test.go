package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/operator/internal/aerolapi"
)

func serving(name string, sandboxes int32) v1.AerolNode {
	n := *node(name, v1.RoleWorker, "general", "")
	n.Status.State, n.Status.Sandboxes = v1.StateServing, sandboxes
	return n
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
			total: 4, haveMembers: true, wantAdd: map[string]int{}, wantRemove: "b2",
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

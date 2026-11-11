package controller

import (
	"testing"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
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

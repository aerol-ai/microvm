package controller

import (
	"context"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/operator/internal/aerolapi"
)

// Workers, no dummy pods (plans/kubernetes-v2-architecture.md §10.4). The
// operator reads AerolVM's own numbers (each worker's free CPU and memory)
// and keeps each pool's headroom in every zone. It adds a worker pod when a
// zone runs short; the pod fits on no machine, so Karpenter or Node Auto
// Provisioning buys one. It removes the emptiest worker, by decommission,
// when a zone has twice the room it needs.

// zoneWorkers is one pool's workers in one zone.
type zoneWorkers struct {
	live    []v1.AerolNode // not ended, not decommissioning
	pending int            // made but not serving yet
	leaving int            // decommissioning
	// failed counts workers held by a failed preflight: still on their
	// machine, which can be fixed in place. unplaced names live workers
	// whose pod has no machine yet.
	failed   int
	unplaced []string
	// free and budget are summed over serving workers' heartbeats.
	freeCPU, budgetCPU float64
	freeMem, budgetMem int
	known              bool // some serving worker had a heartbeat
}

func (z zoneWorkers) freeShare() float64 {
	if z.budgetCPU <= 0 || z.budgetMem <= 0 {
		return 0
	}
	return min(z.freeCPU/z.budgetCPU, float64(z.freeMem)/float64(z.budgetMem))
}

// ensureWorkers adds and removes worker pods for every pool. With no member
// list (the control plane did not answer), only the floor is kept.
func (r *ClusterReconciler) ensureWorkers(ctx context.Context, c *v1.AerolCluster, nodes []v1.AerolNode, members []aerolapi.Node, haveMembers bool) error {
	byID := map[string]aerolapi.Node{}
	for _, m := range members {
		byID[m.NodeID] = m
	}
	for i := range c.Spec.WorkerPools {
		pool := &c.Spec.WorkerPools[i]
		zones := map[string]*zoneWorkers{}
		for _, z := range c.Spec.Zones {
			zones[z] = &zoneWorkers{}
		}
		total := 0
		for _, n := range nodes {
			if n.Spec.Role != v1.RoleWorker || n.Spec.Pool != pool.Name {
				continue
			}
			zw := zones[n.Spec.Zone]
			if zw == nil {
				zw = &zoneWorkers{}
				zones[n.Spec.Zone] = zw
			}
			if n.Status.State == v1.StateFailed && n.DeletionTimestamp == nil {
				// A worker held by a failed preflight is no capacity, but
				// its machine is still there: it counts toward the
				// maximum, so a bad node image cannot buy machines
				// without end.
				total++
				zw.failed++
			}
			if ended(n) {
				continue
			}
			total++
			if n.Annotations[v1.AnnotationDecommission] == "true" {
				zw.leaving++
				continue
			}
			zw.live = append(zw.live, n)
			if n.Status.State != v1.StateServing {
				zw.pending++
				if n.Status.NodeName == "" {
					zw.unplaced = append(zw.unplaced, n.Name)
				}
				continue
			}
			if m, ok := byID[n.Name]; ok && !m.CapacityStale && m.Capacity.CPUBudget > 0 {
				zw.known = true
				zw.freeCPU += m.Capacity.FreeCPU()
				zw.budgetCPU += m.Capacity.CPUBudget
				zw.freeMem += m.Capacity.FreeMemoryMB()
				zw.budgetMem += m.Capacity.MemoryBudgetMB
			}
		}
		want := wantedWorkers(c.Spec.Zones, pool, zones, total, haveMembers)
		for _, zone := range c.Spec.Zones {
			for k := 0; k < want.add[zone]; k++ {
				suffix, err := randomToken(5)
				if err != nil {
					return err
				}
				if err := r.createNode(ctx, c, WorkerName(c.Name, pool.Name, suffix), v1.RoleWorker, pool.Name, zone); err != nil {
					return err
				}
			}
		}
		if want.remove != "" {
			if err := r.markDecommission(ctx, c, want.remove, want.why); err != nil {
				return err
			}
			continue
		}
		if want.calm && pool.MaxMachineAge != nil && pool.MaxMachineAge.Duration > 0 {
			cutoff := r.Now().Add(-pool.MaxMachineAge.Duration)
			for _, name := range oldMachines(c.Spec.Zones, zones, want.add, r.machineBirths(ctx, zones), cutoff) {
				why := fmt.Sprintf("its machine is older than maxMachineAge (%s)", pool.MaxMachineAge.Duration)
				if err := r.markDecommission(ctx, c, name, why); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// machineBirths maps each serving worker to when its machine joined
// Kubernetes. A machine that cannot be read is left out, so it is never
// retired by mistake.
func (r *ClusterReconciler) machineBirths(ctx context.Context, zones map[string]*zoneWorkers) map[string]time.Time {
	born := map[string]time.Time{}
	for _, zw := range zones {
		for _, n := range zw.live {
			if n.Status.State != v1.StateServing || n.Status.NodeName == "" {
				continue
			}
			var node corev1.Node
			if err := r.Get(ctx, client.ObjectKey{Name: n.Status.NodeName}, &node); err != nil {
				continue
			}
			born[n.Name] = node.CreationTimestamp.Time
		}
	}
	return born
}

// oldMachines picks, per zone, the serving worker on the oldest machine
// born before cutoff. A zone with a worker already leaving, still
// starting or being added this pass waits its turn: one retirement per
// zone at a time keeps the zone's room, and the floor adds the
// replacement on the next pass.
func oldMachines(zoneOrder []string, zones map[string]*zoneWorkers, adding map[string]int, born map[string]time.Time, cutoff time.Time) []string {
	var out []string
	for _, z := range zoneOrder {
		zw := zones[z]
		if zw == nil || zw.leaving > 0 || zw.pending > 0 || adding[z] > 0 {
			continue
		}
		pick, oldest := "", cutoff
		for _, n := range zw.live {
			if t, ok := born[n.Name]; ok && n.Status.State == v1.StateServing && t.Before(oldest) {
				pick, oldest = n.Name, t
			}
		}
		if pick != "" {
			out = append(out, pick)
		}
	}
	return out
}

// workerPlan is what one pass changes in a pool.
type workerPlan struct {
	add    map[string]int
	remove string // a worker to decommission
	why    string // why remove goes, for its decommission
	calm   bool   // members known and no zone short: old machines may retire
}

// Reasons a worker is decommissioned by the scaler.
const (
	whyScaleDown = "scale-down: its zone has twice the room the pool keeps free"
	whyUnplaced  = "never got a machine, and its zone has its workers and room again"
)

// floorOrder is the order the floor fills zones in: zones with no worker
// held by a failed preflight first, spec order kept. When the pool's
// maximum leaves fewer slots than zones need, a zone with nothing at all
// gets one before a zone whose worker failed in place and may come back by
// itself. Found by the rotation drill (Phase 3, run p3-drills-2): with
// minWorkers = maxWorkers = 3, a failed worker's zone took the last slot
// and another zone was left with no worker.
func floorOrder(zoneOrder []string, zones map[string]*zoneWorkers) []string {
	out := make([]string, 0, len(zoneOrder))
	for _, failedFirst := range []bool{false, true} {
		for _, z := range zoneOrder {
			if (zones[z].failed > 0) == failedFirst {
				out = append(out, z)
			}
		}
	}
	return out
}

// wantedWorkers decides one pass for a pool: the floor in every zone; one
// more worker in a zone short of room with nothing already on its way; and
// at most one decommission per pass, only when every zone is fine.
func wantedWorkers(zoneOrder []string, pool *v1.WorkerPoolSpec, zones map[string]*zoneWorkers, total int, haveMembers bool) workerPlan {
	plan := workerPlan{add: map[string]int{}}
	floor := ceilDiv(int(pool.MinWorkers), len(zoneOrder))
	need := float64(pool.HeadroomPercent+pool.ZoneLossReservePercent) / 100
	room := func() bool { return pool.MaxWorkers <= 0 || total < int(pool.MaxWorkers) }
	for _, z := range floorOrder(zoneOrder, zones) {
		zw := zones[z]
		for len(zw.live)+plan.add[z] < floor && room() {
			plan.add[z]++
			total++
		}
	}
	short := false
	for _, z := range zoneOrder {
		zw := zones[z]
		if !haveMembers || zw.pending > 0 || plan.add[z] > 0 || !zw.known {
			continue
		}
		if zw.freeShare() < need {
			short = true
			if room() {
				plan.add[z]++
				total++
			}
		}
	}
	plan.calm = haveMembers && !short
	// A worker whose pod never got a machine, in a zone whose serving
	// workers make its floor with twice the room the pool keeps free: it
	// is not needed, and it holds a slot of the pool's maximum. A failed
	// worker that came back leaves one behind (it was the failed one's
	// replacement), and without a cluster autoscaler it would wait for a
	// machine forever while its slot kept another zone empty.
	if haveMembers {
		for _, z := range zoneOrder {
			zw := zones[z]
			if len(zw.unplaced) == 0 || !zw.known || plan.add[z] > 0 {
				continue
			}
			if len(zw.live)-zw.pending >= floor && zw.freeShare() >= 2*need {
				plan.remove, plan.why = zw.unplaced[0], whyUnplaced
				return plan
			}
		}
	}
	if !plan.calm || need <= 0 {
		return plan
	}
	// Scale down: the zone with the most spare room, if it holds twice
	// what the pool keeps free and stays above its floor.
	var best string
	bestShare := 0.0
	for _, z := range zoneOrder {
		zw := zones[z]
		if !zw.known || zw.pending > 0 || zw.leaving > 0 || len(zw.live) <= floor {
			continue
		}
		if s := zw.freeShare(); s >= 2*need && s > bestShare {
			best, bestShare = z, s
		}
	}
	if best == "" {
		return plan
	}
	// The emptiest serving worker there: the fewest sandboxes to move.
	cands := append([]v1.AerolNode(nil), zones[best].live...)
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].Status.Sandboxes < cands[j].Status.Sandboxes })
	for _, n := range cands {
		if n.Status.State == v1.StateServing {
			plan.remove, plan.why = n.Name, whyScaleDown
			break
		}
	}
	return plan
}

func ceilDiv(a, b int) int {
	if b <= 0 {
		return a
	}
	return (a + b - 1) / b
}

// markDecommission starts a worker's decommission (C9); the node controller
// carries it out.
func (r *ClusterReconciler) markDecommission(ctx context.Context, c *v1.AerolCluster, name, why string) error {
	var n v1.AerolNode
	if err := r.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: name}, &n); err != nil {
		return client.IgnoreNotFound(err)
	}
	if n.Annotations[v1.AnnotationDecommission] == "true" {
		return nil
	}
	patch := client.MergeFrom(n.DeepCopy())
	if n.Annotations == nil {
		n.Annotations = map[string]string{}
	}
	n.Annotations[v1.AnnotationDecommission] = "true"
	if err := r.Patch(ctx, &n, patch); err != nil {
		return err
	}
	r.event(&n, corev1.EventTypeNormal, "Decommission", fmt.Sprintf("decommission started: %s", why))
	return nil
}

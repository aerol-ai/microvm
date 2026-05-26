package cluster

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// capacityRequestFromSpec normalizes a replicated CreateSandboxRequest into the
// capacity.Request placement scoring expects. Centralized so the failover-
// recreate paths (dead_owner.go, owner_watcher.go) and the create-time
// placement path (cluster_handler.go capacityRequestFromCreate) cannot drift —
// a recreated sandbox that requests fewer resources than the original would
// silently lose its disk/GPU/runtime gating.
func capacityRequestFromSpec(spec *models.CreateSandboxRequest) capacity.Request {
	if spec == nil {
		return capacity.Request{CPU: models.DefaultCPU, MemoryMB: models.DefaultMemoryMB, DiskGB: models.DefaultDiskGB}
	}
	cpu := spec.CPU
	mem := spec.MemoryMB
	disk := spec.DiskGB
	if cpu <= 0 {
		cpu = models.DefaultCPU
	}
	if mem <= 0 {
		mem = models.DefaultMemoryMB
	}
	if disk <= 0 {
		disk = models.DefaultDiskGB
	}
	runtimeName := strings.TrimSpace(spec.Runtime)
	templateID := strings.TrimSpace(spec.TemplateID)
	if templateID != "" && runtimeName == "" {
		runtimeName = models.RuntimeFirecracker
	}
	out := capacity.Request{
		CPU:        cpu,
		MemoryMB:   mem,
		DiskGB:     diskGBForCapacity(disk, runtimeName, spec.OverlaySizeGB),
		Runtime:    runtimeName,
		TemplateID: templateID,
	}
	if spec.GPUs != nil {
		want := spec.GPUs.Count
		if want <= 0 {
			want = 1
		}
		out.GPUs = want
		out.GPUVendor = string(spec.GPUs.Vendor)
	}
	return out
}

func diskGBForCapacity(base int, runtimeName string, overlaySizeGB int) int {
	if runtimeName == models.RuntimeFirecracker && overlaySizeGB > 0 {
		return base + overlaySizeGB
	}
	return base
}

// SelectPlacement chooses an owner node for a new sandbox using power-of-two-
// choices. The algorithm samples up to 2 random alive members (including self)
// and picks the one with the most CPU+memory headroom relative to the
// requested resources. This gives near-optimal load balancing without any
// global coordination — at scale it converges to within a small constant
// factor of the truly-optimal choice while costing O(1) per placement.
//
// Falls back to self if no alive members are visible yet (just-bootstrapped
// node) or if no other member can satisfy req. Self always loses ties because
// "place locally" is the existing single-node behavior; we only forward when
// a peer is genuinely better.
func (c *Cluster) SelectPlacement(req capacity.Request) (PlacementTarget, error) {
	all := c.membersWithCapacity()
	rejects := make(map[string]int64)
	if err := LargeClusterTopologyError(all); err != nil {
		rejects["topology"] = 1
		recordSchedulerDecision("invalid_topology", 0, rejects)
		return PlacementTarget{}, err
	}
	// Subtract still-in-flight reservations (router wrote opReserve but the
	// target hasn't yet promoted via opPlace, so the gossip ledger doesn't
	// reflect them) from each peer's headroom. Without this, two creates that
	// arrive between gossip ticks both pick the same "best" node and double-
	// book it. The FSM serializes opReserve through raft, so the second
	// SelectPlacement on the same leader sees the first reservation here.
	pending := c.fsm.pendingReservationsByNode(time.Now().Unix())
	// Drained nodes are excluded from the candidate set entirely. Cheaper and
	// clearer than threading the flag through nodeFits — drain is a hard
	// admission rule (operator says "don't put more work here"), not a
	// soft-scoring penalty. Self can be drained too; that's the intended way
	// to roll a node out of rotation without restarting it.
	drained := c.fsm.drainedNodesSnapshot()
	candidates := make([]Member, 0, len(all))
	for _, m := range all {
		if !m.Alive {
			rejects["dead"]++
			continue
		}
		if !CanOwnSandboxRole(m.Role) {
			rejects["role"]++
			continue
		}
		// Only consider members that have advertised an APIURL — others may
		// be partially-joined and forwarding to them would 502.
		if m.APIURL == "" && m.NodeID != c.nodeID {
			rejects["missing_api_url"]++
			continue
		}
		if m.CapacityStale || !hasCapacitySnapshot(m.Capacity) {
			rejects["capacity_heartbeat"]++
			continue
		}
		if drained[m.NodeID] {
			rejects["drained"]++
			continue
		}
		if !nodeFits(m, req, pending[m.NodeID]) {
			rejects["capacity"]++
			continue
		}
		candidates = append(candidates, m)
	}

	self := PlacementTarget{NodeID: c.nodeID, APIURL: c.apiURL, DataPlaneHost: c.dataPlaneHost, InternalURL: c.internalURL, IsSelf: true}
	if len(candidates) == 0 {
		recordSchedulerDecision("no_target", 0, rejects)
		return PlacementTarget{}, ErrNoPlacementTarget
	}

	// Power-of-two-choices.
	a, b := pickTwo(candidates)
	winner := a
	if !sameNode(a, b) && headroomScore(b, req, pending[b.NodeID]) > headroomScore(a, req, pending[a.NodeID]) {
		winner = b
	}

	if winner.NodeID == c.nodeID {
		recordSchedulerDecision("self", len(candidates), rejects)
		return self, nil
	}
	recordSchedulerDecision("remote", len(candidates), rejects)
	return PlacementTarget{
		NodeID:        winner.NodeID,
		APIURL:        winner.APIURL,
		DataPlaneHost: winner.DataPlaneHost,
		InternalURL:   winner.InternalURL,
		IsSelf:        false,
	}, nil
}

// nodeFits returns true if the member could plausibly accept req based on its
// latest capacity heartbeat. We use the budget numbers (post-overcommit)
// because that's what the remote admitter will check. extraReserved is the sum
// of in-flight reservations the cluster has against this node but the
// heartbeat doesn't yet reflect (zero value when none).
func nodeFits(m Member, req capacity.Request, extraReserved capacity.Request) bool {
	cap := m.Capacity
	if m.CapacityStale || !hasCapacitySnapshot(cap) {
		return false
	}
	if !cap.CanAdmit && len(cap.Reasons) > 0 {
		return false
	}
	if cap.CPUBudget > 0 && cap.ReservedCPU+extraReserved.CPU+req.CPU > cap.CPUBudget {
		return false
	}
	if cap.MemoryBudgetMB > 0 && cap.ReservedMemoryMB+extraReserved.MemoryMB+req.MemoryMB > cap.MemoryBudgetMB {
		return false
	}
	if cap.DiskBudgetGB > 0 && cap.ReservedDiskGB+extraReserved.DiskGB+req.DiskGB > cap.DiskBudgetGB {
		return false
	}
	// GPU and runtime are physical attributes — a peer that lacks them can
	// never satisfy the request, so we don't even forward. We only enforce
	// when the snapshot positively reports an inventory: an empty
	// SupportedRuntimes list (legacy peer) means "unknown, allow," matching
	// the rolling-upgrade behaviour the admitter uses on its own host.
	if req.GPUs > 0 {
		if cap.GPUCount < req.GPUs {
			return false
		}
		if req.GPUVendor != "" && cap.GPUVendor != "" && req.GPUVendor != cap.GPUVendor {
			return false
		}
	}
	if req.Runtime != "" && len(cap.SupportedRuntimes) > 0 {
		supported := false
		for _, r := range cap.SupportedRuntimes {
			if r == req.Runtime {
				supported = true
				break
			}
		}
		if !supported {
			return false
		}
	}
	// Phase 6 PR-D template-aware placement. A create that names a
	// template prefers a node that already has the artifacts cached —
	// the consumer-side puller (PR 6-B.2) can recover when placement
	// misses, but a hit avoids paying the docker-pull-from-AOCR window
	// on cold boot, preserving the <100ms boot property the runtime
	// exists to deliver.
	//
	// Unknown-allow rule (mirrors SupportedRuntimes above): empty
	// LocalTemplateIDs on the peer means a legacy or just-joined node
	// that hasn't reported its inventory yet; we don't gate, because
	// gating would strand creates on a fresh cluster. A non-empty list
	// missing the requested template is an authoritative "no" — that
	// peer reported its inventory and the template isn't in it.
	if req.TemplateID != "" && len(cap.LocalTemplateIDs) > 0 {
		hit := false
		for _, t := range cap.LocalTemplateIDs {
			if t == req.TemplateID {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// headroomScore is the metric power-of-two-choices compares. Larger is better.
// We combine CPU, memory, and (when reported) disk headroom (each as fraction
// of budget remaining) with equal weight; this produces a node that's "least
// full" along every axis the operator opted into. Disk only contributes when
// the peer advertises a budget so single-axis (CPU/memory) clusters keep their
// existing scoring behaviour.
func headroomScore(m Member, req capacity.Request, extraReserved capacity.Request) float64 {
	cap := m.Capacity
	if cap.HostCPUCores == 0 && cap.HostMemoryTotalMB == 0 {
		// Unknown capacity — neutral score so it ties with peers that have
		// reported, slightly preferred over fully-loaded ones.
		return 0.5
	}
	cpuScore := 1.0
	if cap.CPUBudget > 0 {
		cpuScore = (cap.CPUBudget - cap.ReservedCPU - extraReserved.CPU - req.CPU) / cap.CPUBudget
	}
	memScore := 1.0
	if cap.MemoryBudgetMB > 0 {
		memScore = float64(cap.MemoryBudgetMB-cap.ReservedMemoryMB-extraReserved.MemoryMB-req.MemoryMB) / float64(cap.MemoryBudgetMB)
	}
	if cap.DiskBudgetGB > 0 {
		diskScore := float64(cap.DiskBudgetGB-cap.ReservedDiskGB-extraReserved.DiskGB-req.DiskGB) / float64(cap.DiskBudgetGB)
		return (cpuScore + memScore + diskScore) / 3
	}
	return (cpuScore + memScore) / 2
}

// pickTwo returns two distinct candidates if possible, else duplicates the
// only available one. Uses math/rand — Phase 1 is single-tenant operator-
// owned so adversarial placement bias is not in the threat model.
func pickTwo(c []Member) (Member, Member) {
	if len(c) == 1 {
		return c[0], c[0]
	}
	i := rand.Intn(len(c))
	j := rand.Intn(len(c) - 1)
	if j >= i {
		j++
	}
	return c[i], c[j]
}

func sameNode(a, b Member) bool { return a.NodeID == b.NodeID }

func (c *Cluster) admitReservationCommand(cmd command) error {
	reservations := reservationCommands(cmd)
	if len(reservations) == 0 {
		return nil
	}
	now := time.Now().Unix()
	pending := c.fsm.pendingReservationsByNode(now)
	pendingCounts := make(map[string]int, len(reservations))
	for _, r := range reservations {
		if _, ok := pendingCounts[r.OwnerNodeID]; !ok {
			pendingCounts[r.OwnerNodeID] = c.fsm.livePendingReservationCount(r.OwnerNodeID, now)
		}
	}
	return admitReservationCommands(c.membersWithCapacity(), pending, pendingCounts, c.cfg.ClusterCreateMaxPendingPerWorker, reservations)
}

func admitReservationCommands(members []Member, pending map[string]capacity.Request, pendingCounts map[string]int, maxPendingPerWorker int, reservations []reservationCommand) error {
	byID := make(map[string]Member, len(members))
	for _, m := range members {
		if m.NodeID != "" {
			byID[m.NodeID] = m
		}
	}
	batchPending := make(map[string]capacity.Request)
	batchCounts := make(map[string]int)
	for _, r := range reservations {
		if r.SandboxID == "" || r.OwnerNodeID == "" {
			return fmt.Errorf("%w: reservation missing sandbox_id or owner_node_id", ErrReservationConflict)
		}
		m, ok := byID[r.OwnerNodeID]
		if !ok || !m.Alive || !CanOwnSandboxRole(m.Role) {
			return fmt.Errorf("%w: worker %s is not an alive placement target", ErrNoPlacementTarget, r.OwnerNodeID)
		}
		if m.CapacityStale || !hasCapacitySnapshot(m.Capacity) {
			return fmt.Errorf("%w: worker %s has no fresh capacity heartbeat", ErrNoPlacementTarget, r.OwnerNodeID)
		}
		if maxPendingPerWorker > 0 && pendingCounts[r.OwnerNodeID]+batchCounts[r.OwnerNodeID] >= maxPendingPerWorker {
			return fmt.Errorf("%w: worker %s has %d pending creates (cap %d)",
				ErrCreateBackpressure, r.OwnerNodeID, pendingCounts[r.OwnerNodeID]+batchCounts[r.OwnerNodeID], maxPendingPerWorker)
		}
		req := capacityRequestFromSpec(r.Spec)
		extra := pending[r.OwnerNodeID]
		batchExtra := batchPending[r.OwnerNodeID]
		extra.CPU += batchExtra.CPU
		extra.MemoryMB += batchExtra.MemoryMB
		extra.DiskGB += batchExtra.DiskGB
		extra.GPUs += batchExtra.GPUs
		if !nodeFits(m, req, extra) {
			return fmt.Errorf("%w: worker %s cannot fit sandbox %s", ErrCapacityExceeded, r.OwnerNodeID, r.SandboxID)
		}
		batchExtra.CPU += req.CPU
		batchExtra.MemoryMB += req.MemoryMB
		batchExtra.DiskGB += req.DiskGB
		batchExtra.GPUs += req.GPUs
		batchPending[r.OwnerNodeID] = batchExtra
		batchCounts[r.OwnerNodeID]++
	}
	return nil
}

// CanOwnSandboxRole reports whether a gossiped node role may own sandboxes.
// Empty is treated as worker-capable for rolling upgrades from builds that
// did not advertise role metadata.
func CanOwnSandboxRole(role string) bool {
	trimmed := strings.TrimSpace(role)
	if trimmed == "" {
		return true
	}
	for raw := range strings.SplitSeq(trimmed, ",") {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case config.NodeRoleWorker, config.NodeRoleMixed:
			return true
		}
	}
	return false
}

// CanServeControlPlaneRole reports whether a gossiped node role may host the
// authoritative Raft/FSM control plane. Empty is treated as server-capable for
// rolling upgrades from builds that did not advertise role metadata.
func CanServeControlPlaneRole(role string) bool {
	trimmed := strings.TrimSpace(role)
	if trimmed == "" {
		return true
	}
	for raw := range strings.SplitSeq(trimmed, ",") {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case config.NodeRoleServer, config.NodeRoleMixed:
			return true
		}
	}
	return false
}

// CanServeIngressRole reports whether a gossiped node role may host public
// ingress routes. Empty is treated as ingress-capable for rolling upgrades
// from builds that did not advertise role metadata.
func CanServeIngressRole(role string) bool {
	trimmed := strings.TrimSpace(role)
	if trimmed == "" {
		return true
	}
	for raw := range strings.SplitSeq(trimmed, ",") {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case config.NodeRoleIngress, config.NodeRoleMixed:
			return true
		}
	}
	return false
}

// SelectPlacement on Noop is in noop.go.

// Sanity: the package-level SelectPlacement signature matches the Client interface.
var _ = func() error {
	var _ Client = (*Cluster)(nil)
	var _ Client = (*Agent)(nil)
	var _ Client = (*Noop)(nil)
	return errors.New("type assertion only, never returned")
}

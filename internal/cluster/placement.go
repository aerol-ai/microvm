package cluster

import (
	"errors"
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
	out := capacity.Request{CPU: cpu, MemoryMB: mem, DiskGB: disk, Runtime: spec.Runtime}
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
	all := c.gossip.members()
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
// gossiped capacity snapshot. We use the budget numbers (post-overcommit)
// because that's what the remote admitter will check. extraReserved is the sum
// of in-flight reservations the cluster has against this node but the gossip
// ledger doesn't yet reflect (zero value when none).
func nodeFits(m Member, req capacity.Request, extraReserved capacity.Request) bool {
	cap := m.Capacity
	// If the snapshot is zero-valued (no advertisement yet), treat as
	// unknown-but-allowed: better to forward and let the remote admitter
	// reject than to skip a viable peer.
	if cap.HostCPUCores == 0 && cap.HostMemoryTotalMB == 0 {
		return true
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

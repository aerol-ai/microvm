package cluster

import (
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
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
	if runtimeName == "" {
		runtimeName = models.RuntimeDocker
	}
	out := capacity.Request{
		CPU:        cpu,
		MemoryMB:   mem,
		DiskGB:     diskGBForCapacity(disk, runtimeName, spec.OverlaySizeGB),
		Runtime:    runtimeName,
		TemplateID: templateID,
		ModuleRef:  models.ModuleRefForCreate(*spec),
	}
	if nodeID, ok := docker.BuiltImagePlacementNode(spec.Image); ok {
		out.RequiredNodeID = nodeID
	}
	if runtimeName == models.RuntimeIsolate {
		if nodeID, _, ok := models.ParseJSBundleNodeRef(out.ModuleRef); ok {
			out.RequiredNodeID = nodeID
		}
	}
	if runtimeName == models.RuntimeWasm {
		out.MemoryMB += 8
	}
	// A recreate of a hostname-filtered sandbox needs a gateway as much as
	// its first create did: failover must not land it on a node that can
	// only answer 501.
	out.NeedsEgressGateway = models.RuntimeUsesEgressGateway(runtimeName) &&
		egresspolicy.NeedsGatewayWith(spec.NetworkAllowOut, spec.NetworkDenyOut, spec.NetworkBlockAll,
			spec.NetworkEgressMode == models.NetworkEgressModeLearn, len(spec.EgressProfiles))
	// WASM and isolate filter in their own mediators, which an older peer
	// lacks: it would store the policy and ignore it (review finding 10).
	out.NeedsMediatedEgress = models.RuntimeMediatesEgress(runtimeName) && models.CreateHasEgress(spec)
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
	target, _, err := c.SelectPlacementWithCandidates(req)
	return target, err
}

// SelectPlacementWithCandidates is SelectPlacement plus the filtered candidate
// slice the router uses to record the secret recipient set at reserve time
// (plans/secrets-hardening §3d-1). The target is always one of candidates.
func (c *Cluster) SelectPlacementWithCandidates(req capacity.Request) (PlacementTarget, []Member, error) {
	all := c.withCatalogueTemplateHolders(c.membersWithCapacity(), req.TemplateID)
	rejects := make(map[string]int64)
	if err := LargeClusterTopologyError(all); err != nil {
		rejects["topology"] = 1
		recordSchedulerDecision("invalid_topology", 0, rejects)
		return PlacementTarget{}, nil, err
	}
	// Subtract still-in-flight reservations (router wrote opReserve but the
	// target hasn't yet promoted via opPlace, so the gossip ledger doesn't
	// reflect them) from each peer's headroom. Without this, two creates that
	// arrive between gossip ticks both pick the same "best" node and double-
	// book it. The FSM serializes opReserve through raft, so the second
	// SelectPlacement on the same leader sees the first reservation here.
	pending, pendingRuntimes := c.fsm.pendingReservationLoadByNode(time.Now().Unix())
	// Drained nodes are excluded from the candidate set entirely. Cheaper and
	// clearer than threading the flag through nodeFits — drain is a hard
	// admission rule (operator says "don't put more work here"), not a
	// soft-scoring penalty. Self can be drained too; that's the intended way
	// to roll a node out of rotation without restarting it.
	drained := c.fsm.drainedNodesSnapshot()
	candidates := make([]Member, 0, len(all))
	// requiredReachable records whether the artifact-bound node, if any, was
	// seen as a live capacity-reporting member. If it was and still produced
	// no candidate, the failure is ordinary (capacity, drain); if it was not,
	// the artifact itself is out of reach and the client must re-create it.
	requiredReachable := false
	// full records that a live, eligible worker able to run the request was
	// turned away only for room (CPU, memory, disk, live memory, or a full
	// network-slot pool). An empty candidate set with one is a cluster at
	// capacity — ErrClusterAtCapacity — not an unexplained "no target".
	full := false
	for _, m := range all {
		if !m.Alive {
			rejects["dead"]++
			continue
		}
		if !CanOwnSandboxRole(m.Role) {
			rejects["role"]++
			continue
		}
		if req.RequiredNodeID != "" && m.NodeID != req.RequiredNodeID {
			rejects["artifact_affinity"]++
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
		if req.RequiredNodeID != "" && m.NodeID == req.RequiredNodeID {
			requiredReachable = true
		}
		if drained[m.NodeID] {
			rejects["drained"]++
			continue
		}
		// A hard capability rule like drain, kept out of nodeFits so the
		// empty-set error can name it: "no gateway" is not "cluster full".
		if req.NeedsEgressGateway && !m.Capacity.EgressGatewayReady {
			rejects["egress_gateway"]++
			continue
		}
		if req.NeedsMediatedEgress && !m.Capacity.MediatedEgress {
			rejects["mediated_egress"]++
			continue
		}
		switch nodeFitVerdict(m, req, pending[m.NodeID]) {
		case fitIncompatible:
			rejects["capacity"]++
			continue
		case fitNoRoom:
			rejects["capacity"]++
			full = true
			continue
		}
		// A node with CPU and memory to spare is still full for this
		// runtime when its network-slot pool is: the create would fail
		// there with "no free slot" (bank density run, 2026-11-01).
		if !slotsFit(m, req, pendingRuntimes[m.NodeID]) {
			rejects["network_slots"]++
			full = true
			continue
		}
		candidates = append(candidates, m)
	}

	self := PlacementTarget{NodeID: c.nodeID, APIURL: c.apiURL, DataPlaneHost: c.dataPlaneHost, InternalURL: c.internalURL, IsSelf: true}
	if len(candidates) == 0 {
		recordSchedulerDecision("no_target", 0, rejects)
		return PlacementTarget{}, nil, noPlacementTargetError(req, requiredReachable, rejects["egress_gateway"] > 0, full)
	}

	// Power-of-two-choices.
	a, b := pickTwo(candidates)
	winner := a
	if !sameNode(a, b) && placementScore(b, req, pending[b.NodeID], pendingRuntimes[b.NodeID]) > placementScore(a, req, pending[a.NodeID], pendingRuntimes[a.NodeID]) {
		winner = b
	}

	if winner.NodeID == c.nodeID {
		recordSchedulerDecision("self", len(candidates), rejects)
		return self, candidates, nil
	}
	recordSchedulerDecision("remote", len(candidates), rejects)
	return PlacementTarget{
		NodeID:        winner.NodeID,
		APIURL:        winner.APIURL,
		DataPlaneHost: winner.DataPlaneHost,
		InternalURL:   winner.InternalURL,
		IsSelf:        false,
	}, candidates, nil
}

func normalizeSecretRecipientIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func sameSecretRecipientSet(a, b []string) bool {
	a = normalizeSecretRecipientIDs(a)
	b = normalizeSecretRecipientIDs(b)
	if len(a) != len(b) {
		return false
	}
	want := make(map[string]struct{}, len(a))
	for _, id := range a {
		want[id] = struct{}{}
	}
	for _, id := range b {
		if _, ok := want[id]; !ok {
			return false
		}
	}
	return true
}

// SelectSecretRecipients builds the seal recipient set: owner first, then up
// to maxBackups other candidates chosen by deterministic rendezvous hashing
// over (sandboxID, nodeID). Sorting by NodeID alone hotspot-loads the
// lexicographically first workers; HRW spreads backup rows evenly while
// remaining stable for a given sandbox.
// When the cluster is smaller than owner+maxBackups, every eligible candidate
// is included. Empty ownerID or candidates yields nil.
func SelectSecretRecipients(sandboxID string, candidates []Member, ownerID string, maxBackups int) []string {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" || len(candidates) == 0 {
		return nil
	}
	if maxBackups < 0 {
		maxBackups = 0
	}
	seen := map[string]struct{}{ownerID: {}}
	out := []string{ownerID}
	type scored struct {
		id    string
		score uint64
	}
	rest := make([]scored, 0, len(candidates))
	for _, m := range candidates {
		id := strings.TrimSpace(m.NodeID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		rest = append(rest, scored{id: id, score: secretRecipientScore(sandboxID, id)})
	}
	sort.SliceStable(rest, func(i, j int) bool {
		if rest[i].score != rest[j].score {
			return rest[i].score > rest[j].score
		}
		return rest[i].id < rest[j].id
	})
	if maxBackups > len(rest) {
		maxBackups = len(rest)
	}
	for i := 0; i < maxBackups; i++ {
		out = append(out, rest[i].id)
	}
	return out
}

// secretRecipientScore is highest-random-weight (rendezvous) hashing so each
// sandbox picks a stable, evenly distributed backup set. FNV alone can
// correlate on sequential IDs; a splitmix-style finalizer removes that skew.
func secretRecipientScore(sandboxID, nodeID string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.TrimSpace(sandboxID)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.TrimSpace(nodeID)))
	x := h.Sum64()
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// fitVerdict is nodeFitVerdict's answer. The two refusals are told apart so
// an empty candidate set can say "at capacity" only when some worker that can
// run the request is merely full, never when none can run it at all.
type fitVerdict int

const (
	fitOK fitVerdict = iota
	// fitIncompatible: the peer can never run req (runtime, GPU inventory,
	// template or module not here), or has no fresh heartbeat.
	fitIncompatible
	// fitNoRoom: the peer can run req but its budgets are spent right now.
	fitNoRoom
)

// nodeFits returns true if the member could plausibly accept req based on its
// latest capacity heartbeat. We use the budget numbers (post-overcommit)
// because that's what the remote admitter will check. extraReserved is the sum
// of in-flight reservations the cluster has against this node but the
// heartbeat doesn't yet reflect (zero value when none).
//
// Parked warm-pool slots are left out of the reserved side: the worker's
// admitter reclaims them for a real sandbox, so counting them made a node the
// pool had filled look full to every create it could have served. A peer that
// does not report Parked* reads as zero, which is the old accounting.
// headroomScore still counts them, so a node with genuinely free room wins
// before warm slots are given up.
//
// Network slots are a separate check (slotsFit): they are counted per pool,
// not as one aggregate, so they need the per-runtime pending counts.
func nodeFits(m Member, req capacity.Request, extraReserved capacity.Request) bool {
	return nodeFitVerdict(m, req, extraReserved) == fitOK
}

// nodeFitVerdict is nodeFits with the reason. The static checks run first, so
// a peer that cannot run req reads as incompatible even when it is also full.
func nodeFitVerdict(m Member, req capacity.Request, extraReserved capacity.Request) fitVerdict {
	cap := m.Capacity
	if m.CapacityStale || !hasCapacitySnapshot(cap) {
		return fitIncompatible
	}
	// GPU and runtime are physical attributes — a peer that lacks them can
	// never satisfy the request, so we don't even forward. We only enforce
	// when the snapshot positively reports an inventory: an empty
	// SupportedRuntimes list (legacy peer) means "unknown, allow," matching
	// the rolling-upgrade behaviour the admitter uses on its own host.
	if req.GPUs > 0 {
		if cap.GPUCount < req.GPUs {
			return fitIncompatible
		}
		if req.GPUVendor != "" && cap.GPUVendor != "" && req.GPUVendor != cap.GPUVendor {
			return fitIncompatible
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
			return fitIncompatible
		}
	}
	// Phase 6 PR-D template-aware placement. A create that names a
	// template prefers a node that already has the artifacts cached —
	// the consumer-side puller (PR 6-B.2) can recover when placement
	// misses, but a hit avoids paying the docker-pull-from-AOCR window
	// on cold boot, preserving the <100ms boot property the runtime
	// exists to deliver.
	//
	// Unknown-allow rule (mirrors SupportedRuntimes above): a peer with
	// LocalTemplateInventoryKnown=false is legacy or just-joined and we
	// don't gate. Once LocalTemplateInventoryKnown=true, an empty list is
	// an authoritative "no templates here" and a non-empty list missing
	// the requested template is an authoritative "no" for that template.
	if req.TemplateID != "" && cap.LocalTemplateInventoryKnown {
		hit := false
		for _, t := range cap.LocalTemplateIDs {
			if t == req.TemplateID {
				hit = true
				break
			}
		}
		if !hit {
			return fitIncompatible
		}
	}
	if req.Runtime == models.RuntimeWasm && req.ModuleRef != "" && cap.LocalWasmModuleInventoryKnown {
		hit := false
		for _, ref := range cap.LocalWasmModuleIDs {
			if ref == req.ModuleRef {
				hit = true
				break
			}
		}
		if !hit {
			return fitIncompatible
		}
	}
	if !cap.CanAdmit && len(cap.Reasons) > 0 {
		return fitNoRoom
	}
	reservedCPU := max(cap.ReservedCPU-cap.ParkedCPU, 0)
	reservedMemMB := max(cap.ReservedMemoryMB-cap.ParkedMemoryMB, 0)
	reservedDiskGB := max(cap.ReservedDiskGB-cap.ParkedDiskGB, 0)
	if cap.CPUBudget > 0 && reservedCPU+extraReserved.CPU+req.CPU > cap.CPUBudget {
		return fitNoRoom
	}
	if cap.MemoryBudgetMB > 0 && reservedMemMB+extraReserved.MemoryMB+req.MemoryMB > cap.MemoryBudgetMB {
		return fitNoRoom
	}
	if cap.DiskBudgetGB > 0 && reservedDiskGB+extraReserved.DiskGB+req.DiskGB > cap.DiskBudgetGB {
		return fitNoRoom
	}
	return fitOK
}

// freeSlotsAfterPending returns how many slots m's pool for req.Runtime has
// left once the reservations in flight to m are counted, and the pool's size.
// Every runtime the pool serves counts: on a containerd node a pending gVisor
// create takes a netns a docker create could have had. ok=false when m reports
// no pool for the runtime.
func freeSlotsAfterPending(m Member, req capacity.Request, pendingByRuntime map[string]int) (free, total int, ok bool) {
	pool, ok := m.Capacity.SlotPoolFor(req.Runtime)
	if !ok {
		return 0, 0, false
	}
	free = pool.Free
	for _, rt := range pool.Runtimes {
		free -= pendingByRuntime[rt]
	}
	return free, pool.Total, true
}

// slotsFit reports whether m has a network slot for req after its in-flight
// reservations. A peer that reports no pool for the runtime — an older build,
// or a runtime with no bounded pool — is not gated ("unknown, allow", like an
// empty SupportedRuntimes), so a rolling upgrade places exactly as before.
//
// The heartbeat can lag a create that has already been promoted (the pending
// claim is gone, the next pull has not run): within one capacity interval a
// node can still be picked for its last slots. The worker then refuses with
// its pool's capacity error (503 + Retry-After) and the retry is placed again;
// that is the same window CPU and memory accounting have.
func slotsFit(m Member, req capacity.Request, pendingByRuntime map[string]int) bool {
	free, _, ok := freeSlotsAfterPending(m, req, pendingByRuntime)
	return !ok || free >= 1
}

// headroomScore is the metric power-of-two-choices compares. Larger is better.
// We combine CPU, memory, and (when reported) disk headroom (each as fraction
// of budget remaining) with equal weight; this produces a node that's "least
// full" along every axis the operator opted into. Disk only contributes when
// the peer advertises a budget so single-axis (CPU/memory) clusters keep their
// existing scoring behaviour.
func headroomScore(m Member, req capacity.Request, extraReserved capacity.Request) float64 {
	sum, axes, known := headroomAxes(m, req, extraReserved)
	if !known {
		// Unknown capacity — neutral score so it ties with peers that have
		// reported, slightly preferred over fully-loaded ones.
		return 0.5
	}
	return sum / float64(axes)
}

// headroomAxes returns the sum of headroomScore's per-axis fractions and how
// many axes it summed; known=false for a peer that reported no host size.
func headroomAxes(m Member, req capacity.Request, extraReserved capacity.Request) (sum float64, axes int, known bool) {
	cap := m.Capacity
	if cap.HostCPUCores == 0 && cap.HostMemoryTotalMB == 0 {
		return 0, 0, false
	}
	cpuScore := 1.0
	if cap.CPUBudget > 0 {
		cpuScore = (cap.CPUBudget - cap.ReservedCPU - extraReserved.CPU - req.CPU) / cap.CPUBudget
	}
	memScore := 1.0
	if cap.MemoryBudgetMB > 0 {
		memScore = float64(cap.MemoryBudgetMB-cap.ReservedMemoryMB-extraReserved.MemoryMB-req.MemoryMB) / float64(cap.MemoryBudgetMB)
	}
	sum, axes = cpuScore+memScore, 2
	if cap.DiskBudgetGB > 0 {
		sum += float64(cap.DiskBudgetGB-cap.ReservedDiskGB-extraReserved.DiskGB-req.DiskGB) / float64(cap.DiskBudgetGB)
		axes++
	}
	return sum, axes, true
}

// placementScore is headroomScore with the request's network-slot pool as one
// more equal axis when the peer reports one. Without it a big host keeps
// winning on CPU and memory until its pool is empty, and the fleet's last
// slots are all spent on the node whose heartbeat is most likely to lag; with
// it, a host whose pool is nearly spent gives way to one with slots left.
func placementScore(m Member, req capacity.Request, extraReserved capacity.Request, pendingByRuntime map[string]int) float64 {
	sum, axes, known := headroomAxes(m, req, extraReserved)
	if !known {
		return headroomScore(m, req, extraReserved)
	}
	if free, total, ok := freeSlotsAfterPending(m, req, pendingByRuntime); ok && total > 0 {
		sum += float64(free-1) / float64(total)
		axes++
	}
	return sum / float64(axes)
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
	pending, pendingRuntimes := c.fsm.pendingReservationLoadByNode(now)
	pendingCounts := make(map[string]int, len(reservations))
	for _, r := range reservations {
		if _, ok := pendingCounts[r.OwnerNodeID]; !ok {
			pendingCounts[r.OwnerNodeID] = c.fsm.livePendingReservationCount(r.OwnerNodeID, now)
		}
	}
	templateIDs := make([]string, 0, len(reservations))
	for _, r := range reservations {
		if r.Spec != nil {
			templateIDs = append(templateIDs, r.Spec.TemplateID)
		}
	}
	members := c.withCatalogueTemplateHolders(c.membersWithCapacity(), templateIDs...)
	return admitReservationCommands(members, pending, pendingRuntimes, pendingCounts, c.cfg.ClusterCreateMaxPendingPerWorker, reservations)
}

// withCatalogueTemplateHolders adds each templateID to the ready-template
// inventory of every member the replicated artifact catalogue says holds it.
//
// The template filter in nodeFits trusts LocalTemplateIDs, which is gossiped
// on the capacity heartbeat. So for up to a heartbeat after a template
// becomes ready, every node reads as an authoritative "no" and a create from
// it fails with ErrNoPlacementTarget. T19's S5 re-run hit exactly that on
// UC-80: the template GET (#498) worked, and the create straight after found
// no target. The catalogue is published before CreateTemplate answers (#496),
// so it names the holder without waiting for gossip. Readiness stays the
// owner's call: its CreateSandbox reads the template row locally, so a holder
// whose build is still running refuses the create with a real error instead
// of the fleet reporting "no capacity".
//
// Members are returned as copies with fresh slices. Gossip snapshots are
// shared, and appending in place would leak the addition into them.
func (c *Cluster) withCatalogueTemplateHolders(members []Member, templateIDs ...string) []Member {
	if c == nil || c.fsm == nil || len(members) == 0 {
		return members
	}
	add := make(map[string][]string)
	seen := make(map[string]bool, len(templateIDs))
	for _, id := range templateIDs {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		for _, nodeID := range c.fsm.artifactCatalogHolders(ArtifactKindTemplate, "", id) {
			add[nodeID] = append(add[nodeID], id)
		}
	}
	if len(add) == 0 {
		return members
	}
	out := make([]Member, len(members))
	copy(out, members)
	for i := range out {
		ids := add[out[i].NodeID]
		// An unknown inventory already admits every template ("unknown,
		// allow"); only an authoritative list can wrongly exclude.
		if len(ids) == 0 || !out[i].Capacity.LocalTemplateInventoryKnown {
			continue
		}
		have := make(map[string]bool, len(out[i].Capacity.LocalTemplateIDs))
		for _, t := range out[i].Capacity.LocalTemplateIDs {
			have[t] = true
		}
		merged := append([]string(nil), out[i].Capacity.LocalTemplateIDs...)
		for _, id := range ids {
			if !have[id] {
				merged = append(merged, id)
			}
		}
		out[i].Capacity.LocalTemplateIDs = merged
	}
	return out
}

// admitReservationCommands re-checks each reservation in a command against
// its owner's fresh heartbeat plus everything already pending there,
// including earlier reservations in the same batch. pendingRuntimes is the
// FSM's per-owner, per-runtime pending count (network slots are per pool).
func admitReservationCommands(members []Member, pending map[string]capacity.Request, pendingRuntimes map[string]map[string]int, pendingCounts map[string]int, maxPendingPerWorker int, reservations []reservationCommand) error {
	byID := make(map[string]Member, len(members))
	for _, m := range members {
		if m.NodeID != "" {
			byID[m.NodeID] = m
		}
	}
	batchPending := make(map[string]capacity.Request)
	batchCounts := make(map[string]int)
	batchRuntimes := make(map[string]map[string]int)
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
		byRuntime := batchRuntimes[r.OwnerNodeID]
		if byRuntime == nil {
			byRuntime = make(map[string]int)
			for rt, n := range pendingRuntimes[r.OwnerNodeID] {
				byRuntime[rt] = n
			}
			batchRuntimes[r.OwnerNodeID] = byRuntime
		}
		if !slotsFit(m, req, byRuntime) {
			return fmt.Errorf("%w: worker %s has no free network slot for %s sandbox %s", ErrCapacityExceeded, r.OwnerNodeID, req.Runtime, r.SandboxID)
		}
		byRuntime[req.Runtime]++
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
// Invoked at init so the assignments stay covered (empty func bodies otherwise
// show as 0% under go cover's statement mode).
var _ = func() error {
	var _ Client = (*Cluster)(nil)
	var _ Client = (*Agent)(nil)
	var _ Client = (*Noop)(nil)
	return errors.New("type assertion only, never returned")
}()

// noPlacementTargetError picks the sentinel for an empty candidate set. A
// request bound to one node by an artifact fails as ErrArtifactNodeUnavailable
// when that node was not a live capacity-reporting member — the artifact is
// gone with it, and waiting will not bring it back.
//
// A gateway-mode create that lost at least one peer only to the gateway rule
// fails as ErrNoEgressGatewayTarget so the client is told why: some node may
// have had room, none could filter hostnames.
//
// Otherwise, when a worker that could run the request was turned away only
// for room (full), the cluster is at capacity: ErrClusterAtCapacity says so,
// and stays an ErrNoPlacementTarget for every existing 503 mapping.
func noPlacementTargetError(req capacity.Request, requiredReachable, gatewayRejected, full bool) error {
	if req.RequiredNodeID != "" && !requiredReachable {
		return fmt.Errorf("%w (node %q)", ErrArtifactNodeUnavailable, req.RequiredNodeID)
	}
	if req.NeedsEgressGateway && gatewayRejected {
		return ErrNoEgressGatewayTarget
	}
	if full {
		return ErrClusterAtCapacity
	}
	return ErrNoPlacementTarget
}

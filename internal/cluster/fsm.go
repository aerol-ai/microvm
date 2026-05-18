package cluster

import (
	"bytes"
	"container/heap"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// Operation codes for raft log entries.
type opCode uint8

const (
	opPlace             opCode = 1
	opDelete            opCode = 2
	opReassign          opCode = 3
	opUpsertSpec        opCode = 4  // overwrite Placement.Spec without touching ownership
	opAddExposedPort    opCode = 5  // record one (port, protocol) intent
	opRemoveExposedPort opCode = 6  // drop one port intent
	opReserve           opCode = 7  // hold capacity + name for a chosen owner before docker
	opCancelReserve     opCode = 8  // release a pending reservation (rollback or TTL GC)
	opSetNodeDrainState opCode = 9  // operator-set "exclude from placement" mark for a node
	opOrphanOwner       opCode = 10 // atomically orphan all placements owned by a dead node
	opClaimOrphan       opCode = 11 // reclaim an orphaned placement back to its previous owner
)

// command is the wire format for one raft log entry. Spec is non-nil for
// opPlace (records the original creation request alongside the owner pointer)
// and opUpsertSpec (records mutations like resize/lifecycle that must survive
// failover). Spec MUST be redacted of plaintext credentials before encoding —
// SealedSecrets carries the matching encrypted bag. Port/Protocol carry one
// (port, protocol) tuple for opAddExposedPort and opRemoveExposedPort —
// replicated as intent-only so the new owner picks a fresh host port from
// its own pool.
//
// SealedSecrets follows the same preserve-on-nil rule as Spec at the FSM
// level: an opPlace or opUpsertSpec that omits SealedSecrets does NOT erase
// a previously-replicated bag. That lets resize/lifecycle write-throughs
// (which never touch credentials) leave the sealed payload alone, and lets
// boot-time replays that have a spec but lost track of the sealed bytes
// avoid clobbering the original.
type command struct {
	Op                 opCode                       `json:"op"`
	SandboxID          string                       `json:"sandbox_id"`
	OwnerNodeID        string                       `json:"owner_node_id,omitempty"`
	OwnerAPIURL        string                       `json:"owner_api_url,omitempty"`
	OwnerDataPlaneHost string                       `json:"owner_data_plane_host,omitempty"`
	Spec               *models.CreateSandboxRequest `json:"spec,omitempty"`
	SealedSecrets      []byte                       `json:"sealed_secrets,omitempty"`
	Port               int                          `json:"port,omitempty"`
	Protocol           string                       `json:"protocol,omitempty"`
	HostPort           int                          `json:"host_port,omitempty"`
	PublicURL          string                       `json:"public_url,omitempty"`
	// ExpiresUnix is set on opReserve to bound how long a reservation holds
	// capacity before the leader GC sweep cancels it. Ignored by every other
	// op; promotion via opPlace clears the reservation's expiry implicitly by
	// transitioning State back to Placed.
	ExpiresUnix int64 `json:"expires_unix,omitempty"`
	// NodeID + Drained are populated by opSetNodeDrainState. NodeID is the
	// target of the drain mark; Drained is the desired state (true = exclude
	// from SelectPlacement, false = uncordon). All other ops leave them zero.
	NodeID  string `json:"node_id,omitempty"`
	Drained bool   `json:"drained,omitempty"`
}

func encodeCommand(c command) ([]byte, error) {
	return json.Marshal(c)
}

func decodeCommand(b []byte) (command, error) {
	var c command
	if err := json.Unmarshal(b, &c); err != nil {
		return command{}, err
	}
	return c, nil
}

// placementFSM is the raft.FSM implementation. It holds the entire placement
// map in-memory; persistence is provided by the raft log + snapshots. The map
// is small (one row per sandbox; row size ~150 bytes), so even a 10K-node
// fleet with 100 sandboxes/node fits comfortably in RAM.
type placementFSM struct {
	mu         sync.RWMutex
	placements map[string]Placement
	version    uint64
	// nameIndex maps sandbox Name → SandboxID for cluster-wide name uniqueness.
	// Empty names are NOT indexed (anonymous sandboxes don't conflict, matching
	// the local SQLite partial unique index that allows many empty names but
	// rejects duplicate non-empty names). Updated inside Apply alongside the
	// placement write so the index can never lag the authoritative map; rebuilt
	// from placements on Restore so older snapshots without an index still load.
	nameIndex map[string]string
	// shardIndex maps stable placement shard -> sandbox IDs in that shard.
	// Ingress/control-plane reads use this to pull a bounded slice instead of
	// scanning/copying the entire placement map for every shard-owned worker.
	// The shard ID derives only from SandboxID, so ownership/spec/port changes
	// update the placement row without touching this index.
	shardIndex map[int]map[string]struct{}
	// hostPortIndex maps a raw-TCP public host port to the placement exposure
	// that owns it. This is the cluster-wide raw TCP capacity index: AddPort
	// rejects collisions in O(1) under the FSM lock instead of scanning every
	// placement at 100k-row scale.
	hostPortIndex map[int]hostPortClaim
	// ownerIndex maps active owner nodeID -> placed sandbox IDs. Dead-owner
	// eviction reads this instead of scanning the full placement table. Pending
	// reservations are tracked separately below because they are capacity
	// holds, not materialized sandboxes.
	ownerIndex map[string]map[string]struct{}
	// pendingReservationClaims is the per-reservation ledger behind
	// pendingReservationCapacity. SelectPlacement reads the aggregate instead
	// of scanning every placement row on each create. Expiries are tracked in
	// pendingReservationExpiries so stale reservations can be removed lazily in
	// O(expired log reservations) without waiting for the leader GC sweep.
	pendingReservationClaims     map[string]pendingReservationClaim
	pendingReservationCapacity   map[string]capacity.Request
	pendingReservationIDsByOwner map[string]map[string]struct{}
	pendingReservationExpiries   pendingReservationExpiryHeap
	// drainedNodes holds the set of nodeIDs an operator has marked as
	// "exclude from SelectPlacement candidate set". Stored in the FSM (not in
	// gossip) so the state survives the drained node going away — operators
	// drain a node precisely because they want to stop it, and a gossip-only
	// flag would vanish at the same moment it mattered most. Empty map is the
	// no-drains steady state; cleared rows are deleted so the map size tracks
	// active drains, not historical ones.
	drainedNodes map[string]bool

	// subMu guards subscribers. Separate from mu so a slow subscriber accept
	// can't block FSM reads — Apply takes mu briefly to write, releases it,
	// then takes subMu to fan out.
	subMu       sync.Mutex
	subscribers []chan<- struct{}
}

type hostPortClaim struct {
	SandboxID string
	Port      int
}

type pendingReservationClaim struct {
	OwnerNodeID string
	Request     capacity.Request
	ExpiresUnix int64
}

type pendingReservationExpiry struct {
	SandboxID   string
	ExpiresUnix int64
}

type pendingReservationExpiryHeap []pendingReservationExpiry

func (h pendingReservationExpiryHeap) Len() int { return len(h) }
func (h pendingReservationExpiryHeap) Less(i, j int) bool {
	return h[i].ExpiresUnix < h[j].ExpiresUnix
}
func (h pendingReservationExpiryHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *pendingReservationExpiryHeap) Push(x any) {
	*h = append(*h, x.(pendingReservationExpiry))
}

func (h *pendingReservationExpiryHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func newPlacementFSM() *placementFSM {
	return &placementFSM{
		placements:                   make(map[string]Placement),
		nameIndex:                    make(map[string]string),
		shardIndex:                   make(map[int]map[string]struct{}),
		hostPortIndex:                make(map[int]hostPortClaim),
		ownerIndex:                   make(map[string]map[string]struct{}),
		pendingReservationClaims:     make(map[string]pendingReservationClaim),
		pendingReservationCapacity:   make(map[string]capacity.Request),
		pendingReservationIDsByOwner: make(map[string]map[string]struct{}),
		drainedNodes:                 make(map[string]bool),
	}
}

// Apply is invoked by raft for every committed log entry on every node.
func (f *placementFSM) Apply(log *raft.Log) interface{} {
	res := f.apply(log)
	// Notify subscribers AFTER releasing the FSM lock so the ingress
	// reconciler (or any other watcher) can immediately re-read placements
	// without contending with the next Apply. Non-blocking by design — see
	// notifySubscribers.
	f.notifySubscribers()
	return res
}

func (f *placementFSM) apply(log *raft.Log) interface{} {
	cmd, err := decodeCommand(log.Data)
	if err != nil {
		return fmt.Errorf("placementFSM: decode: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	// Use the raft log index as the FSM version. Raft guarantees it is
	// strictly monotonic and globally ordered across the cluster, so it
	// doubles as a durable watch revision — survives snapshots (because the
	// raft log carries it) and matches between leader/follower without any
	// extra bookkeeping. The previous "f.version++" counter was per-process
	// and reset to 0 on every cold restart, which broke watchers that
	// expected a monotonic revision across restores (B9).
	f.version = log.Index
	now := time.Now().Unix()

	switch cmd.Op {
	case opPlace:
		// Idempotency: re-placing the same id with the same owner AND the same
		// spec payload is a no-op when the existing row is already a placement.
		// A reservation-state row with the same owner still needs the State
		// transition + UpdatedUnix bump even when Spec/SealedSecrets are nil
		// (the reservation already holds them) — so we fall through to the
		// write path below in that case.
		existing, exists := f.placements[cmd.SandboxID]
		if exists && existing.OwnerNodeID == cmd.OwnerNodeID && cmd.Spec == nil && cmd.SealedSecrets == nil && !existing.IsReserved() {
			return nil
		}
		if exists && existing.IsOrphaned() {
			return fmt.Errorf("%w: %s is orphaned; use ClaimOrphan", ErrReservationConflict, cmd.SandboxID)
		}
		if exists && !existing.IsReserved() && existing.OwnerNodeID != "" && existing.OwnerNodeID != cmd.OwnerNodeID {
			return fmt.Errorf("%w: %s already placed by %s", ErrReservationConflict, cmd.SandboxID, existing.OwnerNodeID)
		}
		// Cluster-wide name uniqueness. Without this, two concurrent creates
		// with the same Name landing on different owners would both succeed
		// (each owner's local SQLite is a separate name namespace) and any
		// name-based facade lookup (e.g. Daytona) would resolve ambiguously.
		// Done before any state mutation so a conflict leaves the FSM
		// untouched and the leader's apply path returns the sentinel for the
		// API handler to roll back the local create.
		if err := f.validateNameUniqueLocked(cmd.SandboxID, specName(cmd.Spec)); err != nil {
			return err
		}
		created := now
		if exists {
			created = existing.CreatedUnix
		}
		spec := cmd.Spec
		if spec == nil && exists {
			// Preserve the previously-replicated spec — never erase it via a
			// later opPlace that omits the payload.
			spec = existing.Spec
		}
		// Same preservation rule as Spec: a partial replay must not erase the
		// sealed credential bag the original create stored.
		sealed := cmd.SealedSecrets
		if sealed == nil && exists {
			sealed = existing.SealedSecrets
		}
		var ports map[int]string
		var portRoutes map[int]ExposedPortRoute
		if exists {
			// Same preservation rule as Spec: opPlace is the "owner + spec"
			// write and must not erase the port intents accumulated by
			// opAddExposedPort calls between creates.
			ports = existing.ExposedPorts
			portRoutes = existing.ExposedPortRoutes
		}
		dataPlaneHost := cmd.OwnerDataPlaneHost
		if dataPlaneHost == "" && exists {
			dataPlaneHost = existing.OwnerDataPlaneHost
		}
		// Drop the OLD name from the index before writing the new placement —
		// otherwise a re-place with a renamed spec would leave a phantom
		// nameIndex entry pointing at this sandbox under its previous name.
		if exists {
			f.releaseNameLocked(cmd.SandboxID, specName(existing.Spec))
			f.releaseOwnerLocked(cmd.SandboxID, existing)
			if existing.IsReserved() {
				f.releasePendingReservationLocked(cmd.SandboxID)
				f.releasePendingReservationOwnerLocked(cmd.SandboxID, existing.OwnerNodeID)
			}
		}
		f.placements[cmd.SandboxID] = Placement{
			SandboxID:          cmd.SandboxID,
			OwnerNodeID:        cmd.OwnerNodeID,
			OwnerAPIURL:        cmd.OwnerAPIURL,
			OwnerDataPlaneHost: dataPlaneHost,
			Version:            f.version,
			CreatedUnix:        created,
			UpdatedUnix:        now,
			Spec:               spec,
			SealedSecrets:      sealed,
			ExposedPorts:       ports,
			ExposedPortRoutes:  portRoutes,
			// opPlace is the promotion path for reservations: writing the
			// empty State here transitions a Reserved row back to Placed.
			// ExpiresUnix is cleared by the zero-value as well so the GC
			// sweep ignores promoted rows.
			State:       PlacementStatePlaced,
			ExpiresUnix: 0,
		}
		f.claimNameLocked(cmd.SandboxID, specName(spec))
		f.claimShardLocked(cmd.SandboxID)
		if p, ok := f.placements[cmd.SandboxID]; ok {
			f.claimOwnerLocked(cmd.SandboxID, p)
		}
		return nil
	case opReserve:
		// Reservations are the first-half of the two-step create: the router
		// commits intent here, the chosen owner promotes via opPlace once the
		// local create succeeds. The intent carries the redacted spec + sealed
		// secrets so a TTL-expired-then-reclaimed reservation can be promoted
		// by a future re-attempt without re-sealing, and so the FSM-side name
		// uniqueness check has the Name to compare against.
		if cmd.SandboxID == "" || cmd.OwnerNodeID == "" {
			return fmt.Errorf("placementFSM: opReserve requires sandbox_id and owner_node_id")
		}
		existing, exists := f.placements[cmd.SandboxID]
		if exists {
			// Reject when the slot is already materialized — a router racing
			// a completed sandbox should back off and let the caller see 409.
			if !existing.IsReserved() {
				return fmt.Errorf("%w: %s already placed by %s", ErrReservationConflict, cmd.SandboxID, existing.OwnerNodeID)
			}
			// Re-reserve from the same owner before expiry is an idempotent
			// retry — refresh the TTL and treat it as a no-op otherwise.
			if existing.OwnerNodeID == cmd.OwnerNodeID && now <= existing.ExpiresUnix {
				existing.ExpiresUnix = cmd.ExpiresUnix
				existing.Version = f.version
				existing.UpdatedUnix = now
				f.placements[cmd.SandboxID] = existing
				f.refreshPendingReservationExpiryLocked(cmd.SandboxID, cmd.ExpiresUnix)
				return nil
			}
			// Expired reservations are eligible for overwrite by a fresh
			// reservation (the GC sweep racing the new opReserve is harmless
			// because the GC's opCancelReserve only fires for State==Reserved
			// AND a different SandboxID is never reused for the same intent).
			if now > existing.ExpiresUnix {
				f.releasePendingReservationLocked(cmd.SandboxID)
				f.releasePendingReservationOwnerLocked(cmd.SandboxID, existing.OwnerNodeID)
				f.releaseNameLocked(cmd.SandboxID, specName(existing.Spec))
				f.releaseShardLocked(cmd.SandboxID)
			} else {
				// Live reservation held by a different owner — conflict.
				return fmt.Errorf("%w: %s reserved by %s", ErrReservationConflict, cmd.SandboxID, existing.OwnerNodeID)
			}
		}
		if err := f.validateNameUniqueLocked(cmd.SandboxID, specName(cmd.Spec)); err != nil {
			return err
		}
		p := Placement{
			SandboxID:          cmd.SandboxID,
			OwnerNodeID:        cmd.OwnerNodeID,
			OwnerAPIURL:        cmd.OwnerAPIURL,
			OwnerDataPlaneHost: cmd.OwnerDataPlaneHost,
			Version:            f.version,
			CreatedUnix:        now,
			UpdatedUnix:        now,
			Spec:               cmd.Spec,
			SealedSecrets:      cmd.SealedSecrets,
			State:              PlacementStateReserved,
			ExpiresUnix:        cmd.ExpiresUnix,
		}
		f.placements[cmd.SandboxID] = p
		f.claimNameLocked(cmd.SandboxID, specName(cmd.Spec))
		f.claimShardLocked(cmd.SandboxID)
		f.claimPendingReservationLocked(cmd.SandboxID, p)
		return nil
	case opCancelReserve:
		// Only cancel reservations — never delete a placed sandbox, even if a
		// stale rollback attempt arrives after a successful promote. This is
		// the safety property that lets the router fire CancelReservation
		// freely on any failure without worrying about a racing successful
		// promote.
		existing, exists := f.placements[cmd.SandboxID]
		if !exists || !existing.IsReserved() {
			return nil
		}
		f.releaseNameLocked(cmd.SandboxID, specName(existing.Spec))
		f.releaseShardLocked(cmd.SandboxID)
		f.releaseAllHostPortsLocked(cmd.SandboxID, existing)
		f.releasePendingReservationLocked(cmd.SandboxID)
		f.releasePendingReservationOwnerLocked(cmd.SandboxID, existing.OwnerNodeID)
		delete(f.placements, cmd.SandboxID)
		return nil
	case opDelete:
		if existing, ok := f.placements[cmd.SandboxID]; ok {
			f.releaseNameLocked(cmd.SandboxID, specName(existing.Spec))
			f.releaseShardLocked(cmd.SandboxID)
			f.releaseAllHostPortsLocked(cmd.SandboxID, existing)
			f.releaseOwnerLocked(cmd.SandboxID, existing)
			if existing.IsReserved() {
				f.releasePendingReservationLocked(cmd.SandboxID)
				f.releasePendingReservationOwnerLocked(cmd.SandboxID, existing.OwnerNodeID)
			}
		}
		delete(f.placements, cmd.SandboxID)
		return nil
	case opReassign:
		existing, exists := f.placements[cmd.SandboxID]
		if !exists {
			// Reassigning a non-existent placement is a no-op (could happen
			// if a delete and a reassign race; delete wins).
			return nil
		}
		wasReserved := existing.IsReserved()
		if wasReserved {
			f.releasePendingReservationLocked(cmd.SandboxID)
			f.releasePendingReservationOwnerLocked(cmd.SandboxID, existing.OwnerNodeID)
		}
		f.releaseOwnerLocked(cmd.SandboxID, existing)
		previousOwner := existing.OwnerNodeID
		existing.OwnerNodeID = cmd.OwnerNodeID
		existing.OwnerAPIURL = cmd.OwnerAPIURL
		existing.OwnerDataPlaneHost = cmd.OwnerDataPlaneHost
		if cmd.OwnerNodeID == "" {
			existing.OwnerState = PlacementOwnerStateOrphaned
			if existing.OrphanedOwnerNodeID == "" {
				existing.OrphanedOwnerNodeID = previousOwner
			}
			if existing.OrphanedUnix == 0 {
				existing.OrphanedUnix = now
			}
		} else {
			existing.OwnerState = PlacementOwnerStateActive
			existing.OrphanedOwnerNodeID = ""
			existing.OrphanedUnix = 0
		}
		existing.Version = f.version
		existing.UpdatedUnix = now
		f.placements[cmd.SandboxID] = existing
		if wasReserved {
			f.claimPendingReservationLocked(cmd.SandboxID, existing)
		} else {
			f.claimOwnerLocked(cmd.SandboxID, existing)
		}
		return nil
	case opOrphanOwner:
		if cmd.NodeID == "" {
			return fmt.Errorf("placementFSM: opOrphanOwner requires node_id")
		}
		for _, id := range f.ownedPlacementIDsLocked(cmd.NodeID) {
			existing, ok := f.placements[id]
			if !ok || existing.IsReserved() || existing.OwnerNodeID != cmd.NodeID {
				continue
			}
			f.releaseOwnerLocked(id, existing)
			existing.OwnerNodeID = ""
			existing.OwnerAPIURL = ""
			existing.OwnerDataPlaneHost = ""
			existing.OwnerState = PlacementOwnerStateOrphaned
			existing.OrphanedOwnerNodeID = cmd.NodeID
			existing.OrphanedUnix = now
			existing.Version = f.version
			existing.UpdatedUnix = now
			f.placements[id] = existing
		}
		for _, id := range f.pendingReservationIDsLocked(cmd.NodeID) {
			existing, ok := f.placements[id]
			if !ok || !existing.IsReserved() || existing.OwnerNodeID != cmd.NodeID {
				continue
			}
			f.releaseNameLocked(id, specName(existing.Spec))
			f.releaseShardLocked(id)
			f.releasePendingReservationLocked(id)
			f.releasePendingReservationOwnerLocked(id, existing.OwnerNodeID)
			delete(f.placements, id)
		}
		return nil
	case opClaimOrphan:
		if cmd.SandboxID == "" || cmd.OwnerNodeID == "" {
			return fmt.Errorf("placementFSM: opClaimOrphan requires sandbox_id and owner_node_id")
		}
		existing, exists := f.placements[cmd.SandboxID]
		if !exists {
			return ErrUnknownSandbox
		}
		if existing.IsReserved() {
			return fmt.Errorf("%w: %s is a pending reservation", ErrReservationConflict, cmd.SandboxID)
		}
		if !existing.IsOrphaned() {
			if existing.OwnerNodeID == cmd.OwnerNodeID {
				return nil
			}
			return fmt.Errorf("%w: %s already placed by %s", ErrReservationConflict, cmd.SandboxID, existing.OwnerNodeID)
		}
		if existing.OrphanedOwnerNodeID != "" && existing.OrphanedOwnerNodeID != cmd.OwnerNodeID {
			return fmt.Errorf("%w: %s orphaned from %s", ErrOrphanClaimConflict, cmd.SandboxID, existing.OrphanedOwnerNodeID)
		}
		if cmd.Spec != nil {
			oldName := specName(existing.Spec)
			newName := specName(cmd.Spec)
			if newName != oldName {
				if err := f.validateNameUniqueLocked(cmd.SandboxID, newName); err != nil {
					return err
				}
				f.releaseNameLocked(cmd.SandboxID, oldName)
				f.claimNameLocked(cmd.SandboxID, newName)
			}
			existing.Spec = cmd.Spec
		}
		if cmd.SealedSecrets != nil {
			existing.SealedSecrets = cmd.SealedSecrets
		}
		existing.OwnerNodeID = cmd.OwnerNodeID
		existing.OwnerAPIURL = cmd.OwnerAPIURL
		existing.OwnerDataPlaneHost = cmd.OwnerDataPlaneHost
		existing.OwnerState = PlacementOwnerStateActive
		existing.OrphanedOwnerNodeID = ""
		existing.OrphanedUnix = 0
		existing.Version = f.version
		existing.UpdatedUnix = now
		f.placements[cmd.SandboxID] = existing
		f.claimOwnerLocked(cmd.SandboxID, existing)
		return nil
	case opUpsertSpec:
		existing, exists := f.placements[cmd.SandboxID]
		if !exists {
			// No placement to attach the spec to. Treat as no-op: the
			// mutating handler that produced this entry will have already
			// failed locally if the sandbox truly doesn't exist.
			return nil
		}
		if cmd.Spec == nil && cmd.SealedSecrets == nil {
			return nil
		}
		if cmd.Spec != nil {
			oldName := specName(existing.Spec)
			newName := specName(cmd.Spec)
			if newName != oldName {
				if err := f.validateNameUniqueLocked(cmd.SandboxID, newName); err != nil {
					return err
				}
				f.releaseNameLocked(cmd.SandboxID, oldName)
				f.claimNameLocked(cmd.SandboxID, newName)
			}
			existing.Spec = cmd.Spec
		}
		// Replace the sealed bag only when the caller supplied one. Resize /
		// lifecycle write-throughs leave it nil, preserving the original
		// secrets — the only call sites that ship a fresh bag are create
		// (opPlace, not here) and an explicit credential rotation.
		if cmd.SealedSecrets != nil {
			existing.SealedSecrets = cmd.SealedSecrets
		}
		wasReserved := existing.IsReserved()
		if wasReserved {
			f.releasePendingReservationLocked(cmd.SandboxID)
		}
		existing.Version = f.version
		existing.UpdatedUnix = now
		f.placements[cmd.SandboxID] = existing
		if wasReserved {
			f.claimPendingReservationLocked(cmd.SandboxID, existing)
		}
		return nil
	case opAddExposedPort:
		existing, exists := f.placements[cmd.SandboxID]
		if !exists || cmd.Port <= 0 {
			return nil
		}
		route := ExposedPortRoute{
			Protocol:  cmd.Protocol,
			HostPort:  cmd.HostPort,
			PublicURL: cmd.PublicURL,
		}
		if route.Protocol == "" {
			route.Protocol = existing.ExposedPorts[cmd.Port]
		}
		if err := f.validateHostPortAvailableLocked(cmd.SandboxID, cmd.Port, route); err != nil {
			return err
		}
		if existing.ExposedPorts == nil {
			existing.ExposedPorts = make(map[int]string)
		}
		if existing.ExposedPortRoutes == nil {
			existing.ExposedPortRoutes = make(map[int]ExposedPortRoute)
		}
		// Same-route re-add is a no-op; protocol/host-port updates overwrite
		// only after the service layer has accepted the local mutation.
		if existing.ExposedPorts[cmd.Port] == route.Protocol && existing.ExposedPortRoutes[cmd.Port] == route {
			return nil
		}
		f.releaseHostPortLocked(cmd.SandboxID, cmd.Port, existing.ExposedPortRoutes[cmd.Port])
		existing.ExposedPorts[cmd.Port] = route.Protocol
		existing.ExposedPortRoutes[cmd.Port] = route
		f.claimHostPortLocked(cmd.SandboxID, cmd.Port, route)
		existing.Version = f.version
		existing.UpdatedUnix = now
		f.placements[cmd.SandboxID] = existing
		return nil
	case opRemoveExposedPort:
		existing, exists := f.placements[cmd.SandboxID]
		if !exists || cmd.Port <= 0 {
			return nil
		}
		if _, present := existing.ExposedPorts[cmd.Port]; !present {
			return nil
		}
		f.releaseHostPortLocked(cmd.SandboxID, cmd.Port, existing.ExposedPortRoutes[cmd.Port])
		delete(existing.ExposedPorts, cmd.Port)
		if len(existing.ExposedPorts) == 0 {
			existing.ExposedPorts = nil
		}
		delete(existing.ExposedPortRoutes, cmd.Port)
		if len(existing.ExposedPortRoutes) == 0 {
			existing.ExposedPortRoutes = nil
		}
		existing.Version = f.version
		existing.UpdatedUnix = now
		f.placements[cmd.SandboxID] = existing
		return nil
	case opSetNodeDrainState:
		// Drain marks live in the FSM so an operator-issued drain persists past
		// the drained node going down — the very next moment after a drain the
		// operator typically stops the process. Idempotent on both edges: a
		// drain of an already-drained node is a no-op, and uncordon of a node
		// that isn't drained drops nothing.
		if cmd.NodeID == "" {
			return fmt.Errorf("placementFSM: opSetNodeDrainState requires node_id")
		}
		if cmd.Drained {
			if f.drainedNodes == nil {
				f.drainedNodes = make(map[string]bool)
			}
			f.drainedNodes[cmd.NodeID] = true
		} else {
			delete(f.drainedNodes, cmd.NodeID)
		}
		return nil
	default:
		return fmt.Errorf("placementFSM: unknown op %d", cmd.Op)
	}
}

// specName returns the trimmed Name field, or "" if spec is nil. Centralized
// so the conflict-check, claim, and release paths all derive the index key
// the same way — a mismatch would silently leak nameIndex entries.
func specName(spec *models.CreateSandboxRequest) string {
	if spec == nil {
		return ""
	}
	return strings.TrimSpace(spec.Name)
}

// validateNameUniqueLocked checks that no other placement currently claims
// name. Empty name is always allowed (anonymous sandboxes don't conflict);
// matches the local SQLite partial-unique-index behavior.
func (f *placementFSM) validateNameUniqueLocked(sandboxID, name string) error {
	if name == "" {
		return nil
	}
	if owner, ok := f.nameIndex[name]; ok && owner != sandboxID {
		return fmt.Errorf("%w: %q is held by %s", ErrNameConflict, name, owner)
	}
	return nil
}

// claimNameLocked records sandboxID as the owner of name. Empty name is a
// no-op — anonymous sandboxes don't enter the index.
func (f *placementFSM) claimNameLocked(sandboxID, name string) {
	if name == "" {
		return
	}
	if f.nameIndex == nil {
		f.nameIndex = make(map[string]string)
	}
	f.nameIndex[name] = sandboxID
}

// releaseNameLocked drops name from the index when sandboxID is the recorded
// owner. The owner-check guards against a delete-then-place race in raft log
// order: if the rename's claim already wrote the new owner, a stale release
// for the old name could otherwise unmap the new placement.
func (f *placementFSM) releaseNameLocked(sandboxID, name string) {
	if name == "" {
		return
	}
	if owner, ok := f.nameIndex[name]; ok && owner == sandboxID {
		delete(f.nameIndex, name)
	}
}

func (f *placementFSM) claimOwnerLocked(sandboxID string, p Placement) {
	if sandboxID == "" || p.IsReserved() || p.IsOrphaned() || p.OwnerNodeID == "" {
		return
	}
	if f.ownerIndex == nil {
		f.ownerIndex = make(map[string]map[string]struct{})
	}
	ids := f.ownerIndex[p.OwnerNodeID]
	if ids == nil {
		ids = make(map[string]struct{})
		f.ownerIndex[p.OwnerNodeID] = ids
	}
	ids[sandboxID] = struct{}{}
}

func (f *placementFSM) releaseOwnerLocked(sandboxID string, p Placement) {
	if sandboxID == "" || p.OwnerNodeID == "" || f.ownerIndex == nil {
		return
	}
	ids := f.ownerIndex[p.OwnerNodeID]
	if ids == nil {
		return
	}
	delete(ids, sandboxID)
	if len(ids) == 0 {
		delete(f.ownerIndex, p.OwnerNodeID)
	}
}

func (f *placementFSM) ownedPlacementIDsLocked(nodeID string) []string {
	if nodeID == "" {
		return nil
	}
	ids := f.ownerIndex[nodeID]
	if ids == nil {
		return nil
	}
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (f *placementFSM) claimShardLocked(sandboxID string) {
	if sandboxID == "" {
		return
	}
	if f.shardIndex == nil {
		f.shardIndex = make(map[int]map[string]struct{})
	}
	shard := PlacementShardForSandbox(sandboxID, DefaultPlacementShardCount)
	ids := f.shardIndex[shard]
	if ids == nil {
		ids = make(map[string]struct{})
		f.shardIndex[shard] = ids
	}
	ids[sandboxID] = struct{}{}
}

func (f *placementFSM) releaseShardLocked(sandboxID string) {
	if sandboxID == "" || f.shardIndex == nil {
		return
	}
	shard := PlacementShardForSandbox(sandboxID, DefaultPlacementShardCount)
	ids := f.shardIndex[shard]
	if ids == nil {
		return
	}
	delete(ids, sandboxID)
	if len(ids) == 0 {
		delete(f.shardIndex, shard)
	}
}

func (f *placementFSM) claimHostPortLocked(sandboxID string, port int, route ExposedPortRoute) {
	if route.Protocol != models.ExposedPortProtocolTCP || route.HostPort <= 0 {
		return
	}
	if f.hostPortIndex == nil {
		f.hostPortIndex = make(map[int]hostPortClaim)
	}
	f.hostPortIndex[route.HostPort] = hostPortClaim{SandboxID: sandboxID, Port: port}
}

func (f *placementFSM) releaseHostPortLocked(sandboxID string, port int, route ExposedPortRoute) {
	if route.Protocol != models.ExposedPortProtocolTCP || route.HostPort <= 0 || f.hostPortIndex == nil {
		return
	}
	claim, ok := f.hostPortIndex[route.HostPort]
	if ok && claim.SandboxID == sandboxID && claim.Port == port {
		delete(f.hostPortIndex, route.HostPort)
	}
}

func (f *placementFSM) releaseAllHostPortsLocked(sandboxID string, p Placement) {
	for port, route := range exposedPortRoutesForPlacement(p) {
		f.releaseHostPortLocked(sandboxID, port, route)
	}
}

func (f *placementFSM) validateHostPortAvailableLocked(sandboxID string, port int, route ExposedPortRoute) error {
	if route.Protocol != models.ExposedPortProtocolTCP || route.HostPort <= 0 {
		return nil
	}
	if f.hostPortIndex == nil {
		f.hostPortIndex = make(map[int]hostPortClaim)
		for id, placement := range f.placements {
			for placementPort, placementRoute := range exposedPortRoutesForPlacement(placement) {
				if placementRoute.Protocol == models.ExposedPortProtocolTCP && placementRoute.HostPort > 0 {
					f.hostPortIndex[placementRoute.HostPort] = hostPortClaim{SandboxID: id, Port: placementPort}
				}
			}
		}
	}
	if claim, ok := f.hostPortIndex[route.HostPort]; ok && (claim.SandboxID != sandboxID || claim.Port != port) {
		return fmt.Errorf("%w: %d reserved by %s:%d", ErrHostPortReserved, route.HostPort, claim.SandboxID, claim.Port)
	}
	return nil
}

func (f *placementFSM) claimPendingReservationLocked(sandboxID string, p Placement) {
	if sandboxID == "" || !p.IsReserved() {
		return
	}
	if f.pendingReservationClaims == nil {
		f.pendingReservationClaims = make(map[string]pendingReservationClaim)
	}
	if f.pendingReservationCapacity == nil {
		f.pendingReservationCapacity = make(map[string]capacity.Request)
	}
	if f.pendingReservationIDsByOwner == nil {
		f.pendingReservationIDsByOwner = make(map[string]map[string]struct{})
	}
	if old, ok := f.pendingReservationClaims[sandboxID]; ok {
		f.subtractPendingCapacityLocked(old.OwnerNodeID, old.Request)
		if old.OwnerNodeID != p.OwnerNodeID {
			f.releasePendingReservationOwnerLocked(sandboxID, old.OwnerNodeID)
		}
	}
	req := capacityRequestFromSpec(p.Spec)
	claim := pendingReservationClaim{
		OwnerNodeID: p.OwnerNodeID,
		Request:     req,
		ExpiresUnix: p.ExpiresUnix,
	}
	f.pendingReservationClaims[sandboxID] = claim
	f.addPendingCapacityLocked(claim.OwnerNodeID, claim.Request)
	f.claimPendingReservationOwnerLocked(sandboxID, claim.OwnerNodeID)
	if claim.ExpiresUnix > 0 {
		heap.Push(&f.pendingReservationExpiries, pendingReservationExpiry{SandboxID: sandboxID, ExpiresUnix: claim.ExpiresUnix})
	}
}

func (f *placementFSM) releasePendingReservationLocked(sandboxID string) {
	if f.pendingReservationClaims == nil {
		return
	}
	claim, ok := f.pendingReservationClaims[sandboxID]
	if !ok {
		return
	}
	f.subtractPendingCapacityLocked(claim.OwnerNodeID, claim.Request)
	delete(f.pendingReservationClaims, sandboxID)
}

func (f *placementFSM) claimPendingReservationOwnerLocked(sandboxID, owner string) {
	if sandboxID == "" || owner == "" {
		return
	}
	if f.pendingReservationIDsByOwner == nil {
		f.pendingReservationIDsByOwner = make(map[string]map[string]struct{})
	}
	ids := f.pendingReservationIDsByOwner[owner]
	if ids == nil {
		ids = make(map[string]struct{})
		f.pendingReservationIDsByOwner[owner] = ids
	}
	ids[sandboxID] = struct{}{}
}

func (f *placementFSM) releasePendingReservationOwnerLocked(sandboxID, owner string) {
	if sandboxID == "" || owner == "" || f.pendingReservationIDsByOwner == nil {
		return
	}
	ids := f.pendingReservationIDsByOwner[owner]
	if ids == nil {
		return
	}
	delete(ids, sandboxID)
	if len(ids) == 0 {
		delete(f.pendingReservationIDsByOwner, owner)
	}
}

func (f *placementFSM) pendingReservationIDsLocked(owner string) []string {
	if owner == "" || f.pendingReservationIDsByOwner == nil {
		return nil
	}
	ids := f.pendingReservationIDsByOwner[owner]
	if ids == nil {
		return nil
	}
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (f *placementFSM) refreshPendingReservationExpiryLocked(sandboxID string, expiresUnix int64) {
	if f.pendingReservationClaims == nil {
		return
	}
	claim, ok := f.pendingReservationClaims[sandboxID]
	if !ok {
		return
	}
	claim.ExpiresUnix = expiresUnix
	f.pendingReservationClaims[sandboxID] = claim
	if expiresUnix > 0 {
		heap.Push(&f.pendingReservationExpiries, pendingReservationExpiry{SandboxID: sandboxID, ExpiresUnix: expiresUnix})
	}
}

func (f *placementFSM) pruneExpiredPendingReservationsLocked(now int64) {
	if now <= 0 {
		return
	}
	for len(f.pendingReservationExpiries) > 0 {
		next := f.pendingReservationExpiries[0]
		if next.ExpiresUnix <= 0 || now <= next.ExpiresUnix {
			return
		}
		heap.Pop(&f.pendingReservationExpiries)
		claim, ok := f.pendingReservationClaims[next.SandboxID]
		if !ok || claim.ExpiresUnix != next.ExpiresUnix {
			continue
		}
		f.releasePendingReservationLocked(next.SandboxID)
	}
}

func (f *placementFSM) addPendingCapacityLocked(owner string, req capacity.Request) {
	if owner == "" {
		return
	}
	cur := f.pendingReservationCapacity[owner]
	cur.CPU += req.CPU
	cur.MemoryMB += req.MemoryMB
	cur.DiskGB += req.DiskGB
	cur.GPUs += req.GPUs
	f.pendingReservationCapacity[owner] = cur
}

func (f *placementFSM) subtractPendingCapacityLocked(owner string, req capacity.Request) {
	if owner == "" || f.pendingReservationCapacity == nil {
		return
	}
	cur := f.pendingReservationCapacity[owner]
	cur.CPU -= req.CPU
	cur.MemoryMB -= req.MemoryMB
	cur.DiskGB -= req.DiskGB
	cur.GPUs -= req.GPUs
	if cur.CPU == 0 && cur.MemoryMB == 0 && cur.DiskGB == 0 && cur.GPUs == 0 {
		delete(f.pendingReservationCapacity, owner)
		return
	}
	f.pendingReservationCapacity[owner] = cur
}

// get returns the placement for id, or zero-value + false if absent.
func (f *placementFSM) get(id string) (Placement, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	p, ok := f.placements[id]
	if !ok {
		return Placement{}, false
	}
	return clonePlacement(p), true
}

// sandboxIDByName returns the sandbox ID currently claiming name in the
// replicated name index.
func (f *placementFSM) sandboxIDByName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	id, ok := f.nameIndex[name]
	return id, ok
}

// idsOwnedBy returns the sandbox IDs whose current owner is nodeID. Used by
// the dead-owner reconciler to enumerate orphan candidates.
func (f *placementFSM) idsOwnedBy(nodeID string) []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.ownedPlacementIDsLocked(nodeID)
}

// currentVersion returns the FSM's monotonic apply counter. The cluster
// ingress reconciler reads it from a fast-poll loop to detect placement
// changes within a fraction of the slow reconcile interval — without this,
// the worst-case wait between an FSM apply and an ingress route update is
// the full reconcile period.
func (f *placementFSM) currentVersion() uint64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.version
}

// pendingReservationsByNode returns the indexed capacity demand of every live
// (not yet expired) reservation, keyed by the owner node ID. SelectPlacement
// uses this to subtract still-in-flight reservations from a peer's gossiped
// headroom so two creates routed to the same node back-to-back can't both pass
// scoring before the first reservation reaches the gossip ledger.
//
// The FSM is the source of truth here: it serializes every opReserve through
// raft, so two routers racing the same target see the second reservation land
// strictly after the first in the log — and the second create's
// SelectPlacement will read the updated aggregate. Expired claims are pruned
// lazily from the expiry heap, so this path does not scan the full placement
// table at 100k-sandbox scale.
func (f *placementFSM) pendingReservationsByNode(now int64) map[string]capacity.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruneExpiredPendingReservationsLocked(now)
	out := make(map[string]capacity.Request, len(f.pendingReservationCapacity))
	for owner, req := range f.pendingReservationCapacity {
		out[owner] = req
	}
	return out
}

// snapshot copies the placement map for use by Snapshot().
func (f *placementFSM) snapshot() map[string]Placement {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[string]Placement, len(f.placements))
	for k, v := range f.placements {
		out[k] = clonePlacement(v)
	}
	return out
}

func (f *placementFSM) placementsForShards(filter PlacementShardFilter) []Placement {
	filter = filter.Normalize()
	if filter.allShards() {
		snap := f.snapshot()
		out := make([]Placement, 0, len(snap))
		for _, p := range snap {
			out = append(out, p)
		}
		return out
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	// The in-memory shard index is built for the default shard space. If an
	// operator ever asks for a different count, fall back to a scan rather
	// than returning a subtly wrong slice.
	if filter.ShardCount != DefaultPlacementShardCount {
		want := make(map[int]struct{}, len(filter.Shards))
		for _, shard := range filter.Shards {
			want[shard] = struct{}{}
		}
		out := make([]Placement, 0)
		for id, p := range f.placements {
			if _, ok := want[PlacementShardForSandbox(id, filter.ShardCount)]; ok {
				out = append(out, clonePlacement(p))
			}
		}
		return out
	}

	out := make([]Placement, 0)
	for _, shard := range filter.Shards {
		for id := range f.shardIndex[shard] {
			if p, ok := f.placements[id]; ok {
				out = append(out, clonePlacement(p))
			}
		}
	}
	return out
}

func (f *placementFSM) placementPage(req PlacementPageRequest) PlacementPageResponse {
	req = req.Normalize()
	shardFilter := req.ShardFilter.Normalize()
	allShards := shardFilter.allShards()
	wantShards := make(map[int]struct{}, len(shardFilter.Shards))
	for _, shard := range shardFilter.Shards {
		wantShards[shard] = struct{}{}
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	ids := make([]string, 0, len(f.placements))
	for id := range f.placements {
		if req.PageToken != "" && id <= req.PageToken {
			continue
		}
		if !allShards {
			shardCount := shardFilter.ShardCount
			if shardCount <= 0 {
				shardCount = DefaultPlacementShardCount
			}
			if _, ok := wantShards[PlacementShardForSandbox(id, shardCount)]; !ok {
				continue
			}
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > req.Limit {
		ids = ids[:req.Limit]
	}
	out := make([]Placement, 0, len(ids))
	for _, id := range ids {
		out = append(out, clonePlacement(f.placements[id]))
	}
	next := ""
	if len(ids) == req.Limit {
		next = ids[len(ids)-1]
	}
	return PlacementPageResponse{Placements: out, NextPageToken: next}
}

// isNodeDrained reports whether nodeID has been marked drained via
// opSetNodeDrainState. SelectPlacement reads this to filter the candidate set;
// callers outside placement scoring can use it for observability (e.g. the
// members endpoint surfacing drain status).
func (f *placementFSM) isNodeDrained(nodeID string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.drainedNodes[nodeID]
}

// drainedNodesSnapshot returns a copy of the drained node set. SelectPlacement
// uses this once per call instead of N isNodeDrained reads to avoid taking the
// FSM lock for every candidate.
func (f *placementFSM) drainedNodesSnapshot() map[string]bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.drainedNodes) == 0 {
		return nil
	}
	out := make(map[string]bool, len(f.drainedNodes))
	for k, v := range f.drainedNodes {
		out[k] = v
	}
	return out
}

// fsmSnapshotPayload is the on-disk envelope for an FSM snapshot. Wrapping
// the map in a struct lets the snapshot carry the FSM version alongside the
// placement state — without this, version reset to 0 on every cold restart
// (B9). Legacy snapshots (pre-envelope) decoded as a bare map[string]Placement;
// Restore detects that shape and reconstructs the version from the highest
// Placement.Version it sees. DrainedNodes is an optional addition — older
// snapshots that pre-date the field decode it as nil and the FSM treats that
// as "no drains," matching the empty-map steady state.
type fsmSnapshotPayload struct {
	Version      uint64
	Placements   map[string]Placement
	DrainedNodes map[string]bool
}

// Snapshot returns a raft.FSMSnapshot capturing current placement state.
func (f *placementFSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	version := f.version
	drained := make(map[string]bool, len(f.drainedNodes))
	for k, v := range f.drainedNodes {
		drained[k] = v
	}
	f.mu.RUnlock()
	return &fsmSnapshot{version: version, placements: f.snapshot(), drainedNodes: drained}, nil
}

// Restore loads state from a previously written snapshot. Replaces in-memory
// placements wholesale — raft only calls Restore on a cold start or follower
// resync.
func (f *placementFSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Errorf("placementFSM: restore read: %w", err)
	}
	var payload fsmSnapshotPayload
	if decErr := gob.NewDecoder(bytes.NewReader(raw)).Decode(&payload); decErr != nil {
		// Legacy on-disk format is the bare map. Fall back so a snapshot
		// taken before the version envelope was added still loads.
		var legacy map[string]Placement
		if legacyErr := gob.NewDecoder(bytes.NewReader(raw)).Decode(&legacy); legacyErr != nil {
			return fmt.Errorf("placementFSM: restore: %w", decErr)
		}
		payload.Placements = legacy
		// No envelope version in the legacy snapshot — derive a non-zero
		// lower bound from existing Placement.Version values so watchers
		// don't see the revision regress. Raft will Apply any post-snapshot
		// log entries next, which will overwrite f.version with log.Index
		// (guaranteed strictly greater than the snapshot's index).
		for _, p := range legacy {
			if p.Version > payload.Version {
				payload.Version = p.Version
			}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if payload.Placements == nil {
		payload.Placements = make(map[string]Placement)
	}
	f.placements = payload.Placements
	f.version = payload.Version
	// Rebuild nameIndex from placements. Snapshots don't carry the index
	// (older snapshots predate it), and rebuilding keeps the FSM the single
	// source of truth even after a cold restart.
	f.nameIndex = make(map[string]string, len(payload.Placements))
	f.shardIndex = make(map[int]map[string]struct{})
	f.hostPortIndex = make(map[int]hostPortClaim)
	f.ownerIndex = make(map[string]map[string]struct{})
	f.pendingReservationClaims = make(map[string]pendingReservationClaim)
	f.pendingReservationCapacity = make(map[string]capacity.Request)
	f.pendingReservationIDsByOwner = make(map[string]map[string]struct{})
	f.pendingReservationExpiries = nil
	for id, p := range payload.Placements {
		if name := specName(p.Spec); name != "" {
			f.nameIndex[name] = id
		}
		f.claimShardLocked(id)
		for port, route := range exposedPortRoutesForPlacement(p) {
			f.claimHostPortLocked(id, port, route)
		}
		if p.IsReserved() {
			f.claimPendingReservationLocked(id, p)
		} else {
			f.claimOwnerLocked(id, p)
		}
	}
	// Pre-drain snapshots have a nil DrainedNodes — initialize empty so the
	// add path can write without a nil-map panic. Active drains carried in
	// the envelope are copied across verbatim; raft will apply any
	// post-snapshot opSetNodeDrainState entries next to bring us current.
	if payload.DrainedNodes == nil {
		f.drainedNodes = make(map[string]bool)
	} else {
		f.drainedNodes = payload.DrainedNodes
	}
	return nil
}

type fsmSnapshot struct {
	version      uint64
	placements   map[string]Placement
	drainedNodes map[string]bool
}

func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	enc := gob.NewEncoder(sink)
	if err := enc.Encode(fsmSnapshotPayload{Version: s.version, Placements: s.placements, DrainedNodes: s.drainedNodes}); err != nil {
		_ = sink.Cancel()
		return fmt.Errorf("fsmSnapshot: encode: %w", err)
	}
	return sink.Close()
}

func (s *fsmSnapshot) Release() {}

func clonePlacement(p Placement) Placement {
	p.Spec = cloneCreateSandboxRequest(p.Spec)
	if len(p.SealedSecrets) > 0 {
		p.SealedSecrets = append([]byte(nil), p.SealedSecrets...)
	}
	if len(p.ExposedPorts) > 0 {
		ports := make(map[int]string, len(p.ExposedPorts))
		for k, v := range p.ExposedPorts {
			ports[k] = v
		}
		p.ExposedPorts = ports
	}
	if len(p.ExposedPortRoutes) > 0 {
		routes := make(map[int]ExposedPortRoute, len(p.ExposedPortRoutes))
		for k, v := range p.ExposedPortRoutes {
			routes[k] = v
		}
		p.ExposedPortRoutes = routes
	}
	return p
}

func cloneCreateSandboxRequest(in *models.CreateSandboxRequest) *models.CreateSandboxRequest {
	if in == nil {
		return nil
	}
	out := *in
	out.Env = cloneStringMap(in.Env)
	out.Tags = cloneStringMap(in.Tags)
	if len(in.ContainerCommand) > 0 {
		out.ContainerCommand = append([]string(nil), in.ContainerCommand...)
	}
	if len(in.Mounts) > 0 {
		out.Mounts = make([]models.MountSpec, len(in.Mounts))
		for i := range in.Mounts {
			out.Mounts[i] = in.Mounts[i]
			out.Mounts[i].Options = cloneStringMap(in.Mounts[i].Options)
			out.Mounts[i].Credentials = cloneStringMap(in.Mounts[i].Credentials)
		}
	}
	if in.Registry != nil {
		registry := *in.Registry
		out.Registry = &registry
	}
	if in.Lifecycle != nil {
		lifecycle := *in.Lifecycle
		out.Lifecycle = &lifecycle
	}
	if in.GPUs != nil {
		gpus := *in.GPUs
		if len(in.GPUs.DeviceIDs) > 0 {
			gpus.DeviceIDs = append([]string(nil), in.GPUs.DeviceIDs...)
		}
		out.GPUs = &gpus
	}
	return &out
}

// subscribe registers ch to receive a non-blocking signal after every Apply.
// The caller is expected to use a buffered channel of capacity 1 so a missed
// signal collapses into the next one (the watcher only needs "something
// changed", not the count of changes). Returns a cancel func that removes the
// subscriber and is safe to call multiple times.
func (f *placementFSM) subscribe(ch chan<- struct{}) (cancel func()) {
	f.subMu.Lock()
	f.subscribers = append(f.subscribers, ch)
	f.subMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			f.subMu.Lock()
			defer f.subMu.Unlock()
			for i, c := range f.subscribers {
				if c == ch {
					f.subscribers = append(f.subscribers[:i], f.subscribers[i+1:]...)
					return
				}
			}
		})
	}
}

// notifySubscribers fires every registered channel non-blocking. A subscriber
// that's already armed (buffered slot full) drops the signal — exactly the
// behaviour we want, because "more than one apply since last wake" is still
// just "wake up and reconcile."
func (f *placementFSM) notifySubscribers() {
	f.subMu.Lock()
	subs := f.subscribers
	f.subMu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

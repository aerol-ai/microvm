package cluster

import (
	"bytes"
	"container/heap"
	"context"
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
	"github.com/google/btree"
	"github.com/hashicorp/raft"
)

// Operation codes for raft log entries.
type opCode uint8

const (
	maxPlacementAuditNodes = 64

	opPlace                  opCode = 1
	opDelete                 opCode = 2
	opReassign               opCode = 3
	opUpsertSpec             opCode = 4  // overwrite Placement.Spec without touching ownership
	opAddExposedPort         opCode = 5  // record one (port, protocol) intent
	opRemoveExposedPort      opCode = 6  // drop one port intent
	opReserve                opCode = 7  // hold capacity + name for a chosen owner before docker
	opCancelReserve          opCode = 8  // release a pending reservation (rollback or TTL GC)
	opSetNodeDrainState      opCode = 9  // operator-set "exclude from placement" mark for a node
	opOrphanOwner            opCode = 10 // atomically orphan all placements owned by a dead node
	opClaimOrphan            opCode = 11 // reclaim an orphaned placement back to its previous owner
	opReserveBatch           opCode = 12 // hold capacity + names for a create burst in one raft entry
	opAddCustomDomain        opCode = 13 // bind one user hostname to a placement (cluster-wide unique)
	opRemoveCustomDomain     opCode = 14 // release one previously-bound hostname
	opUpsertVolume           opCode = 15 // get-or-create a platform-volume metadata row (cluster-wide)
	opDeleteVolume           opCode = 16 // remove a platform-volume metadata row
	opPutVolumeAttach        opCode = 17 // upsert platform-volume attachment rows (cluster-wide)
	opDeleteVolumeAttach     opCode = 18 // drop all platform-volume attachments for one sandbox
	opPruneAuditACL          opCode = 19 // bounded-retention cleanup for post-delete owner ACLs
	opUpdateSecretRecipients opCode = 20 // replace Placement.SecretRecipients (+ optional secret handle) without touching ownership/incarnation
)

// command is the wire format for one raft log entry. Recovery payloads ride
// inline: Spec plus the SecretRef/SecretVersion provider handle travel in the
// entry itself, quorum-committed with the placement they describe (see
// recovery_replication.go for the size cap). Any Spec MUST be redacted of
// plaintext credentials before encoding — there is deliberately no field for
// raw sealed bytes, because log entries and FSM snapshots are not erasable
// per-sandbox.
// Port/Protocol carry one (port, protocol) tuple for opAddExposedPort and
// opRemoveExposedPort — replicated as intent-only so the new owner picks a
// fresh host port from its own pool.
//
// Secrets follow the same preserve-on-empty rule as Spec at the FSM level: an
// opPlace or opUpsertSpec that omits SecretRef/SecretVersion does NOT erase a
// previously-replicated handle. That lets resize/lifecycle write-throughs
// (which never touch credentials) leave the secret ref alone, and lets
// boot-time replays that have the spec but not the secret provider handle
// avoid clobbering the original.
type command struct {
	Op                 opCode                       `json:"op"`
	SandboxID          string                       `json:"sandbox_id"`
	OwnerNodeID        string                       `json:"owner_node_id,omitempty"`
	OwnerAPIURL        string                       `json:"owner_api_url,omitempty"`
	OwnerDataPlaneHost string                       `json:"owner_data_plane_host,omitempty"`
	Spec               *models.CreateSandboxRequest `json:"spec,omitempty"`
	SecretRef          string                       `json:"secret_ref,omitempty"`
	SecretVersion      int                          `json:"secret_version,omitempty"`
	// SecretRecipients rides opReserve (and is preserved by opPlace). Additive
	// omitempty — mixed-version clusters decode missing field as nil.
	SecretRecipients []string `json:"secret_recipients,omitempty"`
	// IncarnationID rides opReserve and is preserved by opPlace/opReassign.
	IncarnationID string `json:"incarnation_id,omitempty"`
	// SecretSealGeneration is set by opUpdateSecretRecipients when coordinating
	// a reseal. Additive omitempty.
	SecretSealGeneration int64 `json:"secret_seal_generation,omitempty"`
	// ExpectedIncarnationID fences opPlace and opUpdateSecretRecipients from
	// applying secret state to another sandbox lifetime. Empty skips it.
	// ExpectedSealGeneration is the opUpdateSecretRecipients generation CAS.
	ExpectedIncarnationID  string `json:"expected_incarnation_id,omitempty"`
	ExpectedSealGeneration int64  `json:"expected_seal_generation,omitempty"`
	// OwnerRef is the control-plane tenant account. Additive omitempty.
	OwnerRef  string `json:"owner_ref,omitempty"`
	Port      int    `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	HostPort  int    `json:"host_port,omitempty"`
	PublicURL string `json:"public_url,omitempty"`
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
	// Hostname carries the single custom-domain hostname for
	// opAddCustomDomain/opRemoveCustomDomain. Callers MUST canonicalize
	// (trim + lower-case) before encoding so the replicated index uses
	// identical keys cluster-wide.
	Hostname string `json:"hostname,omitempty"`

	// ReassignCause tags WHY an opReassign was issued. Observability only —
	// the FSM's state transition is identical regardless of cause, so an
	// entry replayed from an older node (which never set the field) applies
	// exactly the same placement change. Additive + omitempty, so mixed-
	// version clusters and pre-upgrade log entries decode cleanly to "".
	//
	// It exists because opReassign has four producers: two failover paths and
	// two operator/live-migration paths (Cluster.ReassignPlacement,
	// Agent.ReassignPlacement). The failover counter must not silently absorb
	// a WASM live migration, so the cause has to ride with the command rather
	// than be inferred at apply time.
	ReassignCause string `json:"reassign_cause,omitempty"`

	// Reservations is populated by opReserveBatch. The single opReserve fields
	// above are retained for wire compatibility and the normal one-create path.
	Reservations []reservationCommand `json:"reservations,omitempty"`

	// Volume / VolumeTenant / VolumeID / MaxPerTenant carry platform-volume
	// metadata for opUpsertVolume / opDeleteVolume. The volume row is replicated
	// so any node answers Daytona get/list/delete-by-id after tenant ownership
	// moves; the data itself is deterministic in S3/NFS and never in raft.
	Volume            *models.Volume            `json:"volume,omitempty"`
	VolumeTenant      string                    `json:"volume_tenant,omitempty"`
	VolumeID          string                    `json:"volume_id,omitempty"`
	MaxPerTenant      int                       `json:"max_per_tenant,omitempty"`
	VolumeAttachments []models.VolumeAttachment `json:"volume_attachments,omitempty"`
	VolumeSandboxID   string                    `json:"volume_sandbox_id,omitempty"`
}

type reservationCommand struct {
	SandboxID          string                       `json:"sandbox_id"`
	OwnerNodeID        string                       `json:"owner_node_id,omitempty"`
	OwnerAPIURL        string                       `json:"owner_api_url,omitempty"`
	OwnerDataPlaneHost string                       `json:"owner_data_plane_host,omitempty"`
	Spec               *models.CreateSandboxRequest `json:"spec,omitempty"`
	SecretRef          string                       `json:"secret_ref,omitempty"`
	SecretVersion      int                          `json:"secret_version,omitempty"`
	SecretRecipients   []string                     `json:"secret_recipients,omitempty"`
	IncarnationID      string                       `json:"incarnation_id,omitempty"`
	OwnerRef           string                       `json:"owner_ref,omitempty"`
	ExpiresUnix        int64                        `json:"expires_unix,omitempty"`
}

// reassignApplyResult is returned only for failover-tagged opReassign entries.
// Raft exposes the leader FSM's response to applyEncodedLocal, allowing that
// single authoritative apply path to count a real transition without counting
// the same replicated log entry again on every follower.
type reassignApplyResult struct {
	Changed bool
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

func (c command) placementSecrets() PlacementSecrets {
	return PlacementSecrets{
		Ref:     c.SecretRef,
		Version: c.SecretVersion,
	}
}

func reservationFromCommand(c command) reservationCommand {
	return reservationCommand{
		SandboxID:          c.SandboxID,
		OwnerNodeID:        c.OwnerNodeID,
		OwnerAPIURL:        c.OwnerAPIURL,
		OwnerDataPlaneHost: c.OwnerDataPlaneHost,
		Spec:               c.Spec,
		SecretRef:          c.SecretRef,
		SecretVersion:      c.SecretVersion,
		SecretRecipients:   append([]string(nil), c.SecretRecipients...),
		IncarnationID:      c.IncarnationID,
		OwnerRef:           c.OwnerRef,
		ExpiresUnix:        c.ExpiresUnix,
	}
}

func commandFromReservation(r reservationCommand) command {
	return command{
		Op:                 opReserve,
		SandboxID:          r.SandboxID,
		OwnerNodeID:        r.OwnerNodeID,
		OwnerAPIURL:        r.OwnerAPIURL,
		OwnerDataPlaneHost: r.OwnerDataPlaneHost,
		Spec:               r.Spec,
		SecretRef:          r.SecretRef,
		SecretVersion:      r.SecretVersion,
		SecretRecipients:   append([]string(nil), r.SecretRecipients...),
		IncarnationID:      r.IncarnationID,
		OwnerRef:           r.OwnerRef,
		ExpiresUnix:        r.ExpiresUnix,
	}
}

func reservationCommands(c command) []reservationCommand {
	if c.Op == opReserveBatch {
		return c.Reservations
	}
	return []reservationCommand{reservationFromCommand(c)}
}

func (c command) hasSecretUpdate() bool {
	return c.placementSecrets().hasUpdate()
}

func applyCommandSecretUpdate(existing Placement, exists bool, cmd command) PlacementSecrets {
	if !cmd.hasSecretUpdate() && exists {
		return secretsFromPlacement(existing)
	}
	return PlacementSecrets{Ref: cmd.SecretRef, Version: cmd.SecretVersion}
}

// placementFSM is the raft.FSM implementation. It keeps hot routing/admission
// fields separate from larger recovery payloads so ingress/page reads do not
// clone specs or secret handles for every sandbox.
type placementFSM struct {
	mu sync.RWMutex
	// placements is the hot row map. Values deliberately keep Placement.Spec,
	// SecretRef, SecretVersion, and SealedSecrets empty; those larger recovery
	// fields live behind Placement.RecoveryRef and are attached only for point
	// lookups and failover/recreate flows.
	placements map[string]Placement
	// recovery is a legacy/in-memory fallback for tests and old snapshots that
	// contained inline recovery payloads. New snapshots do not persist it.
	recovery      map[string]placementRecovery
	recoveryStore placementRecoveryStore
	// recoveryResolver fetches missing content-addressed recovery blobs from
	// peer servers during log replay or point lookup. It is optional so unit
	// tests and single-process FSM use can stay local-only.
	recoveryResolver func(context.Context, string) (RecoveryBlob, bool, error)
	version          uint64
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
	// placementIDs is a sorted sandbox ID index used by PlacementPage so a
	// bounded page does not allocate/sort the full placement map.
	placementIDs *btree.BTreeG[string]
	// ownerRefIndex maps tenant OwnerRef -> sorted sandbox IDs. PlacementPage
	// with OwnerRef uses this instead of scanning/sorting the full map under
	// the FSM lock (enterprise multi-tenant list fan-out).
	ownerRefIndex map[string]*btree.BTreeG[string]
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
	// reservedIndex tracks rows that are still State=Reserved even after their
	// capacity claim has been pruned as expired. The leader GC uses it to find
	// expired reservation rows without scanning every placed sandbox.
	reservedIndex map[string]struct{}
	// drainedNodes holds the set of nodeIDs an operator has marked as
	// "exclude from SelectPlacement candidate set". Stored in the FSM (not in
	// gossip) so the state survives the drained node going away — operators
	// drain a node precisely because they want to stop it, and a gossip-only
	// flag would vanish at the same moment it mattered most. Empty map is the
	// no-drains steady state; cleared rows are deleted so the map size tracks
	// active drains, not historical ones.
	drainedNodes map[string]bool
	// customHostnameIndex maps a canonical (lower-case, trimmed) hostname to
	// the sandbox ID currently holding it. This is the cluster-wide TLS-ask
	// answer source — ingress nodes that don't own a sandbox themselves can
	// still resolve "is this hostname known?" in O(1) under the FSM read lock
	// without scanning every placement. Rebuilt on Restore from the
	// Placement.CustomHostnames slices so older snapshots still load cleanly.
	customHostnameIndex map[string]string
	// auditACLs retains post-delete existence, tenant ownership when present,
	// and the bounded evidence-node index. This lets any ingress authorize an
	// operator or tenant query without probing 2,000 workers. Expiry is
	// replicated and pruning is an explicit Raft command.
	auditACLs map[string]AuditACL

	// volumes holds replicated platform-volume metadata rows, keyed by
	// volumeKey(tenant, id). volumeNameIndex maps volumeNameKey(tenant, name) →
	// id for get-by-name, idempotent get-or-create, and per-tenant quota. These
	// live in the FSM (not per-node SQLite) so a Daytona volume's id/name/source
	// survive the tenant's API ownership moving to another node. The backing data
	// is deterministic in S3/NFS, so only this small metadata table is replicated.
	volumes         map[string]models.Volume
	volumeNameIndex map[string]string
	// volumeAttachments is the cluster-wide live-reference index. It mirrors the
	// single-node SQLite volume_attachments table but lives in raft so a delete
	// request on any node sees sandboxes attached on every worker.
	volumeAttachments          map[string]models.VolumeAttachment
	volumeAttachmentsByVolume  map[string]map[string]struct{}
	volumeAttachmentsBySandbox map[string]map[string]struct{}

	// subMu guards subscribers. Separate from mu so a slow subscriber accept
	// can't block FSM reads — Apply takes mu briefly to write, releases it,
	// then takes subMu to fan out.
	subMu       sync.Mutex
	subscribers []chan<- struct{}
}

type placementRecovery struct {
	Spec          *models.CreateSandboxRequest
	SecretRef     string
	SecretVersion int
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
	return newPlacementFSMWithRecoveryStore(newPlacementRecoveryMemoryStore())
}

func newPlacementFSMWithRecoveryStore(store placementRecoveryStore) *placementFSM {
	return &placementFSM{
		placements:                   make(map[string]Placement),
		recovery:                     make(map[string]placementRecovery),
		recoveryStore:                store,
		nameIndex:                    make(map[string]string),
		shardIndex:                   make(map[int]map[string]struct{}),
		placementIDs:                 newPlacementIDIndex(),
		ownerRefIndex:                make(map[string]*btree.BTreeG[string]),
		hostPortIndex:                make(map[int]hostPortClaim),
		ownerIndex:                   make(map[string]map[string]struct{}),
		pendingReservationClaims:     make(map[string]pendingReservationClaim),
		pendingReservationCapacity:   make(map[string]capacity.Request),
		pendingReservationIDsByOwner: make(map[string]map[string]struct{}),
		reservedIndex:                make(map[string]struct{}),
		drainedNodes:                 make(map[string]bool),
		customHostnameIndex:          make(map[string]string),
		auditACLs:                    make(map[string]AuditACL),
		volumes:                      make(map[string]models.Volume),
		volumeNameIndex:              make(map[string]string),
		volumeAttachments:            make(map[string]models.VolumeAttachment),
		volumeAttachmentsByVolume:    make(map[string]map[string]struct{}),
		volumeAttachmentsBySandbox:   make(map[string]map[string]struct{}),
	}
}

// volumeKey / volumeNameKey are the FSM index keys. The NUL separator can't
// appear in a tenant scope (hash hex) or a sanitized volume name, so the
// concatenation is unambiguous.
func volumeKey(tenant, id string) string       { return tenant + "\x00" + id }
func volumeNameKey(tenant, name string) string { return tenant + "\x00" + name }
func volumeAttachmentKey(tenant, volumeID, sandboxID, target string) string {
	return tenant + "\x00" + volumeID + "\x00" + sandboxID + "\x00" + target
}

func newPlacementIDIndex() *btree.BTreeG[string] {
	return btree.NewG[string](32, func(a, b string) bool { return a < b })
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
		// transition + UpdatedUnix bump even when Spec/Secrets are empty
		// (the reservation already holds them) — so we fall through to the
		// write path below in that case.
		existing, exists := f.fullPlacementLocked(cmd.SandboxID)
		if exists {
			expected := strings.TrimSpace(cmd.ExpectedIncarnationID)
			current := strings.TrimSpace(existing.IncarnationID)
			if expected != "" && current != "" && current != expected {
				return fmt.Errorf("%w: want %q have %q", ErrIncarnationConflict, expected, current)
			}
		}
		if exists && existing.OwnerNodeID == cmd.OwnerNodeID && cmd.Spec == nil && !cmd.hasSecretUpdate() && !existing.IsReserved() {
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
		name := specName(cmd.Spec)
		if cmd.Spec == nil && exists {
			name = placementName(existing)
		}
		if err := f.validateNameUniqueLocked(cmd.SandboxID, name); err != nil {
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
		// secret provider handle the original create stored.
		secrets := applyCommandSecretUpdate(existing, exists, cmd)
		var ports map[int]string
		var portRoutes map[int]ExposedPortRoute
		var customHostnames []string
		var secretRecipients []string
		var incarnationID string
		var secretSealGeneration int64
		var auditNodeIDs []string
		var auditNodesTruncated bool
		ownerRef := strings.TrimSpace(cmd.OwnerRef)
		if exists {
			// Same preservation rule as Spec: opPlace is the "owner + spec"
			// write and must not erase the port intents accumulated by
			// opAddExposedPort calls between creates.
			ports = existing.ExposedPorts
			portRoutes = existing.ExposedPortRoutes
			// Mirror the ExposedPorts preservation: a re-place / reservation
			// promote must not drop user-bound hostnames that
			// opAddCustomDomain installed earlier in the log.
			customHostnames = existing.CustomHostnames
			// Preserve the reserve-time recipient set unless the command
			// explicitly supplies a new one (normal promote leaves it empty).
			secretRecipients = append([]string(nil), existing.SecretRecipients...)
			incarnationID = existing.IncarnationID
			secretSealGeneration = existing.SecretSealGeneration
			auditNodeIDs = append([]string(nil), existing.AuditNodeIDs...)
			auditNodesTruncated = existing.AuditNodesTruncated
			if ownerRef == "" {
				ownerRef = existing.OwnerRef
			}
		}
		if len(cmd.SecretRecipients) > 0 {
			secretRecipients = append([]string(nil), cmd.SecretRecipients...)
		}
		if id := strings.TrimSpace(cmd.IncarnationID); id != "" && incarnationID == "" {
			incarnationID = id
		}
		dataPlaneHost := cmd.OwnerDataPlaneHost
		if dataPlaneHost == "" && exists {
			dataPlaneHost = existing.OwnerDataPlaneHost
		}
		// Drop the OLD name from the index before writing the new placement —
		// otherwise a re-place with a renamed spec would leave a phantom
		// nameIndex entry pointing at this sandbox under its previous name.
		if exists {
			f.releaseNameLocked(cmd.SandboxID, placementName(existing))
			f.releaseOwnerLocked(cmd.SandboxID, existing)
			f.releaseOwnerRefLocked(cmd.SandboxID, existing.OwnerRef)
			if existing.IsReserved() {
				f.releasePendingReservationLocked(cmd.SandboxID)
				f.releasePendingReservationOwnerLocked(cmd.SandboxID, existing.OwnerNodeID)
			}
		}
		p := Placement{
			SandboxID:            cmd.SandboxID,
			OwnerNodeID:          cmd.OwnerNodeID,
			OwnerAPIURL:          cmd.OwnerAPIURL,
			OwnerDataPlaneHost:   dataPlaneHost,
			Version:              f.version,
			CreatedUnix:          created,
			UpdatedUnix:          now,
			Name:                 name,
			Spec:                 spec,
			SecretRef:            secrets.Ref,
			SecretVersion:        secrets.Version,
			SecretRecipients:     secretRecipients,
			IncarnationID:        incarnationID,
			SecretSealGeneration: secretSealGeneration,
			OwnerRef:             ownerRef,
			AuditNodeIDs:         auditNodeIDs,
			AuditNodesTruncated:  auditNodesTruncated,
			ExposedPorts:         ports,
			ExposedPortRoutes:    portRoutes,
			CustomHostnames:      customHostnames,
			// opPlace is the promotion path for reservations: writing the
			// empty State here transitions a Reserved row back to Placed.
			// ExpiresUnix is cleared by the zero-value as well so the GC
			// sweep ignores promoted rows.
			State:       PlacementStatePlaced,
			ExpiresUnix: 0,
		}
		if err := f.storePlacementLocked(cmd.SandboxID, p); err != nil {
			return err
		}
		f.claimNameLocked(cmd.SandboxID, name)
		f.claimShardLocked(cmd.SandboxID)
		f.claimOwnerRefLocked(cmd.SandboxID, ownerRef)
		f.claimOwnerLocked(cmd.SandboxID, p)
		return nil
	case opReserve:
		// Reservations are the first-half of the two-step create: the router
		// commits intent here, the chosen owner promotes via opPlace once the
		// local create succeeds. The intent carries the redacted spec and,
		// when the caller has a globally-resolvable provider, a secret ref so a
		// TTL-expired-then-reclaimed reservation can be promoted by a future
		// re-attempt without re-sealing. The FSM-side name uniqueness check
		// uses the redacted spec's Name.
		if err := f.reservePlacementLocked(cmd, now); err != nil {
			return err
		}
		return nil
	case opReserveBatch:
		if len(cmd.Reservations) == 0 {
			return fmt.Errorf("placementFSM: opReserveBatch requires at least one reservation")
		}
		if err := f.validateReservationBatchLocked(cmd.Reservations, now); err != nil {
			return err
		}
		for _, r := range cmd.Reservations {
			if err := f.reservePlacementLocked(commandFromReservation(r), now); err != nil {
				return err
			}
		}
		return nil
	case opCancelReserve:
		// Only cancel reservations — never delete a placed sandbox, even if a
		// stale rollback attempt arrives after a successful promote. This is
		// the safety property that lets the router fire CancelReservation
		// freely on any failure without worrying about a racing successful
		// promote.
		existing, exists := f.fullPlacementLocked(cmd.SandboxID)
		if !exists || !existing.IsReserved() {
			return nil
		}
		f.releaseNameLocked(cmd.SandboxID, placementName(existing))
		f.releaseShardLocked(cmd.SandboxID)
		f.releaseOwnerRefLocked(cmd.SandboxID, existing.OwnerRef)
		f.releaseAllHostPortsLocked(cmd.SandboxID, existing)
		f.releaseAllCustomHostnamesLocked(cmd.SandboxID, existing)
		f.releasePendingReservationLocked(cmd.SandboxID)
		f.releasePendingReservationOwnerLocked(cmd.SandboxID, existing.OwnerNodeID)
		f.deletePlacementRecoveryLocked(cmd.SandboxID)
		delete(f.placements, cmd.SandboxID)
		return nil
	case opDelete:
		if existing, ok := f.fullPlacementLocked(cmd.SandboxID); ok {
			recordPlacementAuditNode(&existing, existing.OwnerNodeID)
			recordPlacementAuditNode(&existing, existing.OrphanedOwnerNodeID)
			if f.auditACLs == nil {
				f.auditACLs = make(map[string]AuditACL)
			}
			f.auditACLs[cmd.SandboxID] = AuditACL{
				SandboxID:           cmd.SandboxID,
				IncarnationID:       existing.IncarnationID,
				OwnerRef:            strings.TrimSpace(existing.OwnerRef),
				AuditNodeIDs:        append([]string(nil), existing.AuditNodeIDs...),
				AuditNodesTruncated: existing.AuditNodesTruncated,
				ExpiresUnix:         cmd.ExpiresUnix,
			}
			f.releaseNameLocked(cmd.SandboxID, placementName(existing))
			f.releaseShardLocked(cmd.SandboxID)
			f.releaseOwnerRefLocked(cmd.SandboxID, existing.OwnerRef)
			f.releaseAllHostPortsLocked(cmd.SandboxID, existing)
			f.releaseAllCustomHostnamesLocked(cmd.SandboxID, existing)
			f.releaseOwnerLocked(cmd.SandboxID, existing)
			if existing.IsReserved() {
				f.releasePendingReservationLocked(cmd.SandboxID)
				f.releasePendingReservationOwnerLocked(cmd.SandboxID, existing.OwnerNodeID)
			}
		}
		f.releaseVolumeAttachmentsForSandboxLocked(cmd.SandboxID)
		f.deletePlacementRecoveryLocked(cmd.SandboxID)
		delete(f.placements, cmd.SandboxID)
		return nil
	case opPruneAuditACL:
		for id, acl := range f.auditACLs {
			if acl.ExpiresUnix > 0 && acl.ExpiresUnix <= cmd.ExpiresUnix {
				delete(f.auditACLs, id)
			}
		}
		return nil
	case opReassign:
		existing, exists := f.fullPlacementLocked(cmd.SandboxID)
		if !exists {
			// Reassigning a non-existent placement is a no-op (could happen
			// if a delete and a reassign race; delete wins).
			if cmd.ReassignCause == reassignCauseFailover {
				return reassignApplyResult{}
			}
			return nil
		}
		wasReserved := existing.IsReserved()
		if wasReserved {
			f.releasePendingReservationLocked(cmd.SandboxID)
			f.releasePendingReservationOwnerLocked(cmd.SandboxID, existing.OwnerNodeID)
		}
		f.releaseOwnerLocked(cmd.SandboxID, existing)
		previousOwner := existing.OwnerNodeID
		ownerChanged := previousOwner != cmd.OwnerNodeID
		recordPlacementAuditNode(&existing, previousOwner)
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
		if err := f.storePlacementLocked(cmd.SandboxID, existing); err != nil {
			return err
		}
		if wasReserved {
			f.claimPendingReservationLocked(cmd.SandboxID, existing)
		} else {
			f.claimOwnerLocked(cmd.SandboxID, existing)
		}
		if cmd.ReassignCause == reassignCauseFailover {
			return reassignApplyResult{Changed: ownerChanged}
		}
		return nil
	case opOrphanOwner:
		if cmd.NodeID == "" {
			return fmt.Errorf("placementFSM: opOrphanOwner requires node_id")
		}
		for _, id := range f.ownedPlacementIDsLocked(cmd.NodeID) {
			existing, ok := f.fullPlacementLocked(id)
			if !ok || existing.IsReserved() || existing.OwnerNodeID != cmd.NodeID {
				continue
			}
			f.releaseOwnerLocked(id, existing)
			recordPlacementAuditNode(&existing, cmd.NodeID)
			existing.OwnerNodeID = ""
			existing.OwnerAPIURL = ""
			existing.OwnerDataPlaneHost = ""
			existing.OwnerState = PlacementOwnerStateOrphaned
			existing.OrphanedOwnerNodeID = cmd.NodeID
			existing.OrphanedUnix = now
			existing.Version = f.version
			existing.UpdatedUnix = now
			if err := f.storePlacementLocked(id, existing); err != nil {
				return err
			}
		}
		for _, id := range f.pendingReservationIDsLocked(cmd.NodeID) {
			existing, ok := f.fullPlacementLocked(id)
			if !ok || !existing.IsReserved() || existing.OwnerNodeID != cmd.NodeID {
				continue
			}
			f.releaseNameLocked(id, placementName(existing))
			f.releaseShardLocked(id)
			f.releaseOwnerRefLocked(id, existing.OwnerRef)
			f.releaseAllCustomHostnamesLocked(id, existing)
			f.releasePendingReservationLocked(id)
			f.releasePendingReservationOwnerLocked(id, existing.OwnerNodeID)
			f.deletePlacementRecoveryLocked(id)
			delete(f.placements, id)
		}
		return nil
	case opClaimOrphan:
		if cmd.SandboxID == "" || cmd.OwnerNodeID == "" {
			return fmt.Errorf("placementFSM: opClaimOrphan requires sandbox_id and owner_node_id")
		}
		existing, exists := f.fullPlacementLocked(cmd.SandboxID)
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
			oldName := placementName(existing)
			newName := specName(cmd.Spec)
			if newName != oldName {
				if err := f.validateNameUniqueLocked(cmd.SandboxID, newName); err != nil {
					return err
				}
				f.releaseNameLocked(cmd.SandboxID, oldName)
				f.claimNameLocked(cmd.SandboxID, newName)
			}
			existing.Name = newName
			existing.Spec = cmd.Spec
		}
		if cmd.hasSecretUpdate() {
			secrets := applyCommandSecretUpdate(existing, true, cmd)
			existing.SecretRef = secrets.Ref
			existing.SecretVersion = secrets.Version
		}
		recordPlacementAuditNode(&existing, existing.OrphanedOwnerNodeID)
		existing.OwnerNodeID = cmd.OwnerNodeID
		existing.OwnerAPIURL = cmd.OwnerAPIURL
		existing.OwnerDataPlaneHost = cmd.OwnerDataPlaneHost
		existing.OwnerState = PlacementOwnerStateActive
		existing.OrphanedOwnerNodeID = ""
		existing.OrphanedUnix = 0
		existing.Version = f.version
		existing.UpdatedUnix = now
		if err := f.storePlacementLocked(cmd.SandboxID, existing); err != nil {
			return err
		}
		f.claimOwnerLocked(cmd.SandboxID, existing)
		return nil
	case opUpsertSpec:
		existing, exists := f.fullPlacementLocked(cmd.SandboxID)
		if !exists {
			// No placement to attach the spec to. Treat as no-op: the
			// mutating handler that produced this entry will have already
			// failed locally if the sandbox truly doesn't exist.
			return nil
		}
		if cmd.Spec == nil && !cmd.hasSecretUpdate() {
			return nil
		}
		if cmd.Spec != nil {
			oldName := placementName(existing)
			newName := specName(cmd.Spec)
			if newName != oldName {
				if err := f.validateNameUniqueLocked(cmd.SandboxID, newName); err != nil {
					return err
				}
				f.releaseNameLocked(cmd.SandboxID, oldName)
				f.claimNameLocked(cmd.SandboxID, newName)
			}
			existing.Name = newName
			existing.Spec = cmd.Spec
		}
		// Replace the provider handle only when the caller supplied one.
		// Resize / lifecycle write-throughs leave it empty, preserving the
		// original secrets — the only call sites that ship a fresh handle are
		// create (opPlace, not here) and an explicit credential rotation.
		if cmd.hasSecretUpdate() {
			secrets := applyCommandSecretUpdate(existing, true, cmd)
			existing.SecretRef = secrets.Ref
			existing.SecretVersion = secrets.Version
		}
		wasReserved := existing.IsReserved()
		if wasReserved {
			f.releasePendingReservationLocked(cmd.SandboxID)
		}
		existing.Version = f.version
		existing.UpdatedUnix = now
		if err := f.storePlacementLocked(cmd.SandboxID, existing); err != nil {
			return err
		}
		if wasReserved {
			f.claimPendingReservationLocked(cmd.SandboxID, existing)
		}
		return nil
	case opUpdateSecretRecipients:
		// Dead-target expansion / reseal coordination: replace the frozen
		// recipient set (and optionally the seal handle) while preserving
		// ownership and IncarnationID. Empty recipients is a no-op so a
		// partial forward can't wipe the set.
		existing, exists := f.fullPlacementLocked(cmd.SandboxID)
		if !exists || len(cmd.SecretRecipients) == 0 {
			return nil
		}
		if exp := strings.TrimSpace(cmd.ExpectedIncarnationID); exp != "" {
			if cur := strings.TrimSpace(existing.IncarnationID); cur != exp {
				return fmt.Errorf("%w: incarnation want %q have %q", ErrSecretRecipientsCASMismatch, exp, cur)
			}
		}
		if cmd.ExpectedSealGeneration > 0 {
			if cur := existing.SecretSealGeneration; cur != cmd.ExpectedSealGeneration {
				return fmt.Errorf("%w: seal_generation want %d have %d", ErrSecretRecipientsCASMismatch, cmd.ExpectedSealGeneration, cur)
			}
		}
		existing.SecretRecipients = append([]string(nil), cmd.SecretRecipients...)
		if cmd.hasSecretUpdate() {
			secrets := applyCommandSecretUpdate(existing, true, cmd)
			existing.SecretRef = secrets.Ref
			existing.SecretVersion = secrets.Version
		}
		if cmd.SecretSealGeneration > 0 {
			existing.SecretSealGeneration = cmd.SecretSealGeneration
		}
		existing.Version = f.version
		existing.UpdatedUnix = now
		return f.storePlacementLocked(cmd.SandboxID, existing)
	case opAddExposedPort:
		existing, exists := f.fullPlacementLocked(cmd.SandboxID)
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
		if err := f.storePlacementLocked(cmd.SandboxID, existing); err != nil {
			return err
		}
		return nil
	case opRemoveExposedPort:
		existing, exists := f.fullPlacementLocked(cmd.SandboxID)
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
		if err := f.storePlacementLocked(cmd.SandboxID, existing); err != nil {
			return err
		}
		return nil
	case opAddCustomDomain:
		// Cluster-wide hostname uniqueness check. The service layer already
		// rejects a same-sandbox duplicate locally, but two creates racing on
		// different owners could both pass their local validation and end up
		// at the FSM. The hostname index is the single tiebreaker — first
		// committed log entry wins, the loser's owner returns
		// ErrCustomHostnameConflict so the local row can roll back.
		if cmd.SandboxID == "" || cmd.Hostname == "" {
			return fmt.Errorf("placementFSM: opAddCustomDomain requires sandbox_id and hostname")
		}
		existing, exists := f.fullPlacementLocked(cmd.SandboxID)
		if !exists {
			// No row to attach the hostname to — the local create on the
			// owner has either failed or hasn't promoted yet. Treat as no-op
			// rather than error: the next AddCustomDomain after a successful
			// create will redrive this safely (and the service layer never
			// surfaces it to a user).
			return nil
		}
		if owner, claimed := f.customHostnameIndex[cmd.Hostname]; claimed && owner != cmd.SandboxID {
			return fmt.Errorf("%w: %q held by %s", ErrCustomHostnameConflict, cmd.Hostname, owner)
		}
		if existingHasHostname(existing, cmd.Hostname) {
			// Idempotent re-add: the hostname is already on the placement
			// and the index already points here. Skip the version bump.
			return nil
		}
		existing.CustomHostnames = insertSortedHostname(existing.CustomHostnames, cmd.Hostname)
		existing.Version = f.version
		existing.UpdatedUnix = now
		if err := f.storePlacementLocked(cmd.SandboxID, existing); err != nil {
			return err
		}
		f.claimCustomHostnameLocked(cmd.SandboxID, cmd.Hostname)
		return nil
	case opRemoveCustomDomain:
		if cmd.SandboxID == "" || cmd.Hostname == "" {
			return fmt.Errorf("placementFSM: opRemoveCustomDomain requires sandbox_id and hostname")
		}
		existing, exists := f.fullPlacementLocked(cmd.SandboxID)
		if !exists {
			// Stale replay against an already-deleted placement is harmless.
			// Make sure the index doesn't still point at the now-gone id.
			f.releaseCustomHostnameLocked(cmd.SandboxID, cmd.Hostname)
			return nil
		}
		if !existingHasHostname(existing, cmd.Hostname) {
			return nil
		}
		existing.CustomHostnames = removeHostname(existing.CustomHostnames, cmd.Hostname)
		existing.Version = f.version
		existing.UpdatedUnix = now
		if err := f.storePlacementLocked(cmd.SandboxID, existing); err != nil {
			return err
		}
		f.releaseCustomHostnameLocked(cmd.SandboxID, cmd.Hostname)
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
	case opUpsertVolume:
		// Idempotent get-or-create. A duplicate create (same tenant+name)
		// converges on the existing row rather than inserting a second, so the
		// op is safe under retry and concurrent duplicate calls. Quota is
		// enforced here, on the authoritative ordered log, so two creates for
		// different names can't both observe the same pre-insert count.
		if cmd.Volume == nil {
			return fmt.Errorf("placementFSM: opUpsertVolume requires a volume")
		}
		v := *cmd.Volume
		tenant := strings.TrimSpace(v.Tenant)
		name := strings.TrimSpace(v.Name)
		id := strings.TrimSpace(v.ID)
		if tenant == "" || name == "" || id == "" || strings.TrimSpace(v.Backend) == "" {
			return fmt.Errorf("placementFSM: opUpsertVolume requires tenant, name, id, backend")
		}
		if _, exists := f.volumeNameIndex[volumeNameKey(tenant, name)]; exists {
			// Already present — keep the existing row (idempotent). Readers fetch
			// the canonical row by name afterward.
			return nil
		}
		if cmd.MaxPerTenant > 0 {
			count := 0
			for k := range f.volumes {
				if strings.HasPrefix(k, tenant+"\x00") {
					count++
				}
			}
			if count >= cmd.MaxPerTenant {
				return ErrVolumeQuotaExceeded
			}
		}
		if v.CreatedAt.IsZero() {
			v.CreatedAt = time.Unix(now, 0).UTC()
		}
		v.Tenant, v.Name, v.ID = tenant, name, id
		f.volumes[volumeKey(tenant, id)] = v
		f.volumeNameIndex[volumeNameKey(tenant, name)] = id
		return nil
	case opDeleteVolume:
		tenant := strings.TrimSpace(cmd.VolumeTenant)
		id := strings.TrimSpace(cmd.VolumeID)
		if tenant == "" || id == "" {
			return fmt.Errorf("placementFSM: opDeleteVolume requires tenant and id")
		}
		key := volumeKey(tenant, id)
		row, ok := f.volumes[key]
		if !ok {
			return ErrUnknownVolume
		}
		if n := f.volumeAttachmentCountLocked(tenant, id); n > 0 {
			return fmt.Errorf("%w: %d attachments", ErrVolumeInUse, n)
		}
		delete(f.volumes, key)
		delete(f.volumeNameIndex, volumeNameKey(tenant, row.Name))
		return nil
	case opPutVolumeAttach:
		if len(cmd.VolumeAttachments) == 0 {
			return nil
		}
		cleaned := make([]models.VolumeAttachment, 0, len(cmd.VolumeAttachments))
		for _, a := range cmd.VolumeAttachments {
			tenant := strings.TrimSpace(a.Tenant)
			volumeID := strings.TrimSpace(a.VolumeID)
			sandboxID := strings.TrimSpace(a.SandboxID)
			target := strings.TrimSpace(a.Target)
			source := strings.TrimSpace(a.Source)
			if tenant == "" || volumeID == "" || sandboxID == "" || target == "" || source == "" {
				return fmt.Errorf("placementFSM: opPutVolumeAttach requires tenant, volume_id, sandbox_id, target, and source")
			}
			if _, ok := f.volumes[volumeKey(tenant, volumeID)]; !ok {
				return ErrUnknownVolume
			}
			a.Tenant, a.VolumeID, a.SandboxID, a.Target, a.Source = tenant, volumeID, sandboxID, target, source
			if a.CreatedAt.IsZero() {
				a.CreatedAt = time.Unix(now, 0).UTC()
			}
			cleaned = append(cleaned, a)
		}
		for _, a := range cleaned {
			f.putVolumeAttachmentLocked(a)
		}
		return nil
	case opDeleteVolumeAttach:
		sandboxID := strings.TrimSpace(cmd.VolumeSandboxID)
		if sandboxID == "" {
			return fmt.Errorf("placementFSM: opDeleteVolumeAttach requires sandbox_id")
		}
		f.releaseVolumeAttachmentsForSandboxLocked(sandboxID)
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

func placementName(p Placement) string {
	if name := strings.TrimSpace(p.Name); name != "" {
		return name
	}
	return specName(p.Spec)
}

func (f *placementFSM) validateReservationBatchLocked(reservations []reservationCommand, now int64) error {
	seenIDs := make(map[string]struct{}, len(reservations))
	seenNames := make(map[string]string, len(reservations))
	for _, r := range reservations {
		if r.SandboxID == "" || r.OwnerNodeID == "" {
			return fmt.Errorf("placementFSM: opReserveBatch requires sandbox_id and owner_node_id")
		}
		if _, dup := seenIDs[r.SandboxID]; dup {
			return fmt.Errorf("%w: duplicate reservation for %s in batch", ErrReservationConflict, r.SandboxID)
		}
		seenIDs[r.SandboxID] = struct{}{}

		if existing, exists := f.fullPlacementLocked(r.SandboxID); exists {
			if !existing.IsReserved() {
				return fmt.Errorf("%w: %s already placed by %s", ErrReservationConflict, r.SandboxID, existing.OwnerNodeID)
			}
			if existing.OwnerNodeID != r.OwnerNodeID && now <= existing.ExpiresUnix {
				return fmt.Errorf("%w: %s reserved by %s", ErrReservationConflict, r.SandboxID, existing.OwnerNodeID)
			}
		}

		name := specName(r.Spec)
		if name == "" {
			continue
		}
		if prior, ok := seenNames[name]; ok && prior != r.SandboxID {
			return fmt.Errorf("%w: %q appears more than once in reservation batch", ErrNameConflict, name)
		}
		seenNames[name] = r.SandboxID
		if err := f.validateNameUniqueLocked(r.SandboxID, name); err != nil {
			return err
		}
	}
	return nil
}

func (f *placementFSM) reservePlacementLocked(cmd command, now int64) error {
	if cmd.SandboxID == "" || cmd.OwnerNodeID == "" {
		return fmt.Errorf("placementFSM: opReserve requires sandbox_id and owner_node_id")
	}
	existing, exists := f.fullPlacementLocked(cmd.SandboxID)
	if exists {
		// Reject when the slot is already materialized — a router racing a
		// completed sandbox should back off and let the caller see 409.
		if !existing.IsReserved() {
			return fmt.Errorf("%w: %s already placed by %s", ErrReservationConflict, cmd.SandboxID, existing.OwnerNodeID)
		}
		// Re-reserve from the same owner before expiry is an idempotent retry —
		// refresh the TTL (and recipient set when supplied) and treat it as a
		// no-op otherwise.
		if existing.OwnerNodeID == cmd.OwnerNodeID && now <= existing.ExpiresUnix {
			existing.ExpiresUnix = cmd.ExpiresUnix
			existing.Version = f.version
			existing.UpdatedUnix = now
			if len(cmd.SecretRecipients) > 0 {
				existing.SecretRecipients = append([]string(nil), cmd.SecretRecipients...)
			}
			if id := strings.TrimSpace(cmd.IncarnationID); id != "" && existing.IncarnationID == "" {
				existing.IncarnationID = id
			}
			oldOwnerRef := existing.OwnerRef
			if ref := strings.TrimSpace(cmd.OwnerRef); ref != "" {
				existing.OwnerRef = ref
			}
			if err := f.storePlacementLocked(cmd.SandboxID, existing); err != nil {
				return err
			}
			if existing.OwnerRef != oldOwnerRef {
				f.releaseOwnerRefLocked(cmd.SandboxID, oldOwnerRef)
				f.claimOwnerRefLocked(cmd.SandboxID, existing.OwnerRef)
			}
			f.refreshPendingReservationExpiryLocked(cmd.SandboxID, cmd.ExpiresUnix)
			return nil
		}
		// Expired reservations are eligible for overwrite by a fresh reservation.
		if now > existing.ExpiresUnix {
			f.releasePendingReservationLocked(cmd.SandboxID)
			f.releasePendingReservationOwnerLocked(cmd.SandboxID, existing.OwnerNodeID)
			f.releaseNameLocked(cmd.SandboxID, placementName(existing))
			f.releaseShardLocked(cmd.SandboxID)
			f.releaseOwnerRefLocked(cmd.SandboxID, existing.OwnerRef)
		} else {
			return fmt.Errorf("%w: %s reserved by %s", ErrReservationConflict, cmd.SandboxID, existing.OwnerNodeID)
		}
	}
	name := specName(cmd.Spec)
	if err := f.validateNameUniqueLocked(cmd.SandboxID, name); err != nil {
		return err
	}
	secrets := applyCommandSecretUpdate(Placement{}, false, cmd)
	p := Placement{
		SandboxID:          cmd.SandboxID,
		OwnerNodeID:        cmd.OwnerNodeID,
		OwnerAPIURL:        cmd.OwnerAPIURL,
		OwnerDataPlaneHost: cmd.OwnerDataPlaneHost,
		Version:            f.version,
		CreatedUnix:        now,
		UpdatedUnix:        now,
		Name:               name,
		Spec:               cmd.Spec,
		SecretRef:          secrets.Ref,
		SecretVersion:      secrets.Version,
		SecretRecipients:   append([]string(nil), cmd.SecretRecipients...),
		IncarnationID:      strings.TrimSpace(cmd.IncarnationID),
		OwnerRef:           strings.TrimSpace(cmd.OwnerRef),
		State:              PlacementStateReserved,
		ExpiresUnix:        cmd.ExpiresUnix,
	}
	if err := f.storePlacementLocked(cmd.SandboxID, p); err != nil {
		return err
	}
	f.claimNameLocked(cmd.SandboxID, name)
	f.claimShardLocked(cmd.SandboxID)
	f.claimOwnerRefLocked(cmd.SandboxID, p.OwnerRef)
	f.claimPendingReservationLocked(cmd.SandboxID, p)
	return nil
}

// validateNameUniqueLocked checks that no other placement currently claims
// name. Empty name is always allowed (anonymous sandboxes don't conflict);
// matches the local SQLite partial-unique-index behavior.
func (f *placementFSM) validateNameUniqueLocked(sandboxID, name string) error {
	name = strings.TrimSpace(name)
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
	name = strings.TrimSpace(name)
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
	name = strings.TrimSpace(name)
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
	if f.placementIDs == nil {
		f.placementIDs = newPlacementIDIndex()
	}
	f.placementIDs.ReplaceOrInsert(sandboxID)
}

func (f *placementFSM) releaseShardLocked(sandboxID string) {
	if sandboxID == "" {
		return
	}
	if f.shardIndex != nil {
		shard := PlacementShardForSandbox(sandboxID, DefaultPlacementShardCount)
		ids := f.shardIndex[shard]
		if ids != nil {
			delete(ids, sandboxID)
			if len(ids) == 0 {
				delete(f.shardIndex, shard)
			}
		}
	}
	if f.placementIDs != nil {
		f.placementIDs.Delete(sandboxID)
	}
}

func (f *placementFSM) claimOwnerRefLocked(sandboxID, ownerRef string) {
	sandboxID = strings.TrimSpace(sandboxID)
	ownerRef = strings.TrimSpace(ownerRef)
	if sandboxID == "" || ownerRef == "" {
		return
	}
	if f.ownerRefIndex == nil {
		f.ownerRefIndex = make(map[string]*btree.BTreeG[string])
	}
	tree := f.ownerRefIndex[ownerRef]
	if tree == nil {
		tree = newPlacementIDIndex()
		f.ownerRefIndex[ownerRef] = tree
	}
	tree.ReplaceOrInsert(sandboxID)
}

func (f *placementFSM) releaseOwnerRefLocked(sandboxID, ownerRef string) {
	sandboxID = strings.TrimSpace(sandboxID)
	ownerRef = strings.TrimSpace(ownerRef)
	if sandboxID == "" || ownerRef == "" || f.ownerRefIndex == nil {
		return
	}
	tree := f.ownerRefIndex[ownerRef]
	if tree == nil {
		return
	}
	tree.Delete(sandboxID)
	if tree.Len() == 0 {
		delete(f.ownerRefIndex, ownerRef)
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

func (f *placementFSM) claimCustomHostnameLocked(sandboxID, hostname string) {
	if sandboxID == "" || hostname == "" {
		return
	}
	if f.customHostnameIndex == nil {
		f.customHostnameIndex = make(map[string]string)
	}
	f.customHostnameIndex[hostname] = sandboxID
}

// releaseCustomHostnameLocked drops hostname from the secondary index when
// sandboxID is the recorded owner. The owner guard prevents a stale release
// from a since-orphaned-and-reclaimed sandbox from unmapping a new claim — the
// same delete-then-place race that releaseNameLocked guards against.
func (f *placementFSM) releaseCustomHostnameLocked(sandboxID, hostname string) {
	if hostname == "" || f.customHostnameIndex == nil {
		return
	}
	if owner, ok := f.customHostnameIndex[hostname]; ok && (sandboxID == "" || owner == sandboxID) {
		delete(f.customHostnameIndex, hostname)
	}
}

func (f *placementFSM) releaseAllCustomHostnamesLocked(sandboxID string, p Placement) {
	for _, h := range p.CustomHostnames {
		f.releaseCustomHostnameLocked(sandboxID, h)
	}
}

// existingHasHostname reports whether hostname is already present in the
// placement's hostname slice. Linear in the slice but the per-sandbox cap
// (models.MaxCustomDomainsPerSandbox) bounds it tightly.
func existingHasHostname(p Placement, hostname string) bool {
	for _, h := range p.CustomHostnames {
		if h == hostname {
			return true
		}
	}
	return false
}

// insertSortedHostname returns a new slice with hostname inserted in sorted
// order. Sorted slices keep snapshot bytes deterministic across rebuilds and
// give every node the same Caddy matcher order for free.
func insertSortedHostname(existing []string, hostname string) []string {
	if hostname == "" {
		return existing
	}
	out := make([]string, 0, len(existing)+1)
	inserted := false
	for _, h := range existing {
		if !inserted && hostname < h {
			out = append(out, hostname)
			inserted = true
		}
		if h == hostname {
			// Defensive: existingHasHostname guards the caller, but if a
			// stale path slipped through, return the unchanged sorted slice.
			return existing
		}
		out = append(out, h)
	}
	if !inserted {
		out = append(out, hostname)
	}
	return out
}

func removeHostname(existing []string, hostname string) []string {
	for i, h := range existing {
		if h != hostname {
			continue
		}
		// Keep the slice sorted by splicing rather than swap-remove.
		out := make([]string, 0, len(existing)-1)
		out = append(out, existing[:i]...)
		out = append(out, existing[i+1:]...)
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return existing
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
	if f.reservedIndex == nil {
		f.reservedIndex = make(map[string]struct{})
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
	f.reservedIndex[sandboxID] = struct{}{}
	if claim.ExpiresUnix > 0 {
		heap.Push(&f.pendingReservationExpiries, pendingReservationExpiry{SandboxID: sandboxID, ExpiresUnix: claim.ExpiresUnix})
	}
}

func (f *placementFSM) releasePendingReservationLocked(sandboxID string) {
	f.releasePendingReservationClaimLocked(sandboxID)
	delete(f.reservedIndex, sandboxID)
}

func (f *placementFSM) releasePendingReservationClaimLocked(sandboxID string) {
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

func (f *placementFSM) livePendingReservationCount(owner string, now int64) int {
	if owner == "" {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pendingReservationIDsByOwner == nil {
		return 0
	}
	f.pruneExpiredPendingReservationsLocked(now)
	ids := f.pendingReservationIDsByOwner[owner]
	if len(ids) == 0 {
		return 0
	}
	count := 0
	for id := range ids {
		claim, ok := f.pendingReservationClaims[id]
		if !ok {
			continue
		}
		if claim.ExpiresUnix <= 0 || now <= claim.ExpiresUnix {
			count++
		}
	}
	return count
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
		f.releasePendingReservationClaimLocked(next.SandboxID)
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

func (f *placementFSM) fullPlacementLocked(id string) (Placement, bool) {
	p, ok := f.placements[id]
	if !ok {
		return Placement{}, false
	}
	if p.RecoveryRef != "" {
		if rec, ok, err := f.resolveRecoveryRef(p.RecoveryRef); err == nil && ok {
			return attachPlacementRecovery(p, rec), true
		}
	}
	if rec, ok := f.recovery[id]; ok {
		p = attachPlacementRecovery(p, rec)
	}
	return p, true
}

func attachPlacementRecovery(p Placement, rec placementRecovery) Placement {
	p.Spec = rec.Spec
	p.SecretRef = rec.SecretRef
	p.SecretVersion = rec.SecretVersion
	return p
}

// resolveRecoveryRef serves ROW-level recovery hydration: FSM snapshots carry
// hot rows with a RecoveryRef but not the payload, so a voter that joins from
// a snapshot must fetch each payload from a peer exactly once (fetch-on-miss,
// cached into the local store). Commands never carry refs — payloads ride
// inline in the raft entry — so this is the only remote-recovery path left.
// Pinned by TestFSMSnapshotJoinFetchOnMiss.
func (f *placementFSM) resolveRecoveryRef(ref string) (placementRecovery, bool, error) {
	if f.recoveryStore != nil {
		rec, ok, err := f.recoveryStore.Get(ref)
		if err != nil {
			return placementRecovery{}, false, err
		}
		if ok {
			return rec, true, nil
		}
	}
	if f.recoveryResolver == nil {
		return placementRecovery{}, false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlPlanePlacementRequestTimeout)
	defer cancel()
	blob, ok, err := f.recoveryResolver(ctx, ref)
	if err != nil || !ok {
		return placementRecovery{}, ok, err
	}
	if err := f.storeRecoveryBlob(blob); err != nil {
		return placementRecovery{}, false, err
	}
	return blob.recovery(), true, nil
}

func (f *placementFSM) storeRecoveryBlob(blob RecoveryBlob) error {
	if f.recoveryStore == nil {
		return nil
	}
	ref, err := f.recoveryStore.Put(blob.SandboxID, blob.recovery())
	if err != nil {
		return err
	}
	if ref != blob.Ref {
		return fmt.Errorf("placement recovery blob ref mismatch: got %s want %s", ref, blob.Ref)
	}
	return nil
}

func (f *placementFSM) storePlacementLocked(id string, p Placement) error {
	hot, rec := splitPlacement(p)
	if rec.empty() {
		if hot.RecoveryRef == "" {
			delete(f.recovery, id)
		}
		f.placements[id] = hot
		return nil
	}
	if f.recoveryStore != nil {
		ref, err := f.recoveryStore.Put(id, rec)
		if err != nil {
			return err
		}
		hot.RecoveryRef = ref
		delete(f.recovery, id)
	} else {
		if f.recovery == nil {
			f.recovery = make(map[string]placementRecovery)
		}
		f.recovery[id] = clonePlacementRecovery(rec)
	}
	f.placements[id] = hot
	return nil
}

func (f *placementFSM) deletePlacementRecoveryLocked(id string) {
	delete(f.recovery, id)
}

func splitPlacement(p Placement) (Placement, placementRecovery) {
	rec := placementRecovery{
		Spec:          p.Spec,
		SecretRef:     p.SecretRef,
		SecretVersion: p.SecretVersion,
	}
	if p.Name == "" {
		p.Name = specName(p.Spec)
	}
	p.Spec = nil
	p.SecretRef = ""
	p.SecretVersion = 0
	return p, rec
}

func (r placementRecovery) empty() bool {
	return r.Spec == nil && r.SecretRef == "" && r.SecretVersion == 0
}

// get returns the placement for id, or zero-value + false if absent.
func (f *placementFSM) get(id string) (Placement, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	p, ok := f.fullPlacementLocked(id)
	if !ok {
		return Placement{}, false
	}
	return clonePlacement(p), true
}

// placementsByIDs returns hot clones for the requested IDs. Missing IDs are
// omitted. Holds the FSM read lock once for the whole batch.
func (f *placementFSM) placementsByIDs(ids []string) map[string]Placement {
	out := make(map[string]Placement, len(ids))
	if len(ids) == 0 {
		return out
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if p, ok := f.placements[id]; ok {
			out[id] = cloneHotPlacement(p)
		}
	}
	return out
}

// sandboxIDByCustomHostname returns the sandbox ID currently claiming
// hostname in the replicated custom-domain index. hostname is matched
// verbatim — callers are expected to canonicalize (lower-case, trim) before
// looking up, matching how opAddCustomDomain stores it.
func (f *placementFSM) sandboxIDByCustomHostname(hostname string) (string, bool) {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return "", false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	id, ok := f.customHostnameIndex[hostname]
	return id, ok
}

// customHostnamesForSandbox returns a sorted copy of the hostname set for
// sandboxID, or nil when none. Callers must not mutate the returned slice;
// it is cloned so a follow-up Apply doesn't perturb the snapshot a reader is
// using.
func (f *placementFSM) customHostnamesForSandbox(sandboxID string) []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	p, ok := f.placements[sandboxID]
	if !ok || len(p.CustomHostnames) == 0 {
		return nil
	}
	out := make([]string, len(p.CustomHostnames))
	copy(out, p.CustomHostnames)
	return out
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

func (f *placementFSM) expiredReservationIDs(now int64) []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if now <= 0 || len(f.reservedIndex) == 0 {
		return nil
	}
	out := make([]string, 0)
	for id := range f.reservedIndex {
		p, ok := f.placements[id]
		if !ok || !p.IsReserved() || p.ExpiresUnix == 0 || now <= p.ExpiresUnix {
			continue
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (f *placementFSM) fullPlacementsForOwner(nodeID string) map[string]Placement {
	f.mu.RLock()
	defer f.mu.RUnlock()
	ids := f.ownedPlacementIDsLocked(nodeID)
	out := make(map[string]Placement, len(ids))
	for _, id := range ids {
		if p, ok := f.fullPlacementLocked(id); ok {
			out[id] = clonePlacement(p)
		}
	}
	return out
}

// snapshot copies the full placement map for correctness-sensitive tests and
// recovery paths. Ingress/list reads use placementsForShards and placementPage,
// which intentionally return hot rows without recovery payloads.
func (f *placementFSM) snapshot() map[string]Placement {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[string]Placement, len(f.placements))
	for k := range f.placements {
		p, _ := f.fullPlacementLocked(k)
		out[k] = clonePlacement(p)
	}
	return out
}

func (f *placementFSM) placementsForShards(filter PlacementShardFilter) []Placement {
	filter = filter.Normalize()
	f.mu.RLock()
	defer f.mu.RUnlock()
	if filter.allShards() {
		out := make([]Placement, 0, len(f.placements))
		for _, p := range f.placements {
			out = append(out, cloneHotPlacement(p))
		}
		return out
	}

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
				out = append(out, cloneHotPlacement(p))
			}
		}
		return out
	}

	out := make([]Placement, 0)
	for _, shard := range filter.Shards {
		for id := range f.shardIndex[shard] {
			if p, ok := f.placements[id]; ok {
				out = append(out, cloneHotPlacement(p))
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

	// Fetch Limit+1 so we can tell an exact-full page from a true last page.
	peekReq := req
	peekReq.Limit = req.Limit + 1
	ids := f.pagePlacementIDsLocked(peekReq, shardFilter, allShards, wantShards)
	hasMore := len(ids) > req.Limit
	if hasMore {
		ids = ids[:req.Limit]
	}
	out := make([]Placement, 0, len(ids))
	for _, id := range ids {
		out = append(out, cloneHotPlacement(f.placements[id]))
	}
	next := ""
	// Only emit a cursor when a later ID exists — exact limit boundaries
	// (e.g. 100000 rows @ page size 100) must end with an empty token.
	if hasMore && len(ids) > 0 {
		next = ids[len(ids)-1]
	}
	return PlacementPageResponse{Placements: out, NextPageToken: next, Authoritative: true}
}

func (f *placementFSM) pagePlacementIDsLocked(req PlacementPageRequest, shardFilter PlacementShardFilter, allShards bool, wantShards map[int]struct{}) []string {
	if ownerRef := strings.TrimSpace(req.OwnerRef); ownerRef != "" {
		if f.ownerRefIndex != nil {
			return f.pagePlacementIDsByOwnerRefLocked(req, ownerRef, shardFilter, allShards, wantShards)
		}
		// Index missing (partial restore) — fall back to scan.
		return f.pagePlacementIDsByScanLocked(req, shardFilter, allShards, wantShards)
	}
	if f.placementIDs == nil {
		return f.pagePlacementIDsByScanLocked(req, shardFilter, allShards, wantShards)
	}
	if allShards || shardFilter.ShardCount != DefaultPlacementShardCount || len(shardFilter.Shards) > 1024 {
		return f.pagePlacementIDsFromTreeLocked(req, shardFilter, allShards, wantShards)
	}

	ids := make([]string, 0, req.Limit)
	for _, shard := range shardFilter.Shards {
		for id := range f.shardIndex[shard] {
			if req.PageToken != "" && id <= req.PageToken {
				continue
			}
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > req.Limit {
		ids = ids[:req.Limit]
	}
	return ids
}

func (f *placementFSM) pagePlacementIDsByOwnerRefLocked(req PlacementPageRequest, ownerRef string, shardFilter PlacementShardFilter, allShards bool, wantShards map[int]struct{}) []string {
	tree := f.ownerRefIndex[ownerRef]
	if tree == nil {
		return nil
	}
	ids := make([]string, 0, req.Limit)
	shardCount := shardFilter.ShardCount
	if shardCount <= 0 {
		shardCount = DefaultPlacementShardCount
	}
	tree.AscendGreaterOrEqual(req.PageToken, func(id string) bool {
		if req.PageToken != "" && id <= req.PageToken {
			return true
		}
		if !allShards {
			if _, ok := wantShards[PlacementShardForSandbox(id, shardCount)]; !ok {
				return true
			}
		}
		ids = append(ids, id)
		return len(ids) < req.Limit
	})
	return ids
}

func (f *placementFSM) pagePlacementIDsByScanLocked(req PlacementPageRequest, shardFilter PlacementShardFilter, allShards bool, wantShards map[int]struct{}) []string {
	ids := make([]string, 0, len(f.placements))
	shardCount := shardFilter.ShardCount
	if shardCount <= 0 {
		shardCount = DefaultPlacementShardCount
	}
	ownerRef := strings.TrimSpace(req.OwnerRef)
	for id, p := range f.placements {
		if req.PageToken != "" && id <= req.PageToken {
			continue
		}
		placeOwner := strings.TrimSpace(p.OwnerRef)
		// Never match empty OwnerRef into a tenant page — partial restores can
		// leave blank ownership that would otherwise pollute cursors.
		if ownerRef != "" && (placeOwner == "" || placeOwner != ownerRef) {
			continue
		}
		if !allShards {
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
	return ids
}

func (f *placementFSM) pagePlacementIDsFromTreeLocked(req PlacementPageRequest, shardFilter PlacementShardFilter, allShards bool, wantShards map[int]struct{}) []string {
	ids := make([]string, 0, req.Limit)
	shardCount := shardFilter.ShardCount
	if shardCount <= 0 {
		shardCount = DefaultPlacementShardCount
	}
	f.placementIDs.AscendGreaterOrEqual(req.PageToken, func(id string) bool {
		if req.PageToken != "" && id <= req.PageToken {
			return true
		}
		if !allShards {
			if _, ok := wantShards[PlacementShardForSandbox(id, shardCount)]; !ok {
				return true
			}
		}
		ids = append(ids, id)
		return len(ids) < req.Limit
	})
	return ids
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

func (f *placementFSM) auditACLForSandbox(sandboxID string, nowUnix int64) (AuditACL, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	acl, ok := f.auditACLs[strings.TrimSpace(sandboxID)]
	if !ok {
		return AuditACL{}, false
	}
	if acl.ExpiresUnix > 0 && acl.ExpiresUnix <= nowUnix {
		return AuditACL{}, false
	}
	return cloneAuditACL(acl), true
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

// fsmSnapshotPayload is the on-disk envelope for an FSM snapshot. Rows is the
// compact current format: hot placement fields plus a small RecoveryRef. The
// bulky recovery spec/secret payload lives in the local recovery store, not in
// snapshot bytes. Placements/Recovery are retained for older envelope snapshots,
// and Restore also accepts the original bare map[string]Placement format.
// DrainedNodes is optional; older snapshots decode it as nil and the FSM treats
// that as "no drains."
type fsmSnapshotPayload struct {
	Version      uint64
	Rows         []placementSnapshotRow
	Placements   map[string]Placement
	Recovery     map[string]placementRecovery
	DrainedNodes map[string]bool
	AuditACLs    map[string]AuditACL
	// Volumes is the replicated platform-volume metadata. Optional; older
	// snapshots decode it as nil and the FSM treats that as "no volumes."
	Volumes           []models.Volume
	VolumeAttachments []models.VolumeAttachment
}

type placementSnapshotRow struct {
	Placement Placement
	// Recovery is retained only so Restore can read snapshots produced by the
	// previous hot/cold FSM format. New snapshots leave it empty.
	Recovery placementRecovery
}

// Snapshot returns a raft.FSMSnapshot capturing current placement state.
func (f *placementFSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	version := f.version
	rows := make([]placementSnapshotRow, 0, len(f.placements))
	recoveryRefs := make([]string, 0, len(f.placements))
	for _, p := range f.placements {
		rows = append(rows, placementSnapshotRow{Placement: cloneHotPlacement(p)})
		if p.RecoveryRef != "" {
			recoveryRefs = append(recoveryRefs, p.RecoveryRef)
		}
	}
	drained := make(map[string]bool, len(f.drainedNodes))
	for k, v := range f.drainedNodes {
		drained[k] = v
	}
	auditACLs := make(map[string]AuditACL, len(f.auditACLs))
	for id, acl := range f.auditACLs {
		auditACLs[id] = cloneAuditACL(acl)
	}
	return &fsmSnapshot{
		version:           version,
		rows:              rows,
		drainedNodes:      drained,
		auditACLs:         auditACLs,
		volumes:           f.volumesSnapshotLocked(),
		volumeAttachments: f.volumeAttachmentsSnapshotLocked(),
		recoveryStore:     f.recoveryStore,
		recoveryRefs:      recoveryRefs,
	}, nil
}

// Restore loads state from a previously written snapshot. Replaces in-memory
// placements wholesale — raft only calls Restore on a cold start or follower
// resync.
func (f *placementFSM) Restore(rc io.ReadCloser) (err error) {
	start := time.Now()
	defer func() { recordSnapshotRestore(time.Since(start), err) }()
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
	if len(payload.Rows) > 0 {
		payload.Placements = make(map[string]Placement, len(payload.Rows))
		payload.Recovery = make(map[string]placementRecovery, len(payload.Rows))
		for _, row := range payload.Rows {
			id := row.Placement.SandboxID
			if id == "" {
				continue
			}
			payload.Placements[id] = row.Placement
			if !row.Recovery.empty() {
				payload.Recovery[id] = row.Recovery
			}
		}
	} else if payload.Placements == nil {
		payload.Placements = make(map[string]Placement)
	}
	f.placements = make(map[string]Placement, len(payload.Placements))
	f.recovery = make(map[string]placementRecovery, len(payload.Recovery))
	f.version = payload.Version
	// Rebuild nameIndex from placements. Snapshots don't carry the index
	// (older snapshots predate it), and rebuilding keeps the FSM the single
	// source of truth even after a cold restart.
	f.nameIndex = make(map[string]string, len(payload.Placements))
	f.shardIndex = make(map[int]map[string]struct{})
	f.placementIDs = newPlacementIDIndex()
	f.ownerRefIndex = make(map[string]*btree.BTreeG[string])
	f.hostPortIndex = make(map[int]hostPortClaim)
	f.ownerIndex = make(map[string]map[string]struct{})
	f.pendingReservationClaims = make(map[string]pendingReservationClaim)
	f.pendingReservationCapacity = make(map[string]capacity.Request)
	f.pendingReservationIDsByOwner = make(map[string]map[string]struct{})
	f.pendingReservationExpiries = nil
	f.reservedIndex = make(map[string]struct{})
	f.customHostnameIndex = make(map[string]string)
	f.auditACLs = make(map[string]AuditACL, len(payload.AuditACLs))
	for id, acl := range payload.AuditACLs {
		if id != "" {
			f.auditACLs[id] = cloneAuditACL(acl)
		}
	}
	// Rebuild the replicated volume table + name index from the snapshot.
	f.volumes = make(map[string]models.Volume, len(payload.Volumes))
	f.volumeNameIndex = make(map[string]string, len(payload.Volumes))
	f.volumeAttachments = make(map[string]models.VolumeAttachment, len(payload.VolumeAttachments))
	f.volumeAttachmentsByVolume = make(map[string]map[string]struct{})
	f.volumeAttachmentsBySandbox = make(map[string]map[string]struct{})
	for _, v := range payload.Volumes {
		tenant := strings.TrimSpace(v.Tenant)
		id := strings.TrimSpace(v.ID)
		if tenant == "" || id == "" {
			continue
		}
		f.volumes[volumeKey(tenant, id)] = v
		if name := strings.TrimSpace(v.Name); name != "" {
			f.volumeNameIndex[volumeNameKey(tenant, name)] = id
		}
	}
	for _, a := range payload.VolumeAttachments {
		a.Tenant = strings.TrimSpace(a.Tenant)
		a.VolumeID = strings.TrimSpace(a.VolumeID)
		a.SandboxID = strings.TrimSpace(a.SandboxID)
		a.Target = strings.TrimSpace(a.Target)
		a.Source = strings.TrimSpace(a.Source)
		if a.Tenant == "" || a.VolumeID == "" || a.SandboxID == "" || a.Target == "" || a.Source == "" {
			continue
		}
		if _, ok := f.volumes[volumeKey(a.Tenant, a.VolumeID)]; !ok {
			continue
		}
		f.putVolumeAttachmentLocked(a)
	}
	for id, p := range payload.Placements {
		full := p
		if full.SandboxID == "" {
			full.SandboxID = id
		}
		_, legacyRec := splitPlacement(p)
		rec := legacyRec
		if payload.Recovery != nil {
			if payloadRec, ok := payload.Recovery[id]; ok {
				rec = payloadRec
			}
		}
		if !rec.empty() {
			full.Spec = rec.Spec
			full.SecretRef = rec.SecretRef
			full.SecretVersion = rec.SecretVersion
		}
		if err := f.storePlacementLocked(id, full); err != nil {
			return err
		}
		indexed, _ := f.fullPlacementLocked(id)
		if name := placementName(indexed); name != "" {
			f.nameIndex[name] = id
		}
		f.claimShardLocked(id)
		f.claimOwnerRefLocked(id, indexed.OwnerRef)
		for port, route := range exposedPortRoutesForPlacement(indexed) {
			f.claimHostPortLocked(id, port, route)
		}
		for _, h := range indexed.CustomHostnames {
			f.claimCustomHostnameLocked(id, h)
		}
		if indexed.IsReserved() {
			f.claimPendingReservationLocked(id, indexed)
		} else {
			f.claimOwnerLocked(id, indexed)
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
	version           uint64
	rows              []placementSnapshotRow
	drainedNodes      map[string]bool
	auditACLs         map[string]AuditACL
	volumes           []models.Volume
	volumeAttachments []models.VolumeAttachment
	recoveryStore     placementRecoveryStore
	recoveryRefs      []string
}

func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) (err error) {
	start := time.Now()
	counting := &countingSnapshotSink{SnapshotSink: sink}
	defer func() {
		recordSnapshotPersist(time.Since(start), counting.bytes, len(s.rows), err)
	}()
	enc := gob.NewEncoder(counting)
	if err := enc.Encode(fsmSnapshotPayload{
		Version:           s.version,
		Rows:              s.rows,
		DrainedNodes:      s.drainedNodes,
		AuditACLs:         s.auditACLs,
		Volumes:           s.volumes,
		VolumeAttachments: s.volumeAttachments,
	}); err != nil {
		_ = sink.Cancel()
		return fmt.Errorf("fsmSnapshot: encode: %w", err)
	}
	if err := sink.Close(); err != nil {
		return err
	}
	if s.recoveryStore != nil {
		_ = s.recoveryStore.RetainSnapshotRefs(s.recoveryRefs)
	}
	return nil
}

func (s *fsmSnapshot) Release() {}

type countingSnapshotSink struct {
	raft.SnapshotSink
	bytes int64
}

func (s *countingSnapshotSink) Write(p []byte) (int, error) {
	n, err := s.SnapshotSink.Write(p)
	s.bytes += int64(n)
	return n, err
}

func cloneHotPlacement(p Placement) Placement {
	p.Spec = nil
	p.SecretRef = ""
	p.SecretVersion = 0
	if len(p.SecretRecipients) > 0 {
		p.SecretRecipients = append([]string(nil), p.SecretRecipients...)
	}
	if len(p.AuditNodeIDs) > 0 {
		p.AuditNodeIDs = append([]string(nil), p.AuditNodeIDs...)
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
	if len(p.CustomHostnames) > 0 {
		p.CustomHostnames = append([]string(nil), p.CustomHostnames...)
	}
	return p
}

func clonePlacementRecovery(r placementRecovery) placementRecovery {
	r.Spec = cloneCreateSandboxRequest(r.Spec)
	return r
}

func clonePlacement(p Placement) Placement {
	p.Spec = cloneCreateSandboxRequest(p.Spec)
	if len(p.SecretRecipients) > 0 {
		p.SecretRecipients = append([]string(nil), p.SecretRecipients...)
	}
	if len(p.AuditNodeIDs) > 0 {
		p.AuditNodeIDs = append([]string(nil), p.AuditNodeIDs...)
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
	if len(p.CustomHostnames) > 0 {
		p.CustomHostnames = append([]string(nil), p.CustomHostnames...)
	}
	return p
}

func cloneAuditACL(acl AuditACL) AuditACL {
	if len(acl.AuditNodeIDs) > 0 {
		acl.AuditNodeIDs = append([]string(nil), acl.AuditNodeIDs...)
	}
	return acl
}

// recordPlacementAuditNode retains a bounded, insertion-ordered owner history.
// Once the bound is exceeded, AuditNodesTruncated stays sticky. Readers then
// fail with explicit incomplete-coverage status instead of performing an
// unbounded fleet scan or silently omitting evidence.
func recordPlacementAuditNode(p *Placement, nodeID string) {
	if p == nil {
		return
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return
	}
	for _, existing := range p.AuditNodeIDs {
		if existing == nodeID {
			return
		}
	}
	if len(p.AuditNodeIDs) >= maxPlacementAuditNodes {
		p.AuditNodesTruncated = true
		return
	}
	p.AuditNodeIDs = append(p.AuditNodeIDs, nodeID)
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
	if len(in.PlatformVolumes) > 0 {
		out.PlatformVolumes = append([]models.PlatformVolumeMount(nil), in.PlatformVolumes...)
	}
	if in.Registry != nil {
		registry := *in.Registry
		out.Registry = &registry
	}
	if in.Lifecycle != nil {
		lifecycle := *in.Lifecycle
		out.Lifecycle = &lifecycle
	}
	if in.Failover != nil {
		failover := *in.Failover
		out.Failover = &failover
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

package cluster

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// Operation codes for raft log entries.
type opCode uint8

const (
	opPlace             opCode = 1
	opDelete            opCode = 2
	opReassign          opCode = 3
	opUpsertSpec        opCode = 4 // overwrite Placement.Spec without touching ownership
	opAddExposedPort    opCode = 5 // record one (port, protocol) intent
	opRemoveExposedPort opCode = 6 // drop one port intent
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

	// subMu guards subscribers. Separate from mu so a slow subscriber accept
	// can't block FSM reads — Apply takes mu briefly to write, releases it,
	// then takes subMu to fan out.
	subMu       sync.Mutex
	subscribers []chan<- struct{}
}

func newPlacementFSM() *placementFSM {
	return &placementFSM{
		placements: make(map[string]Placement),
		nameIndex:  make(map[string]string),
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
	f.version++
	now := time.Now().Unix()

	switch cmd.Op {
	case opPlace:
		// Idempotency: re-placing the same id with the same owner AND the same
		// spec payload is a no-op. If the spec changed, we still want the new
		// spec to land — opPlace is the atomic "owner + spec" write used by
		// CreateSandbox, so an idempotent retry that omits the spec must not
		// erase a previously-recorded spec.
		existing, exists := f.placements[cmd.SandboxID]
		if exists && existing.OwnerNodeID == cmd.OwnerNodeID && cmd.Spec == nil && cmd.SealedSecrets == nil {
			return nil
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
		}
		f.claimNameLocked(cmd.SandboxID, specName(spec))
		return nil
	case opDelete:
		if existing, ok := f.placements[cmd.SandboxID]; ok {
			f.releaseNameLocked(cmd.SandboxID, specName(existing.Spec))
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
		existing.OwnerNodeID = cmd.OwnerNodeID
		existing.OwnerAPIURL = cmd.OwnerAPIURL
		existing.OwnerDataPlaneHost = cmd.OwnerDataPlaneHost
		existing.Version = f.version
		existing.UpdatedUnix = now
		f.placements[cmd.SandboxID] = existing
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
		existing.Version = f.version
		existing.UpdatedUnix = now
		f.placements[cmd.SandboxID] = existing
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
		existing.ExposedPorts[cmd.Port] = route.Protocol
		existing.ExposedPortRoutes[cmd.Port] = route
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

func (f *placementFSM) validateHostPortAvailableLocked(sandboxID string, port int, route ExposedPortRoute) error {
	if route.Protocol != models.ExposedPortProtocolTCP || route.HostPort <= 0 {
		return nil
	}
	for otherSandboxID, placement := range f.placements {
		for otherPort, otherRoute := range exposedPortRoutesForPlacement(placement) {
			if otherSandboxID == sandboxID && otherPort == port {
				continue
			}
			if otherRoute.Protocol == models.ExposedPortProtocolTCP && otherRoute.HostPort == route.HostPort {
				return fmt.Errorf("%w: %d reserved by %s:%d", ErrHostPortReserved, route.HostPort, otherSandboxID, otherPort)
			}
		}
	}
	return nil
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

// idsOwnedBy returns the sandbox IDs whose current owner is nodeID. Used by
// the dead-owner reconciler to enumerate orphan candidates.
func (f *placementFSM) idsOwnedBy(nodeID string) []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var out []string
	for id, p := range f.placements {
		if p.OwnerNodeID == nodeID {
			out = append(out, id)
		}
	}
	return out
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

// Snapshot returns a raft.FSMSnapshot capturing current placement state.
func (f *placementFSM) Snapshot() (raft.FSMSnapshot, error) {
	return &fsmSnapshot{placements: f.snapshot()}, nil
}

// Restore loads state from a previously written snapshot. Replaces in-memory
// placements wholesale — raft only calls Restore on a cold start or follower
// resync.
func (f *placementFSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	dec := gob.NewDecoder(rc)
	var loaded map[string]Placement
	if err := dec.Decode(&loaded); err != nil {
		return fmt.Errorf("placementFSM: restore: %w", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if loaded == nil {
		loaded = make(map[string]Placement)
	}
	f.placements = loaded
	// Rebuild nameIndex from placements. Snapshots don't carry the index
	// (older snapshots predate it), and rebuilding keeps the FSM the single
	// source of truth even after a cold restart.
	f.nameIndex = make(map[string]string, len(loaded))
	for id, p := range loaded {
		if name := specName(p.Spec); name != "" {
			f.nameIndex[name] = id
		}
	}
	return nil
}

type fsmSnapshot struct {
	placements map[string]Placement
}

func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	enc := gob.NewEncoder(sink)
	if err := enc.Encode(s.placements); err != nil {
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

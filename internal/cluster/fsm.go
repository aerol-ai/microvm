package cluster

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// Operation codes for raft log entries.
type opCode uint8

const (
	opPlace            opCode = 1
	opDelete           opCode = 2
	opReassign         opCode = 3
	opUpsertSpec       opCode = 4 // overwrite Placement.Spec without touching ownership
	opAddExposedPort   opCode = 5 // record one (port, protocol) intent
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
	Op            opCode                       `json:"op"`
	SandboxID     string                       `json:"sandbox_id"`
	OwnerNodeID   string                       `json:"owner_node_id,omitempty"`
	OwnerAPIURL   string                       `json:"owner_api_url,omitempty"`
	Spec          *models.CreateSandboxRequest `json:"spec,omitempty"`
	SealedSecrets []byte                       `json:"sealed_secrets,omitempty"`
	Port          int                          `json:"port,omitempty"`
	Protocol      string                       `json:"protocol,omitempty"`
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
}

func newPlacementFSM() *placementFSM {
	return &placementFSM{placements: make(map[string]Placement)}
}

// Apply is invoked by raft for every committed log entry on every node.
func (f *placementFSM) Apply(log *raft.Log) interface{} {
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
		if exists {
			// Same preservation rule as Spec: opPlace is the "owner + spec"
			// write and must not erase the port intents accumulated by
			// opAddExposedPort calls between creates.
			ports = existing.ExposedPorts
		}
		f.placements[cmd.SandboxID] = Placement{
			SandboxID:     cmd.SandboxID,
			OwnerNodeID:   cmd.OwnerNodeID,
			OwnerAPIURL:   cmd.OwnerAPIURL,
			Version:       f.version,
			CreatedUnix:   created,
			UpdatedUnix:   now,
			Spec:          spec,
			SealedSecrets: sealed,
			ExposedPorts:  ports,
		}
		return nil
	case opDelete:
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
		if existing.ExposedPorts == nil {
			existing.ExposedPorts = make(map[int]string)
		}
		// Same-protocol re-add is a no-op; protocol upgrade overwrites (the
		// service layer rejects mid-flight protocol changes via the
		// "unexpose first" guard, so this branch only fires on legitimate
		// updates that already succeeded locally).
		if existing.ExposedPorts[cmd.Port] == cmd.Protocol {
			return nil
		}
		existing.ExposedPorts[cmd.Port] = cmd.Protocol
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
		existing.Version = f.version
		existing.UpdatedUnix = now
		f.placements[cmd.SandboxID] = existing
		return nil
	default:
		return fmt.Errorf("placementFSM: unknown op %d", cmd.Op)
	}
}

// get returns the placement for id, or zero-value + false if absent.
func (f *placementFSM) get(id string) (Placement, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	p, ok := f.placements[id]
	return p, ok
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

// snapshot copies the placement map for use by Snapshot().
func (f *placementFSM) snapshot() map[string]Placement {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[string]Placement, len(f.placements))
	for k, v := range f.placements {
		out[k] = v
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

package cluster

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// Operation codes for raft log entries.
type opCode uint8

const (
	opPlace    opCode = 1
	opDelete   opCode = 2
	opReassign opCode = 3
)

// command is the wire format for one raft log entry.
type command struct {
	Op          opCode `json:"op"`
	SandboxID   string `json:"sandbox_id"`
	OwnerNodeID string `json:"owner_node_id,omitempty"`
	OwnerAPIURL string `json:"owner_api_url,omitempty"`
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
		// Idempotency: re-placing the same id with the same owner is a no-op.
		// Re-placing with a different owner overwrites — this is intentional;
		// it lets opReassign be expressed via opPlace too.
		existing, exists := f.placements[cmd.SandboxID]
		if exists && existing.OwnerNodeID == cmd.OwnerNodeID {
			return nil
		}
		created := now
		if exists {
			created = existing.CreatedUnix
		}
		f.placements[cmd.SandboxID] = Placement{
			SandboxID:   cmd.SandboxID,
			OwnerNodeID: cmd.OwnerNodeID,
			OwnerAPIURL: cmd.OwnerAPIURL,
			Version:     f.version,
			CreatedUnix: created,
			UpdatedUnix: now,
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

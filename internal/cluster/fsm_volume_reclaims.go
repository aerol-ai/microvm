package cluster

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The replicated reclaim ledger for delete_with_sandbox volumes
// (plans/agent-sandbox-feature-parity.md V1; review 2 finding 7).
//
// A delete_with_sandbox volume goes, row and bytes, with the last sandbox
// attached to it. In a cluster the attachment index lives in this FSM, and
// the opDelete that removes a placement also drops that sandbox's
// attachments. Once it has, nothing links the volume to any sandbox. The
// destroying worker also writes its own SQLite ledger, but a ledger on one
// worker dies with that worker, and the leader's expiry of an abandoned
// deleting placement (dead_owner.go) has no ledger at all.
//
// So opDelete itself records the obligation, in the same apply that drops
// the last attachment (and opDeleteVolume, asked the same way, records it
// for the volume row it deletes: an API delete or a failed create's cleanup,
// on whichever node took the request): for every delete_with_sandbox volume the deleted
// sandbox was the only holder of, a VolumeReclaim entry. It is replicated
// and snapshotted with the volumes, so it survives the loss of any node and
// any leader change. It is removed only by opAckVolumeReclaim, which a node
// sends after the backend bytes are deleted (or a recreated volume was found
// to own them). Each entry names the node that drains it: the node that
// proposed the delete. A worker's volume-reclaim sweep reads the entries it
// owns, plus the ones whose node is gone or never drains (a server-role
// leader, a dead worker); it takes such an entry over with
// opClaimVolumeReclaim (a compare-and-set on the current node), so one node,
// not the whole fleet, retries it.
//
// Rolling upgrade: an older build ignores the opDelete fields that ask for
// the record and fails the two new ops. A proposer asks for the record only
// when every Raft server (Cluster) or every live member (Agent) runs
// volumeReclaimFSMOpsVersion, so every replica applies the same entry. Until
// then a destroy keeps today's behaviour: the destroying worker's own ledger.

const (
	opAckVolumeReclaim   opCode = 40 // drop one entry once its bytes are deleted
	opClaimVolumeReclaim opCode = 41 // move one entry to another node (compare-and-set)
)

// volumeReclaimFSMOpsVersion: opDelete records delete_with_sandbox volume
// reclaims, and opAckVolumeReclaim / opClaimVolumeReclaim exist.
const volumeReclaimFSMOpsVersion = 10

// ErrVolumeReclaimMoved is a claim of an entry that is gone or no longer
// held by the node the claimer saw: another node took it, or it was acked.
var ErrVolumeReclaimMoved = errors.New("cluster: volume reclaim was acked or taken by another node")

// VolumeReclaim is one delete_with_sandbox volume whose last attachment a
// placement delete released: its bytes (and its row, if still there) are
// owed a delete. Times come from the proposer, never the applier's clock.
type VolumeReclaim struct {
	Tenant   string `json:"tenant"`
	VolumeID string `json:"volume_id"`
	Name     string `json:"name,omitempty"`
	Backend  string `json:"backend"`
	Source   string `json:"source"`
	// SandboxID is the destroyed sandbox whose release made it owed.
	SandboxID string `json:"sandbox_id,omitempty"`
	// NodeID is the node whose volume-reclaim sweep drains it.
	NodeID string `json:"node_id"`
	// RecordedUnixNano versions the entry: an ack or claim names it, so a
	// late ack of an older release never drops a newer one.
	RecordedUnixNano int64 `json:"recorded_unix_nano"`
}

func (r VolumeReclaim) key() string { return volumeKey(r.Tenant, r.VolumeID) }

// putVolumeReclaimLocked stores r and keeps the by-node index in step.
func (f *placementFSM) putVolumeReclaimLocked(r VolumeReclaim) {
	if f.volumeReclaims == nil {
		f.volumeReclaims = make(map[string]VolumeReclaim)
	}
	if f.volumeReclaimsByNode == nil {
		f.volumeReclaimsByNode = make(map[string]map[string]struct{})
	}
	key := r.key()
	f.deleteVolumeReclaimLocked(key)
	f.volumeReclaims[key] = r
	if f.volumeReclaimsByNode[r.NodeID] == nil {
		f.volumeReclaimsByNode[r.NodeID] = make(map[string]struct{})
	}
	f.volumeReclaimsByNode[r.NodeID][key] = struct{}{}
}

func (f *placementFSM) deleteVolumeReclaimLocked(key string) {
	old, ok := f.volumeReclaims[key]
	if !ok {
		return
	}
	delete(f.volumeReclaims, key)
	if keys := f.volumeReclaimsByNode[old.NodeID]; keys != nil {
		delete(keys, key)
		if len(keys) == 0 {
			delete(f.volumeReclaimsByNode, old.NodeID)
		}
	}
}

// recordVolumeReclaimsLocked records a VolumeReclaim for every
// delete_with_sandbox volume sandboxID is the only holder of. opDelete calls
// it just before it releases the sandbox's attachments, when the command
// asks for it.
func (f *placementFSM) recordVolumeReclaimsLocked(sandboxID, nodeID string, stamp int64) {
	sandboxID = strings.TrimSpace(sandboxID)
	nodeID = strings.TrimSpace(nodeID)
	if sandboxID == "" || nodeID == "" {
		return
	}
	// Map order does not matter: each volume's entry depends only on state.
	for key := range f.volumeAttachmentsBySandbox[sandboxID] {
		a, ok := f.volumeAttachments[key]
		if !ok {
			continue
		}
		vKey := volumeKey(a.Tenant, a.VolumeID)
		vol, ok := f.volumes[vKey]
		if !ok || !vol.DeleteWithSandbox || strings.TrimSpace(vol.Source) == "" {
			continue
		}
		if f.volumeHeldByAnotherSandboxLocked(vKey, sandboxID) {
			// The other holder's own delete records it.
			continue
		}
		f.putVolumeReclaimLocked(VolumeReclaim{
			Tenant: vol.Tenant, VolumeID: vol.ID, Name: vol.Name, Backend: vol.Backend, Source: vol.Source,
			SandboxID: sandboxID, NodeID: nodeID, RecordedUnixNano: stamp,
		})
	}
}

// recordDeletedVolumeReclaimLocked records the reclaim of a volume whose
// row opDeleteVolume just removed (an API delete, a failed create's cleanup,
// a destroy's delete_with_sandbox finish), so its bytes are drained like a
// destroy's, by a worker, whichever node took the request. It replaces an
// entry a destroy recorded for the same volume.
func (f *placementFSM) recordDeletedVolumeReclaimLocked(row models.Volume, cmd command) {
	source := strings.TrimSpace(row.Source)
	if source == "" {
		source = strings.TrimSpace(cmd.VolumeReclaimSource)
	}
	node := strings.TrimSpace(cmd.VolumeReclaimNodeID)
	if source == "" || node == "" {
		return
	}
	f.putVolumeReclaimLocked(VolumeReclaim{
		Tenant: strings.TrimSpace(row.Tenant), VolumeID: strings.TrimSpace(row.ID), Name: row.Name, Backend: row.Backend, Source: source,
		NodeID: node, RecordedUnixNano: cmd.StampUnixNano,
	})
}

func (f *placementFSM) volumeHeldByAnotherSandboxLocked(vKey, sandboxID string) bool {
	for key := range f.volumeAttachmentsByVolume[vKey] {
		if a, ok := f.volumeAttachments[key]; ok && a.SandboxID != sandboxID {
			return true
		}
	}
	return false
}

func volumeReclaimFromCommand(cmd command, op string) (VolumeReclaim, error) {
	if cmd.VolumeReclaim == nil {
		return VolumeReclaim{}, fmt.Errorf("placementFSM: %s requires a volume reclaim", op)
	}
	r := *cmd.VolumeReclaim
	r.Tenant, r.VolumeID, r.NodeID = strings.TrimSpace(r.Tenant), strings.TrimSpace(r.VolumeID), strings.TrimSpace(r.NodeID)
	if r.Tenant == "" || r.VolumeID == "" {
		return VolumeReclaim{}, fmt.Errorf("placementFSM: %s requires tenant and volume id", op)
	}
	return r, nil
}

// applyAckVolumeReclaimLocked drops the entry the ack names. An ack of a
// missing entry, or of an older version than the one held, changes nothing,
// so retries and late acks are safe.
func (f *placementFSM) applyAckVolumeReclaimLocked(cmd command) error {
	r, err := volumeReclaimFromCommand(cmd, "opAckVolumeReclaim")
	if err != nil {
		return err
	}
	cur, ok := f.volumeReclaims[r.key()]
	if !ok || cur.RecordedUnixNano != r.RecordedUnixNano {
		return nil
	}
	f.deleteVolumeReclaimLocked(r.key())
	return nil
}

// applyClaimVolumeReclaimLocked moves an entry to cmd.NodeID if it is still
// the version the claimer read, held by the node the claimer read.
func (f *placementFSM) applyClaimVolumeReclaimLocked(cmd command) error {
	r, err := volumeReclaimFromCommand(cmd, "opClaimVolumeReclaim")
	if err != nil {
		return err
	}
	to := strings.TrimSpace(cmd.NodeID)
	if to == "" {
		return fmt.Errorf("placementFSM: opClaimVolumeReclaim requires node_id")
	}
	cur, ok := f.volumeReclaims[r.key()]
	if !ok || cur.RecordedUnixNano != r.RecordedUnixNano || cur.NodeID != r.NodeID {
		return ErrVolumeReclaimMoved
	}
	cur.NodeID = to
	f.putVolumeReclaimLocked(cur)
	return nil
}

// reclaimNodeState reports what membership knows of a node: whether it is
// known and alive, and whether its role runs the reclaim sweep (it can own
// sandboxes).
type reclaimNodeState func(nodeID string) (alive, drains bool)

// volumeReclaimsFor returns up to limit entries nodeID should drain: its
// own first, then the ones it may take over, each group oldest first. An
// entry may be taken over from a live node that never drains (the leader
// that expired an abandoned delete) at once, and from a node that is dead or
// unknown once it is volumeReclaimAdoptAfter old. A live draining node's
// entries are skipped by node, so a poll costs O(own entries + nodes that
// hold entries), not O(every entry), however large a backlog grows.
func (f *placementFSM) volumeReclaimsFor(nodeID string, state reclaimNodeState, now time.Time, limit int) []VolumeReclaim {
	nodeID = strings.TrimSpace(nodeID)
	var own, adopt []VolumeReclaim
	f.mu.RLock()
	for node, keys := range f.volumeReclaimsByNode {
		if node == nodeID {
			for key := range keys {
				own = append(own, f.volumeReclaims[key])
			}
			continue
		}
		if state == nil {
			continue
		}
		alive, drains := state(node)
		if alive && drains {
			continue
		}
		for key := range keys {
			r := f.volumeReclaims[key]
			if alive || now.Sub(time.Unix(0, r.RecordedUnixNano)) >= volumeReclaimAdoptAfter {
				adopt = append(adopt, r)
			}
		}
	}
	f.mu.RUnlock()
	sortVolumeReclaims(own)
	sortVolumeReclaims(adopt)
	out := append(own, adopt...)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// VolumeReclaims returns every entry, oldest first. Never nil.
func (f *placementFSM) VolumeReclaims() []VolumeReclaim {
	f.mu.RLock()
	out := f.volumeReclaimsSnapshotLocked()
	f.mu.RUnlock()
	sortVolumeReclaims(out)
	return out
}

func sortVolumeReclaims(out []VolumeReclaim) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].RecordedUnixNano != out[j].RecordedUnixNano {
			return out[i].RecordedUnixNano < out[j].RecordedUnixNano
		}
		return out[i].key() < out[j].key()
	})
}

func (f *placementFSM) volumeReclaimsSnapshotLocked() []VolumeReclaim {
	out := make([]VolumeReclaim, 0, len(f.volumeReclaims))
	for _, r := range f.volumeReclaims {
		out = append(out, r)
	}
	return out
}

// restoreVolumeReclaimsLocked rebuilds the ledger from a snapshot. An older
// snapshot has none.
func (f *placementFSM) restoreVolumeReclaimsLocked(in []VolumeReclaim) {
	f.volumeReclaims = make(map[string]VolumeReclaim, len(in))
	f.volumeReclaimsByNode = make(map[string]map[string]struct{})
	for _, r := range in {
		r.Tenant, r.VolumeID = strings.TrimSpace(r.Tenant), strings.TrimSpace(r.VolumeID)
		if r.Tenant == "" || r.VolumeID == "" {
			continue
		}
		f.putVolumeReclaimLocked(r)
	}
}

package cluster

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Deny records for deleted nodes (plans/kubectl-style-cluster-ops.md §5).
//
// `aerolvm delete node` on a worker or ingress node writes one, keyed by node
// ID. While it exists that ID gets no placements, every member refuses it as
// an mTLS peer, and gossip refuses it at join (gossip_deny.go). A node cert
// stays valid until it expires and there is no CRL, so without the record a
// deleted node would keep raft-apply and owner-API authority for the rest of
// its cert's life. A later fresh join (with a join token and a new key) is
// what will replace a record; until that lands, a deleted node ID stays
// denied and a machine that comes back needs a new SB_NODE_ID.
//
// Servers hold the records in this FSM. Workers and ingress nodes hold no
// Raft state, so they poll the server tier for the set the way they keep
// their API-token copy (PublicInternalDeniedNodesPath, agent deny mirror).
//
// Rolling upgrade: an older build fails opDenyNode, so the leader proposes it
// only once every Raft server reports nodeDenyFSMOpsVersion
// (raftServersSupport). An older snapshot has no records and restores as
// "none denied"; an older build ignores the field in a newer snapshot, which
// is safe because no record exists until every server runs this build.
const opDenyNode opCode = 42 // record one deleted node ID (idempotent)

// nodeDenyFSMOpsVersion: opDenyNode.
const nodeDenyFSMOpsVersion = 12

// NodeDenyRecord is one deleted node. Times come from the proposer, never the
// applier's clock.
type NodeDenyRecord struct {
	NodeID string `json:"node_id"`
	// Role is the node's gossiped role when it was deleted, for operators.
	Role           string `json:"role,omitempty"`
	DeniedUnixNano int64  `json:"denied_unix_nano"`
}

// nodeDenyApplyResult is the leader FSM's answer to opDenyNode. Changed is
// false when the node was already denied, so a retried delete reports what
// it found instead of writing again.
type nodeDenyApplyResult struct {
	Record  NodeDenyRecord
	Changed bool
}

func (f *placementFSM) applyDenyNodeLocked(cmd command, index uint64) (any, error) {
	in := cmd.NodeDeny
	if in == nil || strings.TrimSpace(in.NodeID) == "" {
		return nil, fmt.Errorf("placementFSM: opDenyNode requires a node id")
	}
	id := strings.TrimSpace(in.NodeID)
	if old, ok := f.deniedNodes[id]; ok {
		return nodeDenyApplyResult{Record: old}, nil
	}
	if f.deniedNodes == nil {
		f.deniedNodes = make(map[string]NodeDenyRecord)
	}
	rec := NodeDenyRecord{NodeID: id, Role: strings.TrimSpace(in.Role), DeniedUnixNano: cmd.StampUnixNano}
	f.deniedNodes[id] = rec
	// The node's admitted key (fsm_join.go) becomes a tombstone, so its old
	// cert stays refused even after a fresh join reuses the ID. An older
	// build skips this, but no admitted record can exist until every server
	// runs a build with joinFSMOpsVersion, so on any log an older build can
	// apply the two agree.
	f.tombstoneAdmittedLocked(id, cmd.StampUnixNano)
	f.deniedNodesVersion = index
	f.publishDeniedLocked()
	return nodeDenyApplyResult{Record: rec, Changed: true}, nil
}

// publishDeniedLocked swaps in a fresh copy of the deny set for the
// lock-free readers. Caller holds f.mu. Copy-on-write is cheap: the set
// changes only when an operator deletes a node.
func (f *placementFSM) publishDeniedLocked() {
	set := make(map[string]bool, len(f.deniedNodes))
	for id := range f.deniedNodes {
		set[id] = true
	}
	f.deniedSet.Store(&set)
}

// isNodeDenied is the hot check, asked by the peer authorizer on every
// internal request and by gossip on every alive message, which memberlist
// delivers with its own node lock held. So it never takes f.mu: a reader
// there would wait behind a long Snapshot and stall gossip with it.
func (f *placementFSM) isNodeDenied(nodeID string) bool {
	if f == nil || nodeID == "" {
		return false
	}
	set := f.deniedSet.Load()
	return set != nil && (*set)[nodeID]
}

// deniedNodesView returns every record, sorted by node ID, and the Raft index
// of the last change to them (the cursor agents poll with).
func (f *placementFSM) deniedNodesView() ([]NodeDenyRecord, uint64) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.deniedNodesSnapshotLocked(), f.deniedNodesVersion
}

func (f *placementFSM) deniedNodesSnapshotLocked() []NodeDenyRecord {
	out := make([]NodeDenyRecord, 0, len(f.deniedNodes))
	for _, rec := range f.deniedNodes {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// restoreDeniedNodesLocked loads the snapshot's records. The version becomes
// the snapshot's index: no change to the set is newer than that, and an agent
// that sees it move only refetches a set it may already hold. haveRevoked
// says the snapshot carries key tombstones, which agents mirror with the set.
func (f *placementFSM) restoreDeniedNodesLocked(records []NodeDenyRecord, version uint64, haveRevoked bool) {
	f.deniedNodes = make(map[string]NodeDenyRecord, len(records))
	for _, r := range records {
		if id := strings.TrimSpace(r.NodeID); id != "" {
			r.NodeID = id
			f.deniedNodes[id] = r
		}
	}
	f.deniedNodesVersion = 0
	if len(f.deniedNodes) > 0 || haveRevoked {
		f.deniedNodesVersion = version
	}
	f.publishDeniedLocked()
}

// DeniedNodesResponse answers PublicInternalDeniedNodesPath: the whole set
// and its version. The set is the deleted nodes of the cluster's life, so a
// full copy per change stays small. RevokedKeys are the cert-key tombstones
// (fsm_join.go): a worker refuses them on its internal listener, so a
// deleted node's old cert is refused there too after its ID is reused. An
// older server omits the field, which reads as "none".
type DeniedNodesResponse struct {
	Nodes       []NodeDenyRecord `json:"nodes"`
	RevokedKeys []RevokedKey     `json:"revoked_keys,omitempty"`
	Version     uint64           `json:"version"`
}

// PublicInternalDeniedNodesPath serves the deny set to nodes that hold no
// Raft state. GET ?since=N answers 304 while the set is no newer than N.
const PublicInternalDeniedNodesPath = "/v1/cluster/internal/denied-nodes"

// DeniedNodes serves an agent's poll from this server's FSM. changed is false
// when the agent's cursor is at least this server's version: the handler
// answers 304. A server that lags another never hands back an older set as
// news, and the agent keeps only a newer version anyway.
func (c *Cluster) DeniedNodes(since uint64) (DeniedNodesResponse, bool) {
	if c == nil || c.fsm == nil {
		return DeniedNodesResponse{Nodes: []NodeDenyRecord{}}, false
	}
	nodes, version := c.fsm.deniedNodesView()
	if since >= version {
		return DeniedNodesResponse{}, false
	}
	return DeniedNodesResponse{Nodes: nodes, RevokedKeys: c.fsm.revokedKeysView(), Version: version}, true
}

// revokedKeysView returns the tombstones, sorted by key hash.
func (f *placementFSM) revokedKeysView() []RevokedKey {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.revokedSnapshotLocked()
}

// IsNodeDenied reports whether nodeID was deleted, from the local FSM.
func (c *Cluster) IsNodeDenied(nodeID string) bool {
	if c == nil || c.fsm == nil {
		return false
	}
	return c.fsm.isNodeDenied(strings.TrimSpace(nodeID))
}

// writeNodeDeny proposes opDenyNode on the leader. The upgrade gate runs
// first: a cluster with any server below nodeDenyFSMOpsVersion answers
// ErrClusterVersion and the log never carries an op a replica would skip.
// Idempotent: denying a denied node changes nothing and reports Changed
// false.
func (c *Cluster) writeNodeDeny(ctx context.Context, nodeID, role string) (nodeDenyApplyResult, error) {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return nodeDenyApplyResult{}, fmt.Errorf("cluster: node holds no placement state")
	}
	// No leadership check of its own: the caller (DeleteNode) checked, and
	// raft refuses an apply on a node that lost it since (ErrNotLeader).
	if err := c.raftServersSupport(nodeDenyFSMOpsVersion, "node delete"); err != nil {
		return nodeDenyApplyResult{}, err
	}
	payload, err := encodeCommand(command{
		Op:            opDenyNode,
		StampUnixNano: time.Now().UnixNano(),
		NodeDeny:      &NodeDenyRecord{NodeID: nodeID, Role: role},
	})
	if err != nil {
		return nodeDenyApplyResult{}, fmt.Errorf("cluster: encode command: %w", err)
	}
	result, err := c.applyEncodedLocalResult(ctx, payload)
	if err != nil {
		return nodeDenyApplyResult{}, err
	}
	applied, _ := result.(nodeDenyApplyResult)
	return applied, nil
}

// errDenyNodeNotForwardable refuses opDenyNode on the generic leader-forward
// apply path (ApplyEncoded).
var errDenyNodeNotForwardable = errors.New("cluster: a node deny record is written only by the leader's node-delete path")

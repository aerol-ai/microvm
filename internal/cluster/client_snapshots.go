package cluster

import (
	"context"
	"fmt"
	"strings"
)

// SnapshotHomeKey is the key under which a snapshot's home node is recorded in
// the cluster index. It folds in the owning tenant so one tenant registering a
// same-named snapshot on another node cannot overwrite another tenant's entry
// and hijack its routing (cross-tenant #11). An empty owner (operator/legacy
// snapshots) uses the bare name, so existing entries and operator snapshots are
// unchanged. The index stores it as an opaque string, so the FSM is untouched.
func SnapshotHomeKey(owner, name string) string {
	owner = strings.TrimSpace(owner)
	name = strings.TrimSpace(name)
	if owner == "" {
		return name
	}
	return owner + "\x00" + name
}

// Snapshot-home routing on the raft-voter Cluster. Writes go through the ordered
// log (applyCommand handles leader-forward); the read comes from the local
// replicated FSM, so any server node can route a snapshot-by-id request after
// the snapshot's node or the request's entry node changes.

// RegisterSnapshotNode records that nodeID holds the named snapshot's image.
// Idempotent and move-safe: re-registering a name overwrites the node.
func (c *Cluster) RegisterSnapshotNode(ctx context.Context, snapshotName, nodeID string) error {
	snapshotName = strings.TrimSpace(snapshotName)
	nodeID = strings.TrimSpace(nodeID)
	if snapshotName == "" || nodeID == "" {
		return fmt.Errorf("cluster: RegisterSnapshotNode requires snapshot name and node id")
	}
	return c.applyCommand(ctx, command{Op: opRegisterSnapshotNode, SnapshotName: snapshotName, NodeID: nodeID})
}

// ForgetSnapshotNode drops the named snapshot's home entry (on delete).
func (c *Cluster) ForgetSnapshotNode(ctx context.Context, snapshotName string) error {
	snapshotName = strings.TrimSpace(snapshotName)
	if snapshotName == "" {
		return nil
	}
	return c.applyCommand(ctx, command{Op: opForgetSnapshotNode, SnapshotName: snapshotName})
}

// SnapshotHomeNode resolves the node holding the named snapshot from the local
// replicated FSM. ok=false means no entry (serve locally).
func (c *Cluster) SnapshotHomeNode(_ context.Context, snapshotName string) (string, bool, error) {
	node, ok := c.fsm.snapshotHomeNode(snapshotName)
	return node, ok, nil
}

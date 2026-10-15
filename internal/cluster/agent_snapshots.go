package cluster

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// Agent-role nodes have no local FSM replica. Snapshot-home writes forward to a
// server peer via applyCommand (the generic raft apply channel); the read
// forwards to the internal snapshot-node endpoint, which a server answers from
// its replicated FSM. Mirrors agent_volumes.go.

// SnapshotNodeQueryResponse is the wire shape of the internal snapshot-node read.
type SnapshotNodeQueryResponse struct {
	NodeID string `json:"node_id,omitempty"`
	Found  bool   `json:"found,omitempty"`
}

func (a *Agent) RegisterSnapshotNode(ctx context.Context, snapshotName, nodeID string) error {
	snapshotName = strings.TrimSpace(snapshotName)
	nodeID = strings.TrimSpace(nodeID)
	if snapshotName == "" || nodeID == "" {
		return fmt.Errorf("cluster agent: RegisterSnapshotNode requires snapshot name and node id")
	}
	return a.applyCommand(ctx, command{Op: opRegisterSnapshotNode, SnapshotName: snapshotName, NodeID: nodeID})
}

func (a *Agent) ForgetSnapshotNode(ctx context.Context, snapshotName string) error {
	snapshotName = strings.TrimSpace(snapshotName)
	if snapshotName == "" {
		return nil
	}
	return a.applyCommand(ctx, command{Op: opForgetSnapshotNode, SnapshotName: snapshotName})
}

func (a *Agent) SnapshotHomeNode(ctx context.Context, snapshotName string) (string, bool, error) {
	snapshotName = strings.TrimSpace(snapshotName)
	if snapshotName == "" {
		return "", false, nil
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	path := PublicInternalSnapshotNodePath + "?" + url.Values{"name": {snapshotName}}.Encode()
	var resp SnapshotNodeQueryResponse
	if err := a.doControlPlaneJSON(reqCtx, "GET", path, path, nil, &resp); err != nil {
		// A 404 means "no home entry", which routing treats as serve-locally.
		if isStatus(err, 404) {
			return "", false, nil
		}
		return "", false, err
	}
	return resp.NodeID, resp.Found && resp.NodeID != "", nil
}

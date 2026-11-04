package cluster

import "strings"

// Snapshot-home routing is replicated through the placement FSM so a
// snapshot-by-id GET/DELETE can reach the node that holds the image. A snapshot
// lives in per-node SQLite with no node column, so a request that lands on
// another node cannot answer it locally; this small name → node index is the
// cluster-wide lookup. The apply cases live in fsm.go's switch; the read helper
// lives here, mirroring fsm_volumes.go.

// snapshotHomeNode returns the node holding the named snapshot, or ("", false)
// when no entry is registered (single-node, pre-index snapshots, or a snapshot
// whose node has left the cluster) — in which case the caller serves locally.
func (f *placementFSM) snapshotHomeNode(name string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	node, ok := f.snapshotNodeIndex[strings.TrimSpace(name)]
	return node, ok && node != ""
}

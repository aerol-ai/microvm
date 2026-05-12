// Package cluster implements Phase-1 cluster mode for sandboxd.
//
// Architecture (Phase 1):
//
//   - Membership and capacity dissemination: SWIM gossip via hashicorp/memberlist.
//     Every node periodically advertises a capacity.Snapshot in its memberlist
//     metadata; placement decisions read these advertised snapshots.
//
//   - Placement map: a small Raft FSM (hashicorp/raft) holds exactly one piece
//     of state — sandbox_id -> owner_node_id. Mutations happen on the leader;
//     reads are local on every node from the in-memory FSM.
//
//   - Owner-sharded execution: once a sandbox is placed on node N, all of its
//     state and lifecycle stays on N. The local SQLite store is unchanged.
//     Cross-node API calls (toolbox, sessions, port forwards) are transparently
//     reverse-proxied to the owner via internal/cluster.ForwardHTTP.
//
//   - No central control plane: any node can accept any request. Mutating
//     requests for sandbox X are forwarded to X's owner; CreateSandbox forwards
//     to the placement target chosen by power-of-two-choices.
//
// Single-node mode (cfg.EnableCluster = false) returns a Noop implementation
// from New so that all callsites can be unconditional.
package cluster

import (
	"context"
	"errors"
	"net/http"

	"github.com/aerol-ai/microvm/pkg/capacity"
)

// ErrNotLeader is returned by mutating Cluster operations when this node is not
// the Raft leader. Callers should retry against the leader (which Client
// resolves automatically by following raft leadership).
var ErrNotLeader = errors.New("cluster: not raft leader")

// ErrUnknownSandbox is returned by OwnerOf when no placement record exists for
// the given sandbox ID. Callers should treat this as "owned locally" only when
// they have just-created the sandbox and not yet committed its placement.
var ErrUnknownSandbox = errors.New("cluster: unknown sandbox placement")

// ErrOrphaned is returned by OwnerOf when a placement exists but its owner has
// been auto-evicted (the node died and grace period expired). The sandbox is
// permanently unreachable until an operator recovers it. Phase 2 only marks
// orphans; true re-creation on a new owner is a Phase 2.5 follow-up that
// requires a replicated sandbox-spec store (today specs live only in the dead
// node's local SQLite).
var ErrOrphaned = errors.New("cluster: sandbox owner is dead, placement orphaned")

// Placement is one row of the FSM's placement map.
type Placement struct {
	SandboxID    string `json:"sandbox_id"`
	OwnerNodeID  string `json:"owner_node_id"`
	OwnerAPIURL  string `json:"owner_api_url"`
	Version      uint64 `json:"version"`
	CreatedUnix  int64  `json:"created_unix"`
	UpdatedUnix  int64  `json:"updated_unix"`
}

// Member is a snapshot of a peer's gossiped state.
type Member struct {
	NodeID   string            `json:"node_id"`
	APIURL   string            `json:"api_url"`
	RaftAddr string            `json:"raft_addr,omitempty"`
	Alive    bool              `json:"alive"`
	Capacity capacity.Snapshot `json:"capacity"`
}

// PlacementTarget is returned by SelectPlacement.
type PlacementTarget struct {
	NodeID string
	APIURL string
	IsSelf bool
}

// OwnerInfo is returned by OwnerOf.
type OwnerInfo struct {
	NodeID string
	APIURL string
	IsSelf bool
}

// Client is the surface the rest of the daemon (Service, API handlers)
// interacts with. Both *Cluster and *Noop satisfy it so callsites stay
// unconditional.
type Client interface {
	// SelfNodeID returns this node's stable cluster identifier.
	SelfNodeID() string
	// SelfAPIURL returns this node's externally-reachable API base URL.
	SelfAPIURL() string

	// OwnerOf returns the node currently owning sandboxID, or
	// ErrUnknownSandbox if no placement record exists.
	OwnerOf(sandboxID string) (OwnerInfo, error)

	// SelectPlacement chooses a node to host a new sandbox with the given
	// resource request. In single-node mode it always returns self.
	SelectPlacement(req capacity.Request) (PlacementTarget, error)

	// RecordPlacement commits sandboxID -> self into the FSM. Idempotent —
	// re-recording the same (id, owner) pair is a no-op.
	RecordPlacement(ctx context.Context, sandboxID string) error

	// DeletePlacement removes sandboxID from the FSM. Idempotent.
	DeletePlacement(ctx context.Context, sandboxID string) error

	// AssertOwnership ensures the FSM lists self as owner for every id in
	// localIDs. Used at boot to recover after a restart. Idempotent.
	AssertOwnership(ctx context.Context, localIDs []string) error

	// ForwardHTTP reverse-proxies r to peerAPIURL, copying response back to w.
	// Used by the API layer when OwnerOf != self.
	ForwardHTTP(peerAPIURL string, w http.ResponseWriter, r *http.Request)

	// Members returns a snapshot of all known cluster members.
	Members() []Member

	// Leader returns the node ID of the current Raft leader, empty if none.
	Leader() string

	// Close shuts down the cluster cleanly.
	Close() error
}

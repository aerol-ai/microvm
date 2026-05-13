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
	"github.com/aerol-ai/microvm/pkg/models"
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
// been auto-evicted and the dead-owner reconciler has cleared the pointer
// without yet selecting a new owner. With auto-recreation enabled this is a
// brief transient — the next reconcile tick reassigns the placement to a live
// node and the new owner re-creates the sandbox from the replicated spec.
// Callers should treat this as 410 Gone (the sandbox is currently unreachable
// but the system is converging).
var ErrOrphaned = errors.New("cluster: sandbox owner is dead, placement orphaned")

// Placement is one row of the FSM's placement map. Spec is the replicated
// sandbox creation request used by the new owner to re-materialize a sandbox
// after its previous owner died (see owner_watcher.go). Spec is a pointer so
// older snapshots written before spec replication still decode cleanly.
//
// SealedSecrets carries the encrypted credential bag (registry password,
// per-mount credentials) that was stripped from Spec before replication.
// The cluster never decrypts it — the service layer (which holds the
// pkg/secrets cipher) re-merges credentials into Spec on recreate. The
// payload is sealed by service.SealClusterSecrets / opened by
// service.UnsealClusterSecrets; the schema is the latter's responsibility,
// not the cluster's. Empty when the original create had no credentials.
//
// ExposedPorts is the replicated set of port→protocol intents; the host port
// and public URL are deliberately not replicated because they're allocated
// per-host. The new owner re-runs ExposePort for each entry after recreate so
// caddy/L4 routes get rebuilt with whatever host port the new node picks.
type Placement struct {
	SandboxID     string                       `json:"sandbox_id"`
	OwnerNodeID   string                       `json:"owner_node_id"`
	OwnerAPIURL   string                       `json:"owner_api_url"`
	Version       uint64                       `json:"version"`
	CreatedUnix   int64                        `json:"created_unix"`
	UpdatedUnix   int64                        `json:"updated_unix"`
	Spec          *models.CreateSandboxRequest `json:"spec,omitempty"`
	SealedSecrets []byte                       `json:"sealed_secrets,omitempty"`
	ExposedPorts  map[int]string               `json:"exposed_ports,omitempty"`
}

// Member is a snapshot of a peer's gossiped state.
type Member struct {
	NodeID   string            `json:"node_id"`
	APIURL   string            `json:"api_url"`
	RaftAddr string            `json:"raft_addr,omitempty"`
	Alive    bool              `json:"alive"`
	Capacity capacity.Snapshot `json:"capacity"`
}

// LocalSandboxState is one entry in the boot-time AssertOwnership payload.
// Carrying Spec + ExposedPorts (rather than just an ID) lets the boot replay
// backfill the FSM with everything a future failover-recreate needs — without
// this, sandboxes that pre-date cluster mode (or pre-date the spec/ports
// replication features) would never gain a replicated spec until their next
// mutating call.
//
// Spec MUST be redacted (no plaintext registry password / mount credentials)
// before being handed to AssertOwnership; SealedSecrets carries the encrypted
// bag that the new owner re-merges on recreate. cmd/sandboxd takes care of
// this via service.SealClusterSecrets + RedactClusterSecrets so the cluster
// layer never sees plaintext. SealedSecrets may be empty when the sandbox
// has no secrets to ship.
type LocalSandboxState struct {
	ID            string
	Spec          *models.CreateSandboxRequest
	SealedSecrets []byte
	ExposedPorts  map[int]string
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

// SandboxRecreator is the cluster's escape hatch back into the service layer
// for the failover-recreate path. The owner watcher (see owner_watcher.go)
// invokes RecreateSandbox for any FSM placement that points to self but has
// no corresponding local sandbox — typically because the previous owner died
// and the dead-owner reconciler reassigned the placement here.
//
// exposedPorts carries the replicated port→protocol intents the previous
// owner had recorded; the implementation is expected to re-issue ExposePort
// for each entry after the create succeeds. The host port is not replicated
// because each node allocates from its own pool — the public URL may differ
// after failover for "tcp" exposures (HTTP/TLS-SNI URLs are stable because
// they're derived from id+port+domain).
//
// Implementations MUST be idempotent: the watcher polls and may invoke
// RecreateSandbox multiple times for the same id while a previous attempt is
// still in flight or after an unexpected restart.
//
// sealedSecrets is the opaque encrypted bag that was stripped from the spec
// before replication (see Placement.SealedSecrets). The implementation is
// expected to decrypt and re-merge it back into spec before instantiating
// the container — without this step, recreated sandboxes would lose access
// to the user's private registry / mount credentials. May be empty when
// the original create supplied no credentials.
type SandboxRecreator interface {
	RecreateSandbox(ctx context.Context, id string, spec models.CreateSandboxRequest, sealedSecrets []byte, exposedPorts map[int]string) error
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

	// RecordPlacement commits sandboxID -> self into the FSM along with the
	// (optional) creation spec used to re-materialize the sandbox after a
	// failover. Idempotent — re-recording with the same owner is a no-op, and
	// passing spec=nil preserves any spec that was previously replicated for
	// this id (so a boot-time replay can't erase a richer record written by
	// the original CreateSandbox call).
	//
	// spec MUST be redacted (no plaintext credentials) before being passed in;
	// sealedSecrets is the opaque encrypted credential bag produced by the
	// service layer. Passing sealedSecrets=nil preserves any sealed bag
	// previously replicated for this id (mirrors the spec-preservation rule —
	// a boot-time replay that has the spec but not the secrets can't erase the
	// secrets the original CreateSandbox stored).
	RecordPlacement(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, sealedSecrets []byte) error

	// UpsertSpec replaces the replicated spec for sandboxID without touching
	// ownership. Mutating handlers (resize, lifecycle) call this after a
	// successful local mutation so the FSM stays current — otherwise a
	// failover-recreated sandbox would revert to its create-time shape.
	//
	// spec MUST be redacted. sealedSecrets=nil preserves the previously
	// replicated bag — resize/lifecycle never touch credentials, so passing
	// nil is the right choice for those callers; the "real" secrets are only
	// re-shipped when the user re-runs create or rotates them explicitly.
	UpsertSpec(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, sealedSecrets []byte) error

	// SpecOf returns the most-recently-replicated CreateSandboxRequest for
	// sandboxID, or nil if no spec is recorded (pre-cluster sandbox, or no
	// placement). The returned spec is REDACTED — no plaintext secrets. Use
	// SealedSecretsOf to retrieve the matching sealed bag if you need to
	// reconstruct the full spec for a recreate.
	SpecOf(sandboxID string) *models.CreateSandboxRequest

	// SealedSecretsOf returns the sealed credential bag that was paired with
	// SpecOf's spec when the placement was last written. Empty when the
	// sandbox was created without any private-registry / mount credentials,
	// or when the placement pre-dates the secret-sealing work.
	SealedSecretsOf(sandboxID string) []byte

	// AddExposedPort records intent that sandboxID has port exposed under
	// protocol. Replicated as intent only — the new owner allocates its own
	// host port on recreate. Idempotent (same port+protocol is a no-op).
	AddExposedPort(ctx context.Context, sandboxID string, port int, protocol string) error

	// RemoveExposedPort drops a port intent from the placement. Idempotent.
	RemoveExposedPort(ctx context.Context, sandboxID string, port int) error

	// ExposedPortsOf returns a copy of the replicated port→protocol map for
	// sandboxID, or nil if none. Used by the recreator to replay exposures
	// after a failover.
	ExposedPortsOf(sandboxID string) map[int]string

	// DeletePlacement removes sandboxID from the FSM. Idempotent.
	DeletePlacement(ctx context.Context, sandboxID string) error

	// ApplyEncoded is the receiving end of leader-forwarded raft writes. The
	// internal API endpoint pipes the request body through here on the leader
	// so any owner-side mutating call (Record/Upsert/Add/Remove/Delete) made on
	// a follower can transparently land on the leader's raft. Returns
	// ErrNotLeader if leadership has shifted; the forwarder retries.
	ApplyEncoded(ctx context.Context, payload []byte) error

	// AssertOwnership ensures the FSM lists self as owner for every entry in
	// local, and backfills any missing Spec / ExposedPorts so failover-recreate
	// works for sandboxes that pre-date the spec-replication features. Used at
	// boot. Idempotent.
	AssertOwnership(ctx context.Context, local []LocalSandboxState) error

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

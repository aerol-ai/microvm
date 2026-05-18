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
	"time"

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

// ErrHostPortReserved is returned when the FSM rejects a raw-TCP exposure
// because another placement already owns the requested cluster-wide host port.
// Callers can retry with another candidate instead of surfacing a random
// expose failure to the user.
var ErrHostPortReserved = errors.New("cluster: tcp host port already reserved")

// ErrNameConflict is returned when the placement FSM rejects an opPlace /
// opUpsertSpec because a different sandbox already owns the requested Name.
// Sandbox names are unique cluster-wide; without this check, two concurrent
// creates landing on different owners could each succeed locally and present
// ambiguous name-based lookups to facades like Daytona that resolve sandboxes
// by name. Callers handle this by rolling back the local create and surfacing
// 409 Conflict to the user.
var ErrNameConflict = errors.New("cluster: sandbox name already in use")

// ErrOrphaned is returned by OwnerOf when a placement exists but its owner has
// been auto-evicted and the dead-owner reconciler has cleared the pointer
// without yet selecting a new owner. With auto-recreation enabled this is a
// brief transient — the next reconcile tick reassigns the placement to a live
// node and the new owner re-creates the sandbox from the replicated spec.
// Callers should treat this as 410 Gone (the sandbox is currently unreachable
// but the system is converging).
var ErrOrphaned = errors.New("cluster: sandbox owner is dead, placement orphaned")

// ErrCapacityExceeded is returned when an opReserve apply finds that the
// chosen target no longer has headroom for the request once concurrent
// in-flight reservations are added to its gossiped reserved totals. Routers
// translate this to 503 so the client retries; the next SelectPlacement
// will see the new reservation and pick a different node.
var ErrCapacityExceeded = errors.New("cluster: target capacity exceeded after pending reservations")

// ErrReservationConflict is returned when opReserve tries to reserve a
// sandbox ID that already has a non-expired placement (placed or actively
// reserved by a different owner). Indicates either a router racing a
// completed sandbox or a router with a stale view.
var ErrReservationConflict = errors.New("cluster: sandbox already placed or reserved")

// ErrNoPlacementTarget is returned when no alive worker-capable node can
// accept a new sandbox. This is distinct from "self wins": a pure server or
// ingress node must not silently fall back to local Docker ownership.
var ErrNoPlacementTarget = errors.New("cluster: no worker placement target available")

// PlacementState distinguishes a reservation (capacity held, no docker yet)
// from a placement (sandbox materialized). Empty defaults to Placed so
// pre-reservation snapshots restore correctly: every old row is a real
// placement, never a pending reservation.
type PlacementState string

const (
	PlacementStatePlaced   PlacementState = "" // empty = legacy/placed
	PlacementStateReserved PlacementState = "reserved"
)

// IsReserved reports whether p is a reservation awaiting promotion.
func (p Placement) IsReserved() bool { return p.State == PlacementStateReserved }

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
// ExposedPortRoute is the replicated routing intent for one exposed sandbox
// port. Protocol drives which Caddy surface is used. HostPort is populated for
// raw TCP so every node can bind/proxy the same cluster-wide port.
type ExposedPortRoute struct {
	Protocol  string `json:"protocol"`
	HostPort  int    `json:"host_port,omitempty"`
	PublicURL string `json:"public_url,omitempty"`
}

// ExposedPorts is the legacy replicated set of port→protocol intents. Newer
// code also fills ExposedPortRoutes with HostPort/PublicURL metadata so remote
// ingress nodes can install owner-aware data-plane routes. Both fields are kept
// so older snapshots still restore cleanly.
type Placement struct {
	SandboxID          string                       `json:"sandbox_id"`
	OwnerNodeID        string                       `json:"owner_node_id"`
	OwnerAPIURL        string                       `json:"owner_api_url"`
	OwnerDataPlaneHost string                       `json:"owner_data_plane_host,omitempty"`
	Version            uint64                       `json:"version"`
	CreatedUnix        int64                        `json:"created_unix"`
	UpdatedUnix        int64                        `json:"updated_unix"`
	Spec               *models.CreateSandboxRequest `json:"spec,omitempty"`
	SealedSecrets      []byte                       `json:"sealed_secrets,omitempty"`
	ExposedPorts       map[int]string               `json:"exposed_ports,omitempty"`
	ExposedPortRoutes  map[int]ExposedPortRoute     `json:"exposed_port_routes,omitempty"`
	// State is empty for materialized placements (the historical schema) and
	// PlacementStateReserved for capacity-only intents that have not yet been
	// promoted by a successful local create. Reservations are eligible for
	// TTL-driven GC; opPlace transitions a reservation back to empty.
	State PlacementState `json:"state,omitempty"`
	// ExpiresUnix is meaningful only when State == PlacementStateReserved;
	// the leader GC sweep cancels rows whose ExpiresUnix < now.
	ExpiresUnix int64 `json:"expires_unix,omitempty"`
}

// Member is a snapshot of a peer's gossiped state.
type Member struct {
	NodeID        string `json:"node_id"`
	APIURL        string `json:"api_url"`
	DataPlaneHost string `json:"data_plane_host,omitempty"`
	RaftAddr      string `json:"raft_addr,omitempty"`
	// InternalURL is the cluster-internal mTLS endpoint used for raft
	// leader-forward applies. Empty when the peer is running without
	// SB_CLUSTER_TLS_DIR — the forwarder falls back to APIURL with PAT-only
	// auth in that case.
	InternalURL string `json:"internal_url,omitempty"`
	// Role is the peer's gossiped SB_NODE_ROLE. Empty for older builds that
	// pre-date the field; callers treat empty as the legacy "mixed" default.
	Role     string            `json:"role,omitempty"`
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
	ExposedPorts  map[int]ExposedPortRoute
}

// PlacementTarget is returned by SelectPlacement.
type PlacementTarget struct {
	NodeID        string
	APIURL        string
	DataPlaneHost string
	// InternalURL is the peer's cluster-internal mTLS URL (e.g. https://10.0.0.5:7002).
	// Empty when the peer is running without SB_CLUSTER_TLS_DIR or hasn't yet
	// gossiped its advertise URL. Cross-node create-forwarding uses this in
	// preference to APIURL so the hop rides the cert-pinned channel.
	InternalURL string
	IsSelf      bool
}

// OwnerInfo is returned by OwnerOf.
type OwnerInfo struct {
	NodeID string
	APIURL string
	// InternalURL is the owner's cluster-internal mTLS URL. Empty when the
	// owner has no TLS material (mixed/legacy cluster). Owner API forwarding
	// uses this in preference to APIURL so the cross-node hop is cert-pinned.
	InternalURL string
	IsSelf      bool
}

// Endpoint pairs a peer's optional cluster-internal mTLS URL with its public
// API URL. Passed to ForwardHTTP so the forwarder can transparently pick the
// cert-pinned internal channel when both ends have TLS material, falling back
// to the public APIURL (PAT-authenticated) otherwise.
type Endpoint struct {
	InternalURL string
	APIURL      string
}

// SandboxRecreator is the cluster's escape hatch back into the service layer
// for the failover-recreate path. The owner watcher (see owner_watcher.go)
// invokes RecreateSandbox for any FSM placement that points to self but has
// no corresponding local sandbox — typically because the previous owner died
// and the dead-owner reconciler reassigned the placement here.
//
// exposedPorts carries the replicated port routing intents the previous owner
// had recorded; the implementation is expected to re-issue ExposePort for each
// entry after the create succeeds. Raw TCP entries include the original
// HostPort so the recreated owner can preserve the public endpoint when the
// port is available on the new node.
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
	RecreateSandbox(ctx context.Context, id string, spec models.CreateSandboxRequest, sealedSecrets []byte, exposedPorts map[int]ExposedPortRoute) error
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

	// OwnerOfName resolves a cluster-wide sandbox name to its sandbox ID and
	// current owner. Names are indexed from replicated specs and exist for
	// facade APIs that accept either ID or name. Returns ErrUnknownSandbox if
	// no placement record claims name.
	OwnerOfName(name string) (string, OwnerInfo, error)

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

	// AddExposedPort records intent that sandboxID has port exposed. Raw TCP
	// routes include HostPort so every ingress node can bind/proxy the same
	// cluster-wide endpoint. Idempotent when the route metadata is unchanged.
	AddExposedPort(ctx context.Context, sandboxID string, port int, route ExposedPortRoute) error

	// RemoveExposedPort drops a port intent from the placement. Idempotent.
	RemoveExposedPort(ctx context.Context, sandboxID string, port int) error

	// ExposedPortsOf returns a copy of the replicated port route map for
	// sandboxID, or nil if none. Used by the recreator and ingress reconciler.
	ExposedPortsOf(sandboxID string) map[int]ExposedPortRoute

	// DeletePlacement removes sandboxID from the FSM. Idempotent.
	DeletePlacement(ctx context.Context, sandboxID string) error

	// ReserveOnTarget writes opReserve into the FSM holding capacity + name
	// for target before the body is forwarded to it. The reservation carries
	// the redacted spec + sealed secrets so the target's RecordPlacement
	// promote step can run with nil Spec/SealedSecrets and inherit them
	// atomically. ttl bounds how long the reservation can hold capacity if
	// the target never promotes (the leader's GC sweep cancels expired rows
	// at ~5s tick cadence). Spec MUST already be redacted — the raft log
	// must NOT carry plaintext credentials.
	ReserveOnTarget(ctx context.Context, sandboxID string, target PlacementTarget, redacted *models.CreateSandboxRequest, sealedSecrets []byte, ttl time.Duration) error

	// CancelReservation drops a pending reservation from the FSM. No-op on
	// missing or already-promoted (Placed) rows, so router rollback / TTL GC
	// / late successful promote can race harmlessly.
	CancelReservation(ctx context.Context, sandboxID string) error

	// SetNodeDrainState marks nodeID as drained (excluded from
	// SelectPlacement) or restores it to the candidate pool. Idempotent on
	// both edges. The mark lives in the FSM and survives the drained node
	// going away — the operator's intent must outlast the process they're
	// about to stop.
	SetNodeDrainState(ctx context.Context, nodeID string, drained bool) error

	// IsNodeDrained reports whether nodeID is currently marked drained.
	// Reads the local FSM (no network hop). Used by observability endpoints
	// — placement scoring uses an internal accessor that takes one lock for
	// the whole sweep.
	IsNodeDrained(nodeID string) bool

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

	// ForwardHTTP reverse-proxies r to the given peer, copying response back to
	// w. Used by the API layer when OwnerOf != self. When target.InternalURL is
	// non-empty AND this node has its own TLS material loaded, the proxy rides
	// the cert-pinned mTLS channel; otherwise it falls back to target.APIURL
	// with PAT-only auth (the legacy public-API path).
	ForwardHTTP(target Endpoint, w http.ResponseWriter, r *http.Request)

	// AttachInternalHandler wires the API server's HTTP handler into the
	// cluster-internal mTLS listener so peers can reverse-proxy owner API calls
	// over the cert-pinned channel (not just leader-forwarded raft applies).
	// No-op for Noop and for Cluster instances with SB_CLUSTER_TLS_DIR unset.
	// Safe to call exactly once after construction; subsequent calls overwrite.
	AttachInternalHandler(h http.Handler)

	// Members returns a snapshot of all known cluster members.
	Members() []Member

	// Placements returns the local FSM's placement snapshot. Used by each node
	// to reconcile owner-aware public ingress routes.
	Placements() []Placement

	// PlacementOf returns the full Placement record for sandboxID and true,
	// or a zero Placement and false if no record exists. Operator/debug
	// endpoints use this for convergence-status reads where the per-aspect
	// getters (OwnerOf/ExposedPortsOf) would lose the placement.Version
	// needed to compute "is this sandbox's route installed yet on this node".
	PlacementOf(sandboxID string) (Placement, bool)

	// PlacementVersion is the FSM's monotonic apply counter — bumps on every
	// raft log entry the FSM applied. Exposed for metrics/observability and
	// as a tie-breaker for tests; the ingress reconciler now uses
	// SubscribePlacement to wake on apply rather than polling this counter.
	// Zero means "no version data" (Noop or fresh cluster).
	PlacementVersion() uint64

	// SubscribePlacement returns a buffered (cap=1) channel that receives a
	// signal after every FSM apply on this node. The channel is fed directly
	// from FSM.Apply, so a leader-side commit reaches every node's
	// subscribers as soon as raft delivers the log entry — no poll interval.
	//
	// Multiple applies between reads collapse into one wake (cap=1, drops on
	// full). Cancel ctx (or the returned cancel func) to deregister; both
	// are safe to call multiple times. Callers MUST tolerate spurious wakes —
	// the channel says "something changed in the FSM," not "the placement
	// you care about changed."
	//
	// In single-node mode (Noop) the returned channel never fires; this is
	// safe to use in a select{} alongside a ticker because Go's select treats
	// a never-firing nil channel as permanently un-ready, not an error.
	SubscribePlacement(ctx context.Context) <-chan struct{}

	// Leader returns the node ID of the current Raft leader, empty if none.
	Leader() string

	// Close shuts down the cluster cleanly.
	Close() error
}

// Package upgradewire holds the wire types of the upgrade API
// (plans/kubectl-style-cluster-ops.md §6). The server routes in pkg/api/v1
// and internal/cluster and the `aerolvm upgrade` / `aerolvm release` client
// in cmd/aerolvm both use these types, so the two sides cannot drift.
//
// Only the public, fleet.admin routes live here. The leader-to-node calls on
// the internal mTLS port (stage, apply, file copies between nodes) are
// cluster internals and keep their own types in internal/cluster.
package upgradewire

import (
	"regexp"
	"time"
)

// Public routes. All of them need fleet.admin and are audited.
const (
	// ClusterUpgradePath: GET reads the current rollout (404 when the
	// cluster never had one); POST starts one (ApplyRequest). A POST that
	// matches the current rollout returns it with 200, a new rollout
	// answers 201 (the table in §6.6 decides which).
	ClusterUpgradePath = "/v1/cluster/upgrade"
	// ClusterUpgradeStopPath, ...ResumePath, ...FinalizePath and
	// ...RollbackPath take an empty body and answer the rollout after the
	// command. A command the current state refuses answers 409 with an
	// ErrorResponse naming the state and the way out.
	ClusterUpgradeStopPath     = "/v1/cluster/upgrade/stop"
	ClusterUpgradeResumePath   = "/v1/cluster/upgrade/resume"
	ClusterUpgradeFinalizePath = "/v1/cluster/upgrade/finalize"
	ClusterUpgradeRollbackPath = "/v1/cluster/upgrade/rollback"
	// ClusterUpgradeFilesPath + "/{sha256}": PUT uploads one release file
	// to the leader for `apply --from` (body = the raw file, at most
	// MaxUploadBytes; the leader refuses a body whose SHA-256 is not the
	// path). 201 when stored, 200 when the leader already had it. HEAD
	// answers 200 when the leader has the file and 404 when not, so the
	// CLI uploads only what is missing.
	ClusterUpgradeFilesPath = "/v1/cluster/upgrade/files"
	// ClusterLeaderTransferPath: POST hands Raft leadership to another
	// voter (LeaderTransferRequest) and answers LeaderTransferResponse.
	ClusterLeaderTransferPath = "/v1/cluster/leader/transfer"

	// NodeUpgradePath is the single-node route (no cluster mode): POST
	// starts an upgrade of this node (NodeUpgradeRequest) and answers 202
	// with NodeUpgradeResponse, or 200 when the node already runs the
	// version. GET answers the latest operation's NodeUpgradeResponse
	// (404 when there was none). In cluster mode both answer 409 with
	// ErrorResponse{Error: ErrCodeClusterMode}.
	NodeUpgradePath = "/v1/node/upgrade"
	// NodeUpgradeFilesPath + "/{sha256}": PUT/HEAD as for
	// ClusterUpgradeFilesPath, on the single node. 409 in cluster mode.
	NodeUpgradeFilesPath = "/v1/node/upgrade/files"
)

// MaxUploadBytes caps one uploaded release file (§6.6: 256 MiB per file;
// sandboxd is about 77 MiB).
const MaxUploadBytes int64 = 256 << 20

// MaxUploadTotalBytes caps what a node holds of uploads at once, on the
// cluster leader and on a single node alike (§8: 2 GiB in total, plus the
// hourly prune of uploads nothing used). A PUT past it answers 507 with
// ErrCodeUploadQuota.
const MaxUploadTotalBytes int64 = 2 << 30

// SHA256Re is the only accepted shape of a {sha256} path segment: 64
// lower-case hex digits. Anything else is a 400 before any file is touched.
var SHA256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Error codes in ErrorResponse.Error that clients branch on.
const (
	ErrCodeClusterMode           = "cluster_mode"            // single-node route called on a cluster
	ErrCodeNotClusterMode        = "not_cluster_mode"        // cluster route called on a single node
	ErrCodeRolloutConflict       = "rollout_conflict"        // the current rollout's state refuses the command
	ErrCodeSkew                  = "version_skew"            // target below upgrade_from_min, or a downgrade
	ErrCodeRemoteUpgradeDisabled = "remote_upgrade_disabled" // SB_REMOTE_UPGRADE=false on the node
	ErrCodeOperatorDriven        = "operator_driven"         // SB_UPGRADE_DRIVER=operator on the node: the operator swaps its image
	ErrCodeKubernetesManaged     = "kubernetes_managed"      // apply or rollback on a cluster the operator upgrades
	ErrCodeNeedsDowntime         = "needs_allow_downtime"    // one or two voters and no AllowDowntime
	ErrCodeSkippedNodes          = "skipped_nodes"           // finalize while nodes are still skipped
	ErrCodeHashMismatch          = "hash_mismatch"           // upload body does not hash to its path
	ErrCodeFilesMissing          = "files_missing"           // source=upload but the leader lacks a file
	ErrCodeUpgradeRunning        = "upgrade_running"         // a local upgrade already holds the node's lock
	ErrCodeUploadQuota           = "upload_quota"            // the node holds MaxUploadTotalBytes of uploads already
)

// ErrorResponse is the body of every refusal on these routes.
type ErrorResponse struct {
	Error  string `json:"error"`
	Reason string `json:"reason,omitempty"`
	// Hint is the one command the operator should run next, if any.
	Hint string `json:"hint,omitempty"`
	// Nodes names the nodes the refusal is about (skipped nodes, a down
	// server that blocks quorum).
	Nodes []string `json:"nodes,omitempty"`
}

// Sources of a rollout's files.
const (
	SourceRelease = "release" // servers download from SB_RELEASE_URL
	SourceUpload  = "upload"  // the CLI uploaded them to the leader (--from)
	// SourceImages: on Kubernetes the operator swaps each pod's images, so
	// no node fetches a release file and the apply names none (C13).
	SourceImages = "images"
)

// ApplyRequest is the body of POST ClusterUpgradePath.
type ApplyRequest struct {
	// Version is the target release, e.g. "v0.6.12".
	Version string `json:"version"`
	// Files maps each release asset name to its SHA-256, for every CPU
	// type the cluster runs: "sandboxd_linux_amd64": "<hex>",
	// "toolboxd_linux_arm64": "<hex>", "caddy_linux_amd64": "<hex>",
	// "release.json": "<hex>". The CLI reads them from checksums.txt (or
	// the bundle's) after checking them.
	Files map[string]string `json:"files"`
	// Source is SourceRelease or SourceUpload.
	Source string `json:"source"`
	// Hold keeps the rollout at "done" until POST ClusterUpgradeFinalizePath.
	Hold bool `json:"hold,omitempty"`
	// Batch is the worker batch size: "3" or "10%". Empty means 10%, at
	// least 1. "0", "0%" and anything above 100% are refused (400).
	Batch string `json:"batch,omitempty"`
	// PauseAfter cuts the first worker batch to at most N workers and
	// pauses once N workers are done (§6.7). 0 means no pause.
	PauseAfter int `json:"pause_after,omitempty"`
	// NodeTimeout is the per-node health deadline as a Go duration
	// ("10m"). Empty means DefaultNodeTimeout.
	NodeTimeout string `json:"node_timeout,omitempty"`
	// AllowDowntime lets a cluster with one voter upgrade it (eng D8).
	AllowDowntime bool `json:"allow_downtime,omitempty"`
	// AllowUnversioned lets dev and test builds whose versions are not
	// release tags be targets (they cannot be ordered, so no skew check).
	AllowUnversioned bool `json:"allow_unversioned,omitempty"`
}

// DefaultNodeTimeout is the per-node health deadline (eng D6).
const DefaultNodeTimeout = 10 * time.Minute

// Rollout states (§6.6).
const (
	StateStaging     = "staging"
	StateRunning     = "running"
	StatePaused      = "paused"
	StateDone        = "done"
	StateFailed      = "failed"
	StateStopped     = "stopped"
	StateFinalizing  = "finalizing"
	StateFinalized   = "finalized"
	StateRollingBack = "rolling-back"
	StateRolledBack  = "rolled-back"
)

// Rollout directions.
const (
	DirectionUpgrade  = "upgrade"
	DirectionRollback = "rollback"
)

// Per-node states (§6.6).
const (
	NodePending   = "pending"
	NodeStaged    = "staged"
	NodeUpgrading = "upgrading"
	NodeDone      = "done"
	NodeFailed    = "failed"
	NodeManual    = "manual"
	NodeSkipped   = "skipped"
)

// Rollout is the record the leader keeps in Raft, as the API shows it.
// GET ClusterUpgradePath and every command route answer it.
type Rollout struct {
	ID              string `json:"id"`
	State           string `json:"state"`
	Direction       string `json:"direction"`
	TargetVersion   string `json:"target_version"`
	PreviousVersion string `json:"previous_version,omitempty"`
	Source          string `json:"source"`
	// Caller is the principal that ran apply, from the committed record.
	Caller        string    `json:"caller"`
	Hold          bool      `json:"hold,omitempty"`
	Batch         string    `json:"batch"`
	PauseAfter    int       `json:"pause_after,omitempty"`
	NodeTimeout   string    `json:"node_timeout"`
	AllowDowntime bool      `json:"allow_downtime,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	// Error is why the rollout is failed or stopped, if it is.
	Error string `json:"error,omitempty"`
	// ActiveVersion is the cluster's active version (§6.5) when this was
	// read: the release it was committed for.
	ActiveVersion string `json:"active_version,omitempty"`
	// ActiveFSMOpsVersion is the active version's FSM op number, the one
	// cross-node writes gate on. It moves only when a new build's op set
	// is finalized, so two builds of one tree share it.
	ActiveFSMOpsVersion int           `json:"active_fsm_ops_version,omitempty"`
	Nodes               []RolloutNode `json:"nodes"`
}

// RolloutNode is one node's progress.
type RolloutNode struct {
	NodeID  string `json:"node_id"`
	Role    string `json:"role"`
	Arch    string `json:"arch"`
	State   string `json:"state"`
	Version string `json:"version,omitempty"`
	// Order is the node's place in the rollout (servers, then ingress,
	// then workers in batches; the reverse for a rollback).
	Order int `json:"order"`
	// Batch is the worker batch number, from 1; 0 for servers and ingress.
	Batch int `json:"batch,omitempty"`
	// Error is why the node failed, or why it is manual or skipped.
	Error string `json:"error,omitempty"`
	// ManualCommand is the command to run on a manual node.
	ManualCommand string `json:"manual_command,omitempty"`
	// Migrated is true once the node ran its one-way schema migrations
	// at finalize (§6.5); finalized waits for every node.
	Migrated bool `json:"migrated,omitempty"`
	// Operator is true for a node the Kubernetes operator upgrades
	// (C13). While its state is "upgrading", the operator swaps the
	// node's agent image; the node is done once it reports the target.
	Operator  bool      `json:"operator,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// LeaderTransferRequest is the body of POST ClusterLeaderTransferPath.
// An empty To lets Raft pick the most up-to-date voter.
type LeaderTransferRequest struct {
	To string `json:"to,omitempty"`
}

// LeaderTransferResponse names the leader after the transfer.
type LeaderTransferResponse struct {
	Leader string `json:"leader"`
	Term   uint64 `json:"term"`
}

// The states of a local operation that callers branch on (the others are
// progress).
const (
	NodeOpPending = "pending"
	NodeOpDone    = "done"
	NodeOpFailed  = "failed"
)

// NodeUpgradeRequest is the body of POST NodeUpgradePath.
type NodeUpgradeRequest struct {
	Version string `json:"version"`
	// Files maps release asset names to SHA-256 for this node's CPU type
	// (and "release.json"), as in ApplyRequest.Files.
	Files map[string]string `json:"files"`
	// Source is SourceRelease (the node downloads from its release URL) or
	// SourceUpload (every file was PUT to NodeUpgradeFilesPath first).
	Source string `json:"source"`
	// Rollback allows a downgrade; with no Files it puts back the *.prev
	// files of the last upgrade (§6.8).
	Rollback         bool   `json:"rollback,omitempty"`
	AllowUnversioned bool   `json:"allow_unversioned,omitempty"`
	HealthTimeout    string `json:"health_timeout,omitempty"`
}

// NodeUpgradeResponse is one local upgrade operation.
type NodeUpgradeResponse struct {
	Op string `json:"op"`
	// State is the operation's phase: NodeOpPending while the upgrader is
	// launched but has written no record yet, then the upgrader's own
	// phases (staging, stopping, backup, swapping, host-apply, starting,
	// reverting), ending in NodeOpDone or NodeOpFailed.
	State   string `json:"state"`
	Version string `json:"version"`
	// From is the version the node ran before the operation.
	From string `json:"from,omitempty"`
	// Rollback is true when the operation was a rollback, so
	// `aerolvm upgrade rollback` run twice does not undo its own rollback.
	Rollback  bool      `json:"rollback,omitempty"`
	Error     string    `json:"error,omitempty"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

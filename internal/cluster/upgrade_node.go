package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// The node side of a rollout (plans/kubectl-style-cluster-ops.md §6.3,
// §6.7; CEO T1, D12).
//
//	leader ──POST /v1/cluster/nodes/{id}/upgrade {stage|apply|finalize}──► node (:7002, mTLS)
//	       ──GET  /v1/cluster/nodes/{id}/upgrade?op=──────────────────────► node: its own state
//
// Every step is fenced before it does anything (Codex outside review
// finding 1): the caller must be a verified live peer (authorizePeerRequest
// and withInternalMTLS), it must be the current Raft leader, its term must
// be the current term and no older than the highest term this node ever
// obeyed, and the rollout ID, the step, the version and every file hash
// must be in the committed record. A server reads its own FSM after a Raft
// read index; a worker or ingress node asks a server
// (PublicInternalUpgradeFencePath), which does the same. So a delayed
// command from a deposed leader, or a peer that only claims to lead, does
// nothing.
//
// stage puts the files into the node's FileStore (nodeupgrade.Stage).
// apply hands them to `sandboxd upgrade node` under systemd-run
// (nodeupgrade.Launch) and answers 202: the upgrader stops this process.
// finalize runs the node's one-way schema migrations once the active
// version is committed (§6.5, CEO D16).

// Internal paths of the node step.
const (
	// NodeUpgradeStepSuffix follows PublicNodesPath + {id}.
	NodeUpgradeStepSuffix = "/upgrade"
	// PublicInternalUpgradeFencePath serves the fence to workers and
	// ingress nodes, from a server: GET ?rollout=<id>&node=<id>.
	PublicInternalUpgradeFencePath = "/v1/cluster/internal/upgrade/fence"
)

// Node steps.
const (
	UpgradeStepStage    = "stage"
	UpgradeStepApply    = "apply"
	UpgradeStepFinalize = "finalize"
)

// Answers of a node step.
const (
	UpgradeNodeStaged   = "staged"
	UpgradeNodeStarted  = "started"
	UpgradeNodeDone     = "done"
	UpgradeNodeFailed   = "failed"
	UpgradeNodeMigrated = "migrated"
)

// materializeTimeout bounds getting an apply's files into place (a copy
// from a server when the store lacks one); launchTimeout bounds starting
// the upgrader. Both outlive the leader's call on purpose; tests shorten
// them.
var (
	materializeTimeout = 45 * time.Second
	launchTimeout      = 30 * time.Second
)

// UpgradeStepRequest is the leader's call to one node.
type UpgradeStepRequest struct {
	RolloutID string `json:"rollout_id"`
	Step      string `json:"step"`
	Direction string `json:"direction"`
	Version   string `json:"version"`
	// Files are the files this node installs: its CPU type's, and
	// release.json.
	Files map[string]string `json:"files,omitempty"`
	// CacheFiles are the files a server keeps for the nodes that copy from
	// it: every CPU type in the rollout (§6.3, Codex eng finding 6).
	CacheFiles       map[string]string `json:"cache_files,omitempty"`
	Source           string            `json:"source,omitempty"`
	Op               string            `json:"op,omitempty"`
	Term             uint64            `json:"term"`
	AllowUnversioned bool              `json:"allow_unversioned,omitempty"`
	HealthTimeout    string            `json:"health_timeout,omitempty"`
}

// UpgradeStepResponse is a node's answer.
type UpgradeStepResponse struct {
	NodeID string `json:"node_id"`
	Step   string `json:"step"`
	State  string `json:"state"`
	Op     string `json:"op,omitempty"`
	// Version and Arch are the build this node runs and its CPU type.
	Version string `json:"version"`
	Arch    string `json:"arch"`
	// Installed hashes the binaries the node runs now, by role, at stage:
	// the previous version's files for a rollback (§6.6).
	Installed map[string]string `json:"installed,omitempty"`
	Fetched   []string          `json:"fetched,omitempty"`
	Bytes     int64             `json:"bytes,omitempty"`
	Error     string            `json:"error,omitempty"`
}

// UpgradeNodeStatus answers GET on the node step route: what the node runs
// and, with ?op=, that operation's record.
type UpgradeNodeStatus struct {
	NodeID        string `json:"node_id"`
	Version       string `json:"version"`
	Arch          string `json:"arch"`
	FSMOpsVersion int    `json:"fsm_ops_version"`
	// AppliedIndex is the node's FSM version: 0 on a node without one. The
	// health check compares a server's with the leader's (§6.2).
	AppliedIndex  uint64 `json:"applied_index,omitempty"`
	RemoteUpgrade bool   `json:"remote_upgrade"`
	Op            string `json:"op,omitempty"`
	OpFound       bool   `json:"op_found,omitempty"`
	OpPhase       string `json:"op_phase,omitempty"`
	OpResult      string `json:"op_result,omitempty"`
	OpVersion     string `json:"op_version,omitempty"`
	OpError       string `json:"op_error,omitempty"`
	// OpRunning is true while an upgrader holds this node's lock.
	OpRunning      bool `json:"op_running,omitempty"`
	SchemaFinished bool `json:"schema_finished,omitempty"`
}

// UpgradeFence is what a node checks a command against: the committed
// leader, term and rollout, read after a Raft read index.
type UpgradeFence struct {
	Leader string `json:"leader"`
	Term   uint64 `json:"term"`
	// Rollout carries the header and only the asking node's record.
	Rollout *RolloutRecord `json:"rollout,omitempty"`
}

// UpgradeStepError is a refused or failed step, with the HTTP status and
// the upgradewire error code the leader branches on.
type UpgradeStepError struct {
	Status int
	Code   string
	Reason string
}

func (e *UpgradeStepError) Error() string {
	if e.Code != "" {
		return e.Code + ": " + e.Reason
	}
	return e.Reason
}

func stepErr(status int, code, format string, a ...any) error {
	return &UpgradeStepError{Status: status, Code: code, Reason: fmt.Sprintf(format, a...)}
}

// Codes of fencing refusals (in UpgradeStepError.Code), beside the
// upgradewire ones.
const (
	upgradeCodeNotLeader   = "not_leader"
	upgradeCodeStaleTerm   = "stale_term"
	upgradeCodeNotInRecord = "not_in_record"
	upgradeCodeRetry       = "retry"
)

// UpgradeStepper is the node step capability: Cluster and Agent implement
// it; Noop does not (a single node has its own route, /v1/node/upgrade).
type UpgradeStepper interface {
	UpgradeStep(ctx context.Context, caller string, req UpgradeStepRequest) (UpgradeStepResponse, error)
	UpgradeStatus(ctx context.Context, op string) UpgradeNodeStatus
	// UpgradeFenceFor serves a worker's fence request; a non-server
	// answers an error.
	UpgradeFenceFor(ctx context.Context, rolloutID, nodeID string) (UpgradeFence, error)
}

// OneWayMigrator runs the store's finalize-gated migrations
// (store.RunOneWayMigrations). The daemon attaches it.
type OneWayMigrator func(ctx context.Context) error

// UpgradeAuditEvent is one node step or rollout command for the audit log.
type UpgradeAuditEvent struct {
	Route     string
	Step      string
	RolloutID string
	// Caller is the principal from the committed record (node steps) or
	// the API request (rollout commands); never from a node request body.
	Caller string
	NodeID string
	Result string
	Reason string
}

// UpgradeAuditRecorder is the optional half of SandboxRecreator that writes
// upgrade records (internal/service).
type UpgradeAuditRecorder interface {
	RecordClusterUpgrade(UpgradeAuditEvent)
}

// upgradeNode is the node half, shared by Cluster and Agent.
type upgradeNode struct {
	nodeID   string
	isServer bool
	cfg      config.Config
	logger   *slog.Logger

	// fence reads the committed leader, term and rollout.
	fence func(ctx context.Context, rolloutID string) (UpgradeFence, error)
	// servers lists live server members other than self, leader last.
	servers func() []Member
	// clientFor is the mTLS client pinned to one peer.
	clientFor func(nodeID string) *http.Client
	patToken  string
	// appliedIndex is the node's FSM version, 0 without one.
	appliedIndex func() uint64
	audit        func(UpgradeAuditEvent)

	migrator    atomic.Pointer[OneWayMigrator]
	schemaDone  atomic.Bool
	paths       func() (nodeupgrade.Paths, error)
	host        nodeupgrade.Host
	launch      func(ctx context.Context, host nodeupgrade.Host, binary string, req nodeupgrade.Request) (string, error)
	fetchRetry  time.Duration
	termMu      sync.Mutex
	highestTerm uint64
	termLoaded  bool
}

func newUpgradeNode(cfg config.Config, nodeID string, isServer bool, logger *slog.Logger) *upgradeNode {
	return &upgradeNode{
		nodeID: nodeID, isServer: isServer, cfg: cfg, logger: logger, patToken: cfg.PATToken,
		host:       &nodeupgrade.SystemHost{},
		launch:     nodeupgrade.Launch,
		fetchRetry: 2 * time.Second,
		paths: func() (nodeupgrade.Paths, error) {
			return nodeupgrade.ResolvePaths(nodeupgrade.DefaultEnvFile, os.Getenv, func() (string, error) { return exec.LookPath("caddy") })
		},
	}
}

func (u *upgradeNode) store(p nodeupgrade.Paths) nodeupgrade.FileStore {
	return nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(p.StateDir)}
}

// termPath keeps the highest leader term this node obeyed, so a restart
// does not forget it.
func termPath(p nodeupgrade.Paths) string { return filepath.Join(p.StateDir, "leader-term") }

func (u *upgradeNode) loadTermLocked(p nodeupgrade.Paths) {
	if u.termLoaded {
		return
	}
	u.termLoaded = true
	raw, err := os.ReadFile(termPath(p))
	if err != nil {
		return
	}
	if v, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); err == nil && v > u.highestTerm {
		u.highestTerm = v
	}
}

// obeyTerm records term as obeyed, refusing one older than the highest.
func (u *upgradeNode) obeyTerm(p nodeupgrade.Paths, term uint64) error {
	u.termMu.Lock()
	defer u.termMu.Unlock()
	u.loadTermLocked(p)
	if term < u.highestTerm {
		return stepErr(http.StatusForbidden, upgradeCodeStaleTerm, "term %d is older than term %d this node already obeyed", term, u.highestTerm)
	}
	if term > u.highestTerm {
		u.highestTerm = term
		if err := os.MkdirAll(p.StateDir, 0o700); err == nil {
			if err := WriteFileAtomic(termPath(p), []byte(strconv.FormatUint(term, 10)+"\n"), 0o600); err != nil && u.logger != nil {
				u.logger.Warn("cluster: could not record the leader term this node obeyed", "err", err)
			}
		}
	}
	return nil
}

// checkUpgradeFence is the whole fencing rule, pure so it is tested row by
// row: the caller leads, the term is current, and the step is the
// committed record's.
func checkUpgradeFence(caller, selfID string, req UpgradeStepRequest, f UpgradeFence) error {
	if f.Leader == "" {
		return stepErr(http.StatusServiceUnavailable, upgradeCodeRetry, "the cluster has no leader right now")
	}
	if caller != f.Leader {
		return stepErr(http.StatusForbidden, upgradeCodeNotLeader, "%s is not the leader (%s is)", caller, f.Leader)
	}
	if req.Term < f.Term {
		return stepErr(http.StatusForbidden, upgradeCodeStaleTerm, "term %d is older than the current term %d", req.Term, f.Term)
	}
	if req.Term > f.Term {
		return stepErr(http.StatusServiceUnavailable, upgradeCodeRetry, "term %d is newer than this node's view (%d); retry", req.Term, f.Term)
	}
	r := f.Rollout
	if r == nil || r.ID != req.RolloutID {
		return stepErr(http.StatusForbidden, upgradeCodeNotInRecord, "rollout %s is not the committed rollout", req.RolloutID)
	}
	n := r.Nodes[selfID]
	if n == nil {
		return stepErr(http.StatusForbidden, upgradeCodeNotInRecord, "this node is not in rollout %s", r.ID)
	}
	if req.Direction != r.Direction {
		return stepErr(http.StatusForbidden, upgradeCodeNotInRecord, "rollout %s is a %s, not a %s", r.ID, r.Direction, req.Direction)
	}
	want, files := r.TargetVersion, r.Files
	if r.Direction == upgradewire.DirectionRollback {
		want, files = r.PreviousVersion, r.PrevFiles
	}
	if req.Version != want {
		return stepErr(http.StatusForbidden, upgradeCodeNotInRecord, "rollout %s moves to %s, not %s", r.ID, want, req.Version)
	}
	for _, set := range []map[string]string{req.Files, req.CacheFiles} {
		for name, sum := range set {
			if files[name] != sum {
				return stepErr(http.StatusForbidden, upgradeCodeNotInRecord, "%s=%s is not in rollout %s", name, sum, r.ID)
			}
		}
	}
	switch req.Step {
	case UpgradeStepStage:
		if r.Direction != upgradewire.DirectionUpgrade || !containsState([]string{upgradewire.StateStaging, upgradewire.StateRunning, upgradewire.StateDone}, r.State) {
			return stepErr(http.StatusConflict, upgradewire.ErrCodeRolloutConflict, "rollout %s is %s: no staging", r.ID, r.State)
		}
		if n.State != upgradewire.NodePending && n.State != upgradewire.NodeStaged {
			return stepErr(http.StatusConflict, upgradewire.ErrCodeRolloutConflict, "this node is %s in rollout %s, not pending", n.State, r.ID)
		}
	case UpgradeStepApply:
		if n.State != upgradewire.NodeUpgrading || n.Op == "" || n.Op != req.Op {
			return stepErr(http.StatusForbidden, upgradeCodeNotInRecord, "op %s is not this node's step in rollout %s (node is %s, op %q)", req.Op, r.ID, n.State, n.Op)
		}
	case UpgradeStepFinalize:
		if r.State != upgradewire.StateFinalizing {
			return stepErr(http.StatusConflict, upgradewire.ErrCodeRolloutConflict, "rollout %s is %s, not finalizing", r.ID, r.State)
		}
	default:
		return stepErr(http.StatusBadRequest, "", "unknown step %q", req.Step)
	}
	return nil
}

// Step runs one fenced node step.
func (u *upgradeNode) Step(ctx context.Context, caller string, req UpgradeStepRequest) (resp UpgradeStepResponse, err error) {
	resp = UpgradeStepResponse{NodeID: u.nodeID, Step: req.Step, Version: version.Version, Arch: runtime.GOARCH}
	var fence UpgradeFence
	defer func() {
		ev := UpgradeAuditEvent{Route: "node-step", Step: req.Step, RolloutID: req.RolloutID, NodeID: u.nodeID, Result: "success"}
		if fence.Rollout != nil && fence.Rollout.ID == req.RolloutID {
			ev.Caller = fence.Rollout.Caller
		}
		if err != nil {
			ev.Result, ev.Reason = "failure", err.Error()
			var se *UpgradeStepError
			if errors.As(err, &se) && se.Code != "" {
				upgradeFenceRefused.Add(se.Code, 1)
			}
		}
		if u.audit != nil {
			u.audit(ev)
		}
		if u.logger != nil {
			u.logger.Info("cluster: upgrade node step", "rollout_id", req.RolloutID, "step", req.Step, "op", req.Op,
				"leader", caller, "caller", ev.Caller, "result", ev.Result, "reason", ev.Reason)
		}
	}()
	if req.Step != UpgradeStepFinalize && !u.cfg.RemoteUpgradeEnabled() {
		return resp, stepErr(http.StatusConflict, upgradewire.ErrCodeRemoteUpgradeDisabled, "SB_REMOTE_UPGRADE=false on %s: run the upgrade on the node", u.nodeID)
	}
	if u.fence == nil {
		return resp, stepErr(http.StatusServiceUnavailable, upgradeCodeRetry, "the node cannot read the rollout yet")
	}
	fence, err = u.fence(ctx, req.RolloutID)
	if err != nil {
		var se *UpgradeStepError
		if errors.As(err, &se) {
			return resp, err
		}
		return resp, stepErr(http.StatusServiceUnavailable, upgradeCodeRetry, "read the committed rollout: %v", err)
	}
	if err := checkUpgradeFence(caller, u.nodeID, req, fence); err != nil {
		return resp, err
	}
	p, err := u.paths()
	if err != nil {
		return resp, stepErr(http.StatusInternalServerError, "", "read the node's paths: %v", err)
	}
	if err := u.obeyTerm(p, req.Term); err != nil {
		return resp, err
	}
	switch req.Step {
	case UpgradeStepStage:
		return u.stage(ctx, p, req, resp)
	case UpgradeStepApply:
		return u.apply(ctx, p, req, resp)
	default:
		return u.finalize(ctx, resp)
	}
}

func (u *upgradeNode) stage(ctx context.Context, p nodeupgrade.Paths, req UpgradeStepRequest, resp UpgradeStepResponse) (UpgradeStepResponse, error) {
	all := cloneStringMap(req.Files)
	if all == nil {
		all = map[string]string{}
	}
	if u.isServer {
		for k, v := range req.CacheFiles {
			all[k] = v
		}
	}
	res, err := nodeupgrade.Stage(ctx, p, u.host, u.store(p), nodeupgrade.StageRequest{
		Files: all, Install: req.Files, Fetch: u.fetcher(p, req),
	})
	if err != nil {
		return resp, stepErr(http.StatusUnprocessableEntity, "", "stage %s: %v", req.Version, err)
	}
	installed, err := nodeupgrade.InstalledFiles(p)
	if err != nil {
		return resp, stepErr(http.StatusInternalServerError, "", "%v", err)
	}
	resp.State = UpgradeNodeStaged
	resp.Installed = installed
	resp.Fetched = res.Fetched
	resp.Bytes = res.Bytes
	return resp, nil
}

func (u *upgradeNode) apply(ctx context.Context, p nodeupgrade.Paths, req UpgradeStepRequest, resp UpgradeStepResponse) (UpgradeStepResponse, error) {
	resp.Op = req.Op
	if version.Version == req.Version {
		resp.State = UpgradeNodeDone
		return resp, nil
	}
	if st, err := nodeupgrade.LoadState(p.StateDir, req.Op); err == nil {
		// The same op again: a new leader resuming, or a retried call. The
		// node's own record wins, so a second upgrade never starts.
		switch st.Phase {
		case nodeupgrade.PhaseDone:
			resp.State = UpgradeNodeDone
		case nodeupgrade.PhaseFailed:
			resp.State, resp.Error = UpgradeNodeFailed, st.Error
		default:
			resp.State = UpgradeNodeStarted
		}
		return resp, nil
	}
	if holder, busy := nodeupgrade.LockHolder(p.StateDir); busy {
		if holder == req.Op {
			resp.State = UpgradeNodeStarted
			return resp, nil
		}
		return resp, stepErr(http.StatusConflict, upgradewire.ErrCodeUpgradeRunning, "another upgrade (op %q) is running on %s", holder, u.nodeID)
	}
	rollback := req.Direction == upgradewire.DirectionRollback
	// AllowDowntime: the leader kept quorum and moved leadership off this
	// node before this call (§6.2); the node must not second-guess a
	// one-voter rollout run with --allow-downtime.
	nreq := nodeupgrade.Request{
		Version: req.Version, Op: req.Op, Rollback: rollback, AllowUnversioned: req.AllowUnversioned,
		AllowDowntime: true,
	}
	if d, err := time.ParseDuration(req.HealthTimeout); err == nil && d > 0 {
		nreq.HealthTimeout = d
	}
	if len(req.Files) > 0 {
		// The leader's call may give up before a slow copy ends; the work
		// must not die with it, or a rollback would lose its fallback.
		mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), materializeTimeout)
		dir, err := u.materialize(mctx, p, req, rollback)
		cancel()
		switch {
		case err == nil:
			nreq.SHA256, nreq.From = cloneStringMap(req.Files), dir
		case rollback:
			// No copy of the previous files anywhere: put back the *.prev
			// files the last upgrade kept, which the upgrader checks.
			if u.logger != nil {
				u.logger.Warn("cluster: rollback files not available; putting back this node's *.prev files", "err", err)
			}
		default:
			return resp, stepErr(http.StatusUnprocessableEntity, "", "%v", err)
		}
	}
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), launchTimeout)
	defer cancel()
	if u.host.UnitActive(lctx, nodeupgrade.LaunchUnit(nreq.Op)) {
		// Launched by an earlier call whose answer was lost.
		resp.State = UpgradeNodeStarted
		return resp, nil
	}
	op, err := u.launch(lctx, u.host, p.Sandboxd, nreq)
	if err != nil {
		if errors.Is(err, nodeupgrade.ErrUsage) {
			return resp, stepErr(http.StatusBadRequest, "", "%v", err)
		}
		return resp, stepErr(http.StatusInternalServerError, "", "start the upgrader: %v", err)
	}
	resp.Op, resp.State = op, UpgradeNodeStarted
	return resp, nil
}

// materialize makes sure every file is in the store (staged earlier, this
// node's own *.prev for a rollback, or a fresh copy) and links them into a
// directory for Request.From.
func (u *upgradeNode) materialize(ctx context.Context, p nodeupgrade.Paths, req UpgradeStepRequest, rollback bool) (string, error) {
	store := u.store(p)
	fetch := u.fetcher(p, req)
	for _, name := range sortedKeys(req.Files) {
		sum := req.Files[name]
		if store.Has(sum) || (rollback && nodeupgrade.PutLocalCopy(p, store, sum)) {
			continue
		}
		rc, err := fetch(ctx, name, sum)
		if err != nil {
			return "", fmt.Errorf("get %s: %w", name, err)
		}
		_, _, err = store.Put(sum, rc)
		_ = rc.Close()
		if err != nil {
			return "", fmt.Errorf("store %s: %w", name, err)
		}
	}
	dir := filepath.Join(p.StateDir, "from-"+req.Op)
	if err := store.Materialize(dir, req.Files); err != nil {
		return "", err
	}
	return dir, nil
}

func (u *upgradeNode) finalize(ctx context.Context, resp UpgradeStepResponse) (UpgradeStepResponse, error) {
	m := u.migrator.Load()
	if m == nil || *m == nil {
		return resp, stepErr(http.StatusServiceUnavailable, upgradeCodeRetry, "the store is not attached yet")
	}
	if err := (*m)(ctx); err != nil {
		return resp, stepErr(http.StatusInternalServerError, "", "one-way migrations: %v", err)
	}
	u.schemaDone.Store(true)
	resp.State = UpgradeNodeMigrated
	return resp, nil
}

// fetcher returns where this node copies a missing file from (§6.3, CEO
// D12): a server downloads from SB_RELEASE_URL (source release) or copies
// the upload from the leader or another server (source upload); a worker
// or ingress node copies from a server, never from the internet.
func (u *upgradeNode) fetcher(p nodeupgrade.Paths, req UpgradeStepRequest) func(ctx context.Context, asset, sum string) (io.ReadCloser, error) {
	return func(ctx context.Context, asset, sum string) (io.ReadCloser, error) {
		if u.isServer && req.Source == upgradewire.SourceRelease {
			src := p.ReleaseURL + "/" + url.PathEscape(req.Version) + "/" + url.PathEscape(asset)
			rc, _, err := u.host.Fetch(ctx, src)
			return rc, err
		}
		return u.copyFromServers(ctx, sum)
	}
}

// copyFromServers copies one file from a server's store, trying each live
// server in turn and waiting on a busy one (503) until ctx ends.
func (u *upgradeNode) copyFromServers(ctx context.Context, sum string) (io.ReadCloser, error) {
	if !upgradewire.SHA256Re.MatchString(sum) {
		return nil, nodeupgrade.ErrBadHash
	}
	var lastErr error
	for {
		servers := []Member(nil)
		if u.servers != nil {
			servers = u.servers()
		}
		if len(servers) == 0 {
			lastErr = errors.New("no live server to copy from")
		}
		for _, m := range servers {
			rc, retry, err := u.copyFrom(ctx, m, sum)
			if err == nil {
				return rc, nil
			}
			lastErr = err
			if !retry {
				continue
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w (last: %v)", ctx.Err(), lastErr)
		case <-time.After(u.fetchRetry):
		}
	}
}

// copyFrom asks one server for a file. retry is true for an answer worth
// waiting on (busy, starting).
func (u *upgradeNode) copyFrom(ctx context.Context, m Member, sum string) (io.ReadCloser, bool, error) {
	if strings.TrimSpace(m.InternalURL) == "" || u.clientFor == nil {
		return nil, false, fmt.Errorf("server %s has no internal URL", m.NodeID)
	}
	base := u.clientFor(m.NodeID)
	if base == nil {
		return nil, false, fmt.Errorf("no client for %s", m.NodeID)
	}
	// The pooled client has a request timeout sized for control-plane
	// calls; a release file streams for much longer, so the caller's
	// context bounds it instead.
	client := *base
	client.Timeout = 0
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(m.InternalURL, "/")+PublicInternalUpgradeFilesPath+sum, nil)
	if err != nil {
		return nil, false, err
	}
	SetPeerNodeIDHeader(req, u.nodeID)
	if u.patToken != "" {
		req.Header.Set("Authorization", "Bearer "+u.patToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("copy from %s: %w", m.NodeID, err)
	}
	if resp.StatusCode == http.StatusOK {
		return resp.Body, false, nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	_ = resp.Body.Close()
	retry := resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusTooManyRequests
	return nil, retry, fmt.Errorf("copy from %s: status %d: %s", m.NodeID, resp.StatusCode, strings.TrimSpace(string(msg)))
}

// Status answers GET on the node step route.
func (u *upgradeNode) Status(op string) UpgradeNodeStatus {
	st := UpgradeNodeStatus{
		NodeID: u.nodeID, Version: version.Version, Arch: runtime.GOARCH, FSMOpsVersion: fsmOpsVersion,
		RemoteUpgrade: u.cfg.RemoteUpgradeEnabled(), Op: op, SchemaFinished: u.schemaDone.Load(),
	}
	if u.appliedIndex != nil {
		st.AppliedIndex = u.appliedIndex()
	}
	p, err := u.paths()
	if err != nil {
		return st
	}
	if op != "" {
		if rec, err := nodeupgrade.LoadState(p.StateDir, op); err == nil {
			st.OpFound = true
			st.OpPhase, st.OpResult, st.OpVersion, st.OpError = string(rec.Phase), rec.Result, rec.Version, rec.Error
		}
	}
	if holder, busy := nodeupgrade.LockHolder(p.StateDir); busy {
		st.OpRunning = true
		if op != "" && holder == op && !st.OpFound {
			st.OpPhase = string(nodeupgrade.PhaseStaging)
		}
	}
	return st
}

// AttachOneWayMigrator hands the node its store's finalize step, and
// whether its one-way migrations already ran (a node whose database has
// none pending is finished from the start).
func (u *upgradeNode) AttachOneWayMigrator(run OneWayMigrator, finished bool) {
	if u == nil {
		return
	}
	u.migrator.Store(&run)
	if finished {
		u.schemaDone.Store(true)
	}
}

// trimFence keeps the header and only nodeID's record: a worker's fence
// answer stays small at fleet scale.
func trimFence(r *RolloutRecord, nodeID string) *RolloutRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.Nodes = map[string]*RolloutNodeRecord{}
	if n, ok := r.Nodes[nodeID]; ok && n != nil {
		cp := *n
		out.Nodes[nodeID] = &cp
	}
	return &out
}

// serverFence is the server side of the fence: a Raft read index proves
// who leads and that every entry committed before it is applied here, then
// the record is read from the local FSM.
func (c *Cluster) serverFence(ctx context.Context, rolloutID, nodeID string) (UpgradeFence, error) {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return UpgradeFence{}, errors.New("cluster: node holds no placement state")
	}
	idx, err := c.readIndex(ctx)
	if err != nil {
		return UpgradeFence{}, err
	}
	for c.fsm.currentVersion() < idx {
		select {
		case <-ctx.Done():
			return UpgradeFence{}, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	_, leader := c.raft.raft.LeaderWithID()
	r, _ := c.fsm.rolloutView()
	return UpgradeFence{Leader: string(leader), Term: c.raft.raft.CurrentTerm(), Rollout: trimFence(r, nodeID)}, nil
}

// UpgradeFenceFor serves a worker's or ingress node's fence request.
func (c *Cluster) UpgradeFenceFor(ctx context.Context, rolloutID, nodeID string) (UpgradeFence, error) {
	return c.serverFence(ctx, rolloutID, nodeID)
}

// UpgradeStep runs a fenced node step on this server.
func (c *Cluster) UpgradeStep(ctx context.Context, caller string, req UpgradeStepRequest) (UpgradeStepResponse, error) {
	return c.upgrade.Step(ctx, caller, req)
}

// UpgradeStatus answers the leader's read of this node.
func (c *Cluster) UpgradeStatus(_ context.Context, op string) UpgradeNodeStatus {
	return c.upgrade.Status(op)
}

// AttachOneWayMigrator wires the store's finalize step (pkg/daemon).
func (c *Cluster) AttachOneWayMigrator(run OneWayMigrator, finished bool) {
	if c != nil {
		c.upgrade.AttachOneWayMigrator(run, finished)
	}
}

// SchemaFinalized reports whether this node ran its one-way migrations:
// features that need the new schema turn on per node only after (§6.5,
// Codex eng finding 4).
func (c *Cluster) SchemaFinalized() bool { return c != nil && c.upgrade.schemaDone.Load() }

// UpgradeStep runs a fenced node step on this worker or ingress node.
func (a *Agent) UpgradeStep(ctx context.Context, caller string, req UpgradeStepRequest) (UpgradeStepResponse, error) {
	return a.upgrade.Step(ctx, caller, req)
}

// UpgradeStatus answers the leader's read of this node.
func (a *Agent) UpgradeStatus(_ context.Context, op string) UpgradeNodeStatus {
	return a.upgrade.Status(op)
}

// UpgradeFenceFor is served by servers only.
func (a *Agent) UpgradeFenceFor(context.Context, string, string) (UpgradeFence, error) {
	return UpgradeFence{}, stepErr(http.StatusNotFound, "", "this node holds no Raft state")
}

// AttachOneWayMigrator wires the store's finalize step (pkg/daemon).
func (a *Agent) AttachOneWayMigrator(run OneWayMigrator, finished bool) {
	if a != nil {
		a.upgrade.AttachOneWayMigrator(run, finished)
	}
}

// SchemaFinalized reports whether this node ran its one-way migrations.
func (a *Agent) SchemaFinalized() bool { return a != nil && a.upgrade.schemaDone.Load() }

// recordUpgradeAudit hands an upgrade record to the service's audit
// writer, when one is attached.
func (a *Agent) recordUpgradeAudit(ev UpgradeAuditEvent) {
	if rec, ok := a.currentRecreator().(UpgradeAuditRecorder); ok {
		rec.RecordClusterUpgrade(ev)
	}
}

// agentFence asks a server for the fence: the server takes the read index.
func (a *Agent) agentFence(ctx context.Context, rolloutID string) (UpgradeFence, error) {
	q := url.Values{"rollout": {rolloutID}, "node": {a.nodeID}}
	path := PublicInternalUpgradeFencePath + "?" + q.Encode()
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var out UpgradeFence
	if err := a.doControlPlaneJSON(reqCtx, http.MethodGet, path, path, nil, &out); err != nil {
		return UpgradeFence{}, err
	}
	return out, nil
}

// serversForCopy lists live servers other than self with the leader last:
// the leader serves nothing while another server is up (CEO D15).
func serversForCopy(members []Member, self, leader string) []Member {
	var out, last []Member
	for _, m := range members {
		if m.NodeID == self || !m.Alive || m.InternalURL == "" || !CanServeControlPlaneRole(m.Role) {
			continue
		}
		if m.NodeID == leader {
			last = append(last, m)
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return append(out, last...)
}

// decodeUpgradeStepError restores an UpgradeStepError from a node's
// refusal body.
func decodeUpgradeStepError(status int, body []byte) error {
	var e upgradewire.ErrorResponse
	if json.Unmarshal(body, &e) == nil && (e.Error != "" || e.Reason != "") {
		return &UpgradeStepError{Status: status, Code: e.Error, Reason: e.Reason}
	}
	return &UpgradeStepError{Status: status, Reason: strings.TrimSpace(string(body))}
}

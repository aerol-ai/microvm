package v1

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clusterroute"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Cluster upgrade routes (plans/kubectl-style-cluster-ops.md §6). All are
// new paths; nothing existing changes (/v1 is soft-frozen). Every write is
// audited with its caller.
//
//	GET    /v1/cluster/upgrade                    fleet.admin  the rollout (404 when none)
//	POST   /v1/cluster/upgrade                    fleet.admin  apply (201 new, 200 the current one)
//	POST   /v1/cluster/upgrade/{stop,resume,finalize,rollback}  fleet.admin
//	PUT    /v1/cluster/upgrade/files/{sha256}     fleet.admin  upload one file to the leader
//	HEAD   /v1/cluster/upgrade/files/{sha256}     fleet.admin  does the leader hold it
//	POST   /v1/cluster/leader/transfer            fleet.admin  hand Raft leadership to a voter
//	POST   /v1/cluster/nodes/{id}/upgrade         peer: the leader's stage/apply/finalize step
//	GET    /v1/cluster/nodes/{id}/upgrade         peer: the node's upgrade state
//	GET    /v1/cluster/internal/upgrade/fence     peer, servers: the committed fence for a worker
//	GET    /v1/cluster/internal/upgrade/files/{sha256}  peer, servers: copy one release file
//
// Writes run on the leader: any other node forwards them there over the
// internal mTLS channel with the caller's own credentials, so the leader
// authenticates the caller itself. With cluster mode off every public
// route answers 409 not_cluster_mode; a single node upgrades through
// /v1/node/upgrade.

// clusterUpgradeLeaderHeader marks a request this route already forwarded
// to the leader, so a node that lost leadership since answers 503 instead
// of forwarding again.
const clusterUpgradeLeaderHeader = "X-Cluster-Upgrade-Leader"

// rolloutWriteTimeout bounds a rollout write: a Raft apply, plus a leader
// transfer's election.
const rolloutWriteTimeout = 30 * time.Second

func writeUpgradeError(w http.ResponseWriter, status int, code, reason, hint string, nodes ...string) {
	apihttp.WriteJSON(w, status, upgradewire.ErrorResponse{Error: code, Reason: reason, Hint: hint, Nodes: nodes})
}

// writeRolloutError maps a rollout or node-step error to its answer.
func writeRolloutError(w http.ResponseWriter, err error) {
	var re *cluster.RolloutError
	var se *cluster.UpgradeStepError
	switch {
	case errors.As(err, &re):
		apihttp.WriteJSON(w, re.Status, re.Body)
	case errors.As(err, &se):
		if se.Status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "2")
		}
		writeUpgradeError(w, se.Status, se.Code, se.Reason, "")
	case errors.Is(err, cluster.ErrNotCaughtUp):
		clusterroute.WriteNotCaughtUp(w, apihttp.WriteError)
	case errors.Is(err, cluster.ErrNotLeader):
		w.Header().Set("Retry-After", "1")
		writeUpgradeError(w, http.StatusServiceUnavailable, "not_leader", "the leader changed; retry", "")
	case errors.Is(err, cluster.ErrClusterVersion):
		writeUpgradeError(w, http.StatusConflict, "cluster_version", err.Error(), "")
	case errors.Is(err, context.DeadlineExceeded):
		writeUpgradeError(w, http.StatusGatewayTimeout, "timeout", err.Error(), "")
	default:
		writeUpgradeError(w, http.StatusInternalServerError, "internal", err.Error(), "")
	}
}

// upgradeCluster returns the cluster client, or answers 409
// not_cluster_mode under Noop.
func (h *handlers) upgradeCluster(w http.ResponseWriter) (cluster.Client, bool) {
	var c cluster.Client
	if h.deps.Service != nil {
		c = h.deps.Service.Cluster()
	}
	if _, ok := c.(cluster.UpgradeStepper); !ok {
		writeUpgradeError(w, http.StatusConflict, upgradewire.ErrCodeNotClusterMode,
			"this node does not run in cluster mode", "upgrade a single node with aerolvm upgrade apply (POST "+upgradewire.NodeUpgradePath+")")
		return nil, false
	}
	return c, true
}

// onLeader forwards r to the leader unless this node leads, and returns
// the leader's rollout capability when it does.
func (h *handlers) onLeader(w http.ResponseWriter, r *http.Request) (cluster.Rollouts, bool) {
	c, ok := h.upgradeCluster(w)
	if !ok {
		return nil, false
	}
	if ro, isServer := c.(cluster.Rollouts); isServer && c.Leader() == c.SelfNodeID() {
		return ro, true
	}
	if r.Header.Get(clusterUpgradeLeaderHeader) == "1" {
		w.Header().Set("Retry-After", "1")
		writeUpgradeError(w, http.StatusServiceUnavailable, "not_leader", "the leader changed while this call was forwarded; retry", "")
		return nil, false
	}
	h.forwardTemplateToLeader(w, r, c, clusterUpgradeLeaderHeader)
	return nil, false
}

// upgradeCaller is the principal the record and the audit name.
func upgradeCaller(r *http.Request) string {
	if access, ok := controlplane.AccessFromContext(r.Context()); ok && access.Principal.ID != "" {
		return string(access.Principal.Kind) + ":" + access.Principal.ID
	}
	return "unknown"
}

// auditUpgrade writes one record for a rollout write.
func (h *handlers) auditUpgrade(r *http.Request, route, rolloutID string, err error) {
	if h.deps.Service == nil {
		return
	}
	ev := cluster.UpgradeAuditEvent{Route: route, RolloutID: rolloutID, Caller: upgradeCaller(r), Result: "success"}
	if err != nil {
		ev.Result, ev.Reason = "failure", err.Error()
	}
	h.deps.Service.RecordClusterUpgrade(ev)
	if h.deps.Logger != nil {
		h.deps.Logger.Info("cluster upgrade call", "route", route, "rollout_id", rolloutID, "caller", ev.Caller, "result", ev.Result, "reason", ev.Reason)
	}
}

func (h *handlers) clusterGetUpgrade(w http.ResponseWriter, r *http.Request) {
	c, ok := h.upgradeCluster(w)
	if !ok {
		return
	}
	ro, isServer := c.(cluster.Rollouts)
	if !isServer {
		// A worker holds no FSM: the leader answers.
		if _, ok := h.onLeader(w, r); !ok {
			return
		}
		return
	}
	out, err := ro.GetRollout(r.Context())
	if err != nil {
		writeRolloutError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, out)
}

func (h *handlers) clusterApplyUpgrade(w http.ResponseWriter, r *http.Request) {
	ro, ok := h.onLeader(w, r)
	if !ok {
		return
	}
	var req upgradewire.ApplyRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		writeUpgradeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), rolloutWriteTimeout)
	defer cancel()
	out, created, err := ro.ApplyRollout(ctx, upgradeCaller(r), req)
	id := ""
	if out != nil {
		id = out.ID
	}
	h.auditUpgrade(r, "apply", id, err)
	if err != nil {
		writeRolloutError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	apihttp.WriteJSON(w, status, out)
}

// clusterUpgradeCommand serves stop, resume, finalize and rollback.
func (h *handlers) clusterUpgradeCommand(command string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ro, ok := h.onLeader(w, r)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), rolloutWriteTimeout)
		defer cancel()
		out, err := ro.RolloutCommand(ctx, upgradeCaller(r), command)
		id := ""
		if out != nil {
			id = out.ID
		}
		h.auditUpgrade(r, command, id, err)
		if err != nil {
			writeRolloutError(w, err)
			return
		}
		apihttp.WriteJSON(w, http.StatusOK, out)
	}
}

func (h *handlers) clusterLeaderTransfer(w http.ResponseWriter, r *http.Request) {
	ro, ok := h.onLeader(w, r)
	if !ok {
		return
	}
	var req upgradewire.LeaderTransferRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil && r.ContentLength != 0 {
		writeUpgradeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), rolloutWriteTimeout)
	defer cancel()
	out, err := ro.TransferLeadership(ctx, req.To)
	h.auditUpgrade(r, "leader-transfer", "", err)
	if err != nil {
		writeRolloutError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, out)
}

// clusterUpgradeFile serves PUT (upload) and HEAD (do you have it) on the
// leader.
func (h *handlers) clusterUpgradeFile(w http.ResponseWriter, r *http.Request) {
	sum := r.PathValue("sha256")
	if !upgradewire.SHA256Re.MatchString(sum) {
		writeUpgradeError(w, http.StatusBadRequest, "bad_request", "the path must end in 64 lower-case hex digits", "")
		return
	}
	ro, ok := h.onLeader(w, r)
	if !ok {
		return
	}
	files, ok := ro.(cluster.UpgradeFiles)
	if !ok {
		writeUpgradeError(w, http.StatusConflict, upgradewire.ErrCodeNotClusterMode, "this node holds no upload store", "")
		return
	}
	if r.Method == http.MethodHead {
		has, err := files.HasUpgradeFile(sum)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !has {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.ContentLength > upgradewire.MaxUploadBytes {
		writeUpgradeError(w, http.StatusRequestEntityTooLarge, "too_large", "a release file may be at most 256 MiB", "")
		return
	}
	body := http.MaxBytesReader(w, r.Body, upgradewire.MaxUploadBytes)
	created, size, err := files.PutUpgradeFile(r.Context(), sum, body)
	h.auditUpgrade(r, "upload "+sum, "", err)
	switch {
	case errors.Is(err, nodeupgrade.ErrHashMismatch):
		writeUpgradeError(w, http.StatusBadRequest, upgradewire.ErrCodeHashMismatch, err.Error(), "")
		return
	case errors.Is(err, cluster.ErrUploadQuota):
		writeUpgradeError(w, http.StatusInsufficientStorage, "upload_quota", err.Error(), "")
		return
	case err != nil && strings.Contains(err.Error(), "larger than"):
		writeUpgradeError(w, http.StatusRequestEntityTooLarge, "too_large", err.Error(), "")
		return
	case err != nil:
		writeUpgradeError(w, http.StatusBadRequest, "upload_failed", err.Error(), "")
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	apihttp.WriteJSON(w, status, map[string]any{"sha256": sum, "size": size, "created": created})
}

// clusterNodeUpgradeStep is the leader's call to this node (internal).
func (h *handlers) clusterNodeUpgradeStep(w http.ResponseWriter, r *http.Request) {
	stepper, ok := h.nodeUpgradeTarget(w, r)
	if !ok {
		return
	}
	var req cluster.UpgradeStepRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		writeUpgradeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", "")
		return
	}
	peerID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	resp, err := stepper.UpgradeStep(r.Context(), peerID, req)
	if err != nil {
		writeRolloutError(w, err)
		return
	}
	status := http.StatusOK
	if resp.State == cluster.UpgradeNodeStarted {
		status = http.StatusAccepted
	}
	apihttp.WriteJSON(w, status, resp)
}

// clusterNodeUpgradeStatus answers the leader's read of this node.
func (h *handlers) clusterNodeUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	stepper, ok := h.nodeUpgradeTarget(w, r)
	if !ok {
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, stepper.UpgradeStatus(r.Context(), strings.TrimSpace(r.URL.Query().Get("op"))))
}

// nodeUpgradeTarget checks the call is for this node: the leader dials the
// node itself, so another {id} is a misrouted call.
func (h *handlers) nodeUpgradeTarget(w http.ResponseWriter, r *http.Request) (cluster.UpgradeStepper, bool) {
	c, ok := h.upgradeCluster(w)
	if !ok {
		return nil, false
	}
	if id := strings.TrimSpace(r.PathValue("id")); id != c.SelfNodeID() {
		writeUpgradeError(w, http.StatusMisdirectedRequest, "wrong_node", "this is "+c.SelfNodeID()+", not "+id, "")
		return nil, false
	}
	return c.(cluster.UpgradeStepper), true
}

// clusterInternalUpgradeFence serves a worker's fence request (servers).
func (h *handlers) clusterInternalUpgradeFence(w http.ResponseWriter, r *http.Request) {
	c, ok := h.upgradeCluster(w)
	if !ok {
		return
	}
	if _, isServer := c.(cluster.Rollouts); !isServer {
		writeUpgradeError(w, http.StatusNotFound, "not_server", "only a server holds the rollout", "")
		return
	}
	peerID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	node := strings.TrimSpace(r.URL.Query().Get("node"))
	if node != peerID {
		// A node reads only its own record.
		writeUpgradeError(w, http.StatusForbidden, "wrong_node", "a node may read only its own fence", "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out, err := c.(cluster.UpgradeStepper).UpgradeFenceFor(ctx, strings.TrimSpace(r.URL.Query().Get("rollout")), node)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeUpgradeError(w, http.StatusServiceUnavailable, "retry", err.Error(), "")
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, out)
}

// clusterInternalUpgradeFile serves one release file to a peer (servers).
func (h *handlers) clusterInternalUpgradeFile(w http.ResponseWriter, r *http.Request) {
	c, ok := h.upgradeCluster(w)
	if !ok {
		return
	}
	files, isServer := c.(cluster.UpgradeFiles)
	if !isServer {
		writeUpgradeError(w, http.StatusNotFound, "not_server", "only servers serve release files", "")
		return
	}
	peerID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	files.ServeUpgradeFile(w, r, peerID, r.PathValue("sha256"))
}

package v1

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Single-node upgrade routes (plans/kubectl-style-cluster-ops.md §6.1). With
// cluster mode off, `aerolvm upgrade apply` uploads the release files here
// (for --from) and starts `sandboxd upgrade node` on this node; there is no
// rollout record. In a cluster every route answers 409 cluster_mode, because
// the rollout must own every restart there. The work lives in
// nodeupgrade.Local; these handlers only decode and map errors.

// maxNodeUpgradeBody bounds a POST body: a version and a few dozen hashes.
const maxNodeUpgradeBody = 1 << 20

// maxNodeUpgradeFile caps one upload (§6.6: 256 MiB); tests lower it.
var maxNodeUpgradeFile = upgradewire.MaxUploadBytes

func writeUpgradeError(w http.ResponseWriter, status int, e upgradewire.ErrorResponse) {
	apihttp.WriteJSON(w, status, e)
}

// nodeUpgradeAllowed answers the refusals every node route shares: cluster
// mode, and (for the routes that change the node) SB_REMOTE_UPGRADE=false.
func (h *handlers) nodeUpgradeAllowed(w http.ResponseWriter, r *http.Request, changes bool) bool {
	svc := h.deps.Service
	if svc.ClusterEnabled() {
		writeUpgradeError(w, http.StatusConflict, upgradewire.ErrorResponse{
			Error:  upgradewire.ErrCodeClusterMode,
			Reason: "this node runs in a cluster; the cluster's rollout upgrades its nodes",
			Hint:   "aerolvm upgrade apply <version>",
		})
		return false
	}
	if changes && !svc.RemoteUpgradeEnabled() {
		writeUpgradeError(w, http.StatusForbidden, upgradewire.ErrorResponse{
			Error:  upgradewire.ErrCodeRemoteUpgradeDisabled,
			Reason: "SB_REMOTE_UPGRADE is off on this node, so it takes no upgrade over the API",
			Hint:   "on the node: sudo sandboxd upgrade node <version> --sha256 <file>=<hash>...",
		})
		return false
	}
	return true
}

// nodeUpgradeStart is POST /v1/node/upgrade: 202 with the new (or the
// still-running, same-version) operation, 200 when the node already runs
// the version.
func (h *handlers) nodeUpgradeStart(w http.ResponseWriter, r *http.Request) {
	if !h.nodeUpgradeAllowed(w, r, true) {
		return
	}
	var req upgradewire.NodeUpgradeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxNodeUpgradeBody)).Decode(&req); err != nil {
		writeUpgradeError(w, http.StatusBadRequest, upgradewire.ErrorResponse{Error: "invalid_request", Reason: "decode body: " + err.Error()})
		return
	}
	resp, started, err := h.deps.Service.NodeUpgrades().Start(r.Context(), req)
	var running *nodeupgrade.ErrRunning
	var missing *nodeupgrade.ErrFilesMissing
	switch {
	case errors.Is(err, nodeupgrade.ErrUsage):
		writeUpgradeError(w, http.StatusBadRequest, upgradewire.ErrorResponse{Error: "invalid_request", Reason: err.Error()})
		return
	case errors.As(err, &running):
		writeUpgradeError(w, http.StatusConflict, upgradewire.ErrorResponse{Error: upgradewire.ErrCodeUpgradeRunning,
			Reason: err.Error(), Hint: "aerolvm upgrade status"})
		return
	case errors.As(err, &missing):
		writeUpgradeError(w, http.StatusConflict, upgradewire.ErrorResponse{Error: upgradewire.ErrCodeFilesMissing, Reason: err.Error()})
		return
	case err != nil:
		h.deps.Logger.Error("node upgrade did not start", "version", req.Version, "error", err)
		writeUpgradeError(w, http.StatusInternalServerError, upgradewire.ErrorResponse{Error: "internal", Reason: err.Error()})
		return
	}
	auditlog.NoteTarget(r.Context(), resp.Op)
	status := http.StatusOK
	if started {
		status = http.StatusAccepted
	}
	apihttp.WriteJSON(w, status, resp)
}

// nodeUpgradeStatus is GET /v1/node/upgrade: the latest operation.
func (h *handlers) nodeUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	if !h.nodeUpgradeAllowed(w, r, false) {
		return
	}
	resp, ok := h.deps.Service.NodeUpgrades().Latest(r.Context())
	if !ok {
		writeUpgradeError(w, http.StatusNotFound, upgradewire.ErrorResponse{Error: "not_found", Reason: "no upgrade has run on this node"})
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// nodeUpgradeFileSum is the {sha256} path value, or "" after a 400.
func nodeUpgradeFileSum(w http.ResponseWriter, r *http.Request) string {
	sum := r.PathValue("sha256")
	if !upgradewire.SHA256Re.MatchString(sum) {
		writeUpgradeError(w, http.StatusBadRequest, upgradewire.ErrorResponse{Error: "invalid_request",
			Reason: "the file name must be its SHA-256 in lower-case hex"})
		return ""
	}
	return sum
}

// nodeUpgradePutFile is PUT /v1/node/upgrade/files/{sha256}: 201 stored,
// 200 already there. The body is streamed to disk and hashed on the way; a
// body whose hash is not the name is refused and nothing is kept.
func (h *handlers) nodeUpgradePutFile(w http.ResponseWriter, r *http.Request) {
	if !h.nodeUpgradeAllowed(w, r, true) {
		return
	}
	sum := nodeUpgradeFileSum(w, r)
	if sum == "" {
		return
	}
	if r.ContentLength > maxNodeUpgradeFile {
		writeUpgradeError(w, http.StatusRequestEntityTooLarge, upgradewire.ErrorResponse{Error: "too_large",
			Reason: "a release file may be at most 256 MiB"})
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxNodeUpgradeFile)
	created, size, err := h.deps.Service.NodeUpgrades().PutFile(sum, body)
	var tooBig *http.MaxBytesError
	switch {
	case errors.Is(err, nodeupgrade.ErrHashMismatch):
		writeUpgradeError(w, http.StatusBadRequest, upgradewire.ErrorResponse{Error: upgradewire.ErrCodeHashMismatch, Reason: err.Error()})
		return
	case errors.As(err, &tooBig):
		writeUpgradeError(w, http.StatusRequestEntityTooLarge, upgradewire.ErrorResponse{Error: "too_large",
			Reason: "a release file may be at most 256 MiB"})
		return
	case err != nil:
		h.deps.Logger.Error("store an uploaded release file", "sha256", sum, "error", err)
		writeUpgradeError(w, http.StatusInternalServerError, upgradewire.ErrorResponse{Error: "internal", Reason: err.Error()})
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	apihttp.WriteJSON(w, status, map[string]any{"sha256": sum, "size": size})
}

// nodeUpgradeHeadFile is HEAD /v1/node/upgrade/files/{sha256}: 200 when the
// node has the file (and keeps it another hour), 404 when not.
func (h *handlers) nodeUpgradeHeadFile(w http.ResponseWriter, r *http.Request) {
	if !h.nodeUpgradeAllowed(w, r, true) {
		return
	}
	sum := nodeUpgradeFileSum(w, r)
	if sum == "" {
		return
	}
	if !h.deps.Service.NodeUpgrades().HasFile(sum) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

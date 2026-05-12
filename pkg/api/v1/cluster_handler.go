package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// clusterForwardWrap returns a middleware that, for any request carrying a
// {id} path value, looks up the placement and forwards to the owner if the
// owner is not this node. When the owner is this node — or no placement
// exists yet (single-node mode, or unknown sandbox) — the request runs
// locally; the local handler returns 404 if the sandbox truly doesn't exist.
//
// This is the ONLY entry point for cross-node call routing. Once the request
// is forwarded, the receiving node runs the same wrapper, sees IsSelf=true,
// and falls through to the local handler. The X-Cluster-Forwarded header set
// by ForwardHTTP guards against infinite loops if the placement view is stale.
func (h *handlers) clusterForwardWrap(local http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			local.ServeHTTP(w, r)
			return
		}
		c := h.deps.Service.Cluster()
		if c == nil {
			local.ServeHTTP(w, r)
			return
		}
		owner, err := c.OwnerOf(id)
		if err != nil {
			if errors.Is(err, cluster.ErrUnknownSandbox) {
				local.ServeHTTP(w, r)
				return
			}
			if errors.Is(err, cluster.ErrOrphaned) {
				// 410 Gone: the sandbox's owning node died and was
				// auto-evicted. The placement record exists but points
				// nowhere. Clients should treat this as a permanent
				// disappearance and (if they care to) issue a fresh create.
				apihttp.WriteError(w, http.StatusGone, "sandbox owner died; placement orphaned (manual recovery required)")
				return
			}
			apihttp.WriteError(w, http.StatusInternalServerError, "cluster lookup: "+err.Error())
			return
		}
		if owner.IsSelf {
			local.ServeHTTP(w, r)
			return
		}
		if owner.APIURL == "" {
			apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: owner "+owner.NodeID+" API URL unknown")
			return
		}
		c.ForwardHTTP(owner.APIURL, w, r)
	})
}

// clusterCreateWrap is the handler for POST /v1/sandboxes. It runs placement
// before invoking the local createSandbox: if a peer wins, the request is
// forwarded; if self wins, we run locally and then commit the placement
// pointer to raft. On commit failure we attempt to roll back the local
// create — better an aborted create than a sandbox the cluster doesn't know
// about.
func (h *handlers) clusterCreateWrap(w http.ResponseWriter, r *http.Request) {
	// Parse the body up front so an invalid JSON request fails fast with 400
	// without consuming a placement slot — and so the test that passes a nil
	// service still observes the same "bad request → 400" contract as the
	// pre-cluster handler.
	raw, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var req models.CreateSandboxRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	// Restore the body so downstream consumers (local handler or forwarder)
	// can read it.
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))

	if h.deps.Service == nil {
		h.createSandbox(w, r)
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		h.createSandbox(w, r)
		return
	}

	target, err := c.SelectPlacement(capacityRequestFromCreate(req))
	if err != nil {
		apihttp.WriteError(w, http.StatusInternalServerError, "placement: "+err.Error())
		return
	}
	if !target.IsSelf {
		c.ForwardHTTP(target.APIURL, w, r)
		return
	}

	resp, err := h.deps.Service.CreateSandbox(r.Context(), req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	// Raft commit on the response path. This is the only new latency on
	// CreateSandbox — pr-review.md invariant 2 (CreateSandbox latency) is
	// honored because the commit happens AFTER the local create returns,
	// not before, so admission and create latency are unchanged. Single-node
	// mode skips this branch entirely (cluster is Noop, RecordPlacement is a
	// no-op).
	commitCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := c.RecordPlacement(commitCtx, resp.Sandbox.ID); err != nil {
		h.deps.Logger.Error("cluster: RecordPlacement failed; rolling back create",
			"sandbox_id", resp.Sandbox.ID, "err", err)
		// Use a fresh context — the request context may already be cancelled
		// by the time we get here, but we still want the rollback to run.
		rbCtx, rbCancel := context.WithTimeout(context.Background(), 30*time.Second)
		if rbErr := h.deps.Service.DestroySandbox(rbCtx, resp.Sandbox.ID); rbErr != nil {
			h.deps.Logger.Error("cluster: rollback destroy failed",
				"sandbox_id", resp.Sandbox.ID, "err", rbErr)
		}
		rbCancel()
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: placement commit failed: "+err.Error())
		return
	}

	apihttp.WriteJSON(w, http.StatusCreated, resp)
}

// clusterDestroyWrap runs the local destroy then deletes the placement
// record. clusterForwardWrap forwards to the owner before this fires, so when
// we get here we are the owner.
func (h *handlers) clusterDestroyWrap(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.deps.Service.DestroySandbox(r.Context(), id); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	c := h.deps.Service.Cluster()
	if c != nil {
		commitCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := c.DeletePlacement(commitCtx, id); err != nil {
			// Local destroy already succeeded; surface a warning but don't
			// fail the response — reconcile catches ghost rows.
			h.deps.Logger.Warn("cluster: DeletePlacement after destroy failed",
				"sandbox_id", id, "err", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// clusterMembers returns the gossiped member list (observability only).
func (h *handlers) clusterMembers(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteJSON(w, http.StatusOK, map[string]any{"members": []any{}})
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, map[string]any{"members": c.Members()})
}

// clusterLeader returns the current Raft leader's node ID.
func (h *handlers) clusterLeader(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteJSON(w, http.StatusOK, map[string]any{"leader": ""})
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, map[string]any{"leader": c.Leader()})
}

// clusterPlacement returns the placement record for one sandbox.
func (h *handlers) clusterPlacement(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusNotFound, "cluster not enabled")
		return
	}
	owner, err := c.OwnerOf(r.PathValue("id"))
	if err != nil {
		if errors.Is(err, cluster.ErrUnknownSandbox) {
			apihttp.WriteError(w, http.StatusNotFound, "no placement record")
			return
		}
		if errors.Is(err, cluster.ErrOrphaned) {
			apihttp.WriteJSON(w, http.StatusOK, map[string]any{
				"orphaned": true,
				"node_id":  "",
				"api_url":  "",
			})
			return
		}
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, owner)
}

// capacityRequestFromCreate maps the wire CreateSandboxRequest into a
// capacity.Request used for placement scoring. Defaults match the admission
// floor so unspecified requests still produce a stable, comparable score.
func capacityRequestFromCreate(req models.CreateSandboxRequest) capacity.Request {
	cpu := req.CPU
	mem := req.MemoryMB
	if cpu <= 0 {
		cpu = 0.5
	}
	if mem <= 0 {
		mem = 256
	}
	return capacity.Request{CPU: cpu, MemoryMB: mem}
}

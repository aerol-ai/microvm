package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

const clusterCreateTargetHeader = "X-Cluster-Create-Target"

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
		if h.deps.Service == nil {
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
		if owner.APIURL == "" && owner.InternalURL == "" {
			apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: owner "+owner.NodeID+" URL unknown")
			return
		}
		c.ForwardHTTP(cluster.Endpoint{InternalURL: owner.InternalURL, APIURL: owner.APIURL}, w, r)
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

	if targetNodeID := strings.TrimSpace(r.Header.Get(clusterCreateTargetHeader)); targetNodeID != "" {
		if targetNodeID != c.SelfNodeID() {
			apihttp.WriteError(w, http.StatusMisdirectedRequest, "cluster: forwarded create reached wrong target")
			return
		}
		h.createSandboxOnSelectedNode(w, r, req)
		return
	}

	target, err := c.SelectPlacement(capacityRequestFromCreate(req))
	if err != nil {
		apihttp.WriteError(w, http.StatusInternalServerError, "placement: "+err.Error())
		return
	}
	if !target.IsSelf {
		r.Header.Set(clusterCreateTargetHeader, target.NodeID)
		c.ForwardHTTP(cluster.Endpoint{InternalURL: target.InternalURL, APIURL: target.APIURL}, w, r)
		return
	}

	h.createSandboxOnSelectedNode(w, r, req)
}

// createSandboxOnSelectedNode performs the local side effect once placement has
// already selected this node. Cross-node forwarded creates enter here through
// X-Cluster-Create-Target instead of re-running placement on the target.
func (h *handlers) createSandboxOnSelectedNode(w http.ResponseWriter, r *http.Request, req models.CreateSandboxRequest) {
	c := h.deps.Service.Cluster()
	if c == nil {
		h.createSandbox(w, r)
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
	// Replicate the original spec alongside the placement pointer so a future
	// owner can recreate this sandbox if the current owner dies. Secrets
	// (registry password, mount creds) are sealed into a separate encrypted
	// bag and the spec is redacted before going on the wire — the raft log
	// must NOT carry plaintext credentials.
	sealed, err := h.deps.Service.SealClusterSecrets(req)
	if err != nil {
		h.deps.Logger.Error("cluster: seal secrets failed; rolling back create",
			"sandbox_id", resp.Sandbox.ID, "err", err)
		rbCtx, rbCancel := context.WithTimeout(context.Background(), 30*time.Second)
		if rbErr := h.deps.Service.DestroySandbox(rbCtx, resp.Sandbox.ID); rbErr != nil {
			h.deps.Logger.Error("cluster: rollback destroy failed",
				"sandbox_id", resp.Sandbox.ID, "err", rbErr)
		}
		rbCancel()
		apihttp.WriteError(w, http.StatusInternalServerError, "cluster: seal secrets: "+err.Error())
		return
	}
	redacted := service.RedactClusterSecrets(req)
	if err := c.RecordPlacement(commitCtx, resp.Sandbox.ID, &redacted, sealed); err != nil {
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
		// Cluster-wide name conflict surfaces as 409 so clients can
		// distinguish "pick a different name" from "cluster degraded, retry"
		// (503). Without this mapping, two concurrent same-name creates
		// landing on different owners both look like transient placement
		// failures and clients would back off pointlessly.
		if errors.Is(err, cluster.ErrNameConflict) {
			apihttp.WriteError(w, http.StatusConflict, "sandbox name already in use cluster-wide")
			return
		}
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: placement commit failed: "+err.Error())
		return
	}

	apihttp.WriteJSON(w, http.StatusCreated, resp)
}

// clusterListWrap aggregates GET /v1/sandboxes results across the cluster so
// the "any node accepts any request" promise also holds for list — without
// this, list returns only the locally-owned subset and clients have to know
// which node holds which sandbox to enumerate them.
//
// Per-peer requests carry X-Cluster-Forwarded: 1; each peer answers with its
// own local list and never re-fans-out, so a malformed view (e.g. a peer that
// thinks IT is the aggregator) cannot recurse. Per-peer errors degrade to
// "log + skip" rather than failing the whole response — a partial list is
// more useful than 5xx for an enumerate-everything call. The cap on
// degradation is the per-peer 5s timeout: a slow peer can't stall the
// response past that.
//
// Single-node mode (Cluster() == nil) and forwarded requests fall through to
// the local handler unchanged so callers and tests see identical behavior to
// the pre-cluster wire format.
func (h *handlers) clusterListWrap(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Cluster-Forwarded") == "1" {
		h.listSandboxes(w, r)
		return
	}
	if h.deps.Service == nil {
		h.listSandboxes(w, r)
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		h.listSandboxes(w, r)
		return
	}

	selfID := c.SelfNodeID()
	peers := make([]cluster.Member, 0)
	for _, m := range c.Members() {
		if !m.Alive || m.NodeID == "" || m.NodeID == selfID || m.APIURL == "" {
			continue
		}
		peers = append(peers, m)
	}

	tagFilter := parseTagFilter(r)
	local, err := h.deps.Service.ListSandboxes(r.Context(), tagFilter)
	if err != nil {
		h.deps.Logger.Warn("cluster list: local list failed", "error", err)
		local = nil
	}

	type peerResult struct {
		nodeID    string
		sandboxes []*models.Sandbox
		err       error
	}
	results := make(chan peerResult, len(peers))
	auth := r.Header.Get("Authorization")
	// Forward the original query string to each peer so they apply the same
	// tag filter locally — only matching rows traverse the network. Empty
	// when the caller didn't pass any tag.* params.
	peerQuery := r.URL.RawQuery
	httpClient := &http.Client{Timeout: 5 * time.Second}
	for _, peer := range peers {
		go func() {
			endpoint := strings.TrimRight(peer.APIURL, "/") + "/v1/sandboxes"
			if peerQuery != "" {
				endpoint += "?" + peerQuery
			}
			req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil)
			if err != nil {
				results <- peerResult{nodeID: peer.NodeID, err: err}
				return
			}
			req.Header.Set("X-Cluster-Forwarded", "1")
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				results <- peerResult{nodeID: peer.NodeID, err: err}
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
				results <- peerResult{nodeID: peer.NodeID, err: errors.New(strings.TrimSpace(string(body)))}
				return
			}
			var sbs []*models.Sandbox
			if err := json.NewDecoder(resp.Body).Decode(&sbs); err != nil {
				results <- peerResult{nodeID: peer.NodeID, err: err}
				return
			}
			results <- peerResult{nodeID: peer.NodeID, sandboxes: sbs}
		}()
	}

	merged := make([]*models.Sandbox, 0, len(local))
	seen := make(map[string]struct{}, len(local))
	for _, sb := range local {
		if sb == nil {
			continue
		}
		seen[sb.ID] = struct{}{}
		merged = append(merged, sb)
	}
	for i := 0; i < len(peers); i++ {
		res := <-results
		if res.err != nil {
			h.deps.Logger.Warn("cluster list: peer query failed", "peer", res.nodeID, "error", res.err)
			continue
		}
		for _, sb := range res.sandboxes {
			if sb == nil {
				continue
			}
			// Dedupe: a stopped sandbox may still appear in its previous
			// owner's local store briefly after a failover, while the new
			// owner already lists the recreated one under the same ID. Local
			// wins because it's the freshest read for this node.
			if _, dup := seen[sb.ID]; dup {
				continue
			}
			seen[sb.ID] = struct{}{}
			merged = append(merged, sb)
		}
	}

	apihttp.WriteJSON(w, http.StatusOK, merged)
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

// clusterInternalApply receives an encoded raft command from a follower and
// applies it on this node. The handler is auth-gated by the same PAT bearer
// as every other v1 route, so any caller able to forward here is already
// trusted to mutate the cluster state directly. We respond 503 (and *not* a
// generic 5xx) when raft says we're not the leader so the forwarder treats it
// as a retry signal rather than a hard failure.
func (h *handlers) clusterInternalApply(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = r.Body.Close()
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if len(body) == 0 {
		apihttp.WriteError(w, http.StatusBadRequest, "empty raft command body")
		return
	}
	if err := c.ApplyEncoded(r.Context(), body); err != nil {
		if errors.Is(err, cluster.ErrNotLeader) {
			apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not leader")
			return
		}
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

// replicateSpecPatch is the write-through used by mutating handlers (resize,
// lifecycle) to keep the FSM-replicated spec in sync with the local sandbox.
// It reads the current spec from the cluster, applies patch, and writes back
// via UpsertSpec. No-op when:
//   - cluster is nil (single-node mode handled by Noop returning nil from SpecOf)
//   - no spec is recorded yet (pre-cluster sandbox; recreate is impossible
//     until a future write-through bumps the spec — known limitation)
//
// Failures are logged at warn rather than failing the response: the local
// mutation already succeeded and was confirmed to the user. A stale FSM spec
// only matters if this owner dies before the next successful write-through;
// the next mutating call (or an explicit reconcile) will refresh it.
//
// Race: two concurrent mutations for the same sandbox can clobber each other
// in the FSM, but the local sandbox is already authoritative — the worst case
// is a stale spec on a node that hasn't died yet, which the next mutation
// fixes. Same-sandbox mutations are rare and serialize at the docker layer
// anyway.
func (h *handlers) replicateSpecPatch(ctx context.Context, id string, patch func(*models.CreateSandboxRequest)) {
	c := h.deps.Service.Cluster()
	if c == nil {
		return
	}
	spec := c.SpecOf(id)
	if spec == nil {
		// Pre-cluster sandbox or never-recorded spec; nothing to patch.
		return
	}
	patch(spec)
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Pass nil for sealedSecrets — resize / lifecycle never touch credentials,
	// so preserving the existing sealed bag is correct (and required: re-sealing
	// here would silently drop the bag because spec is already redacted, so
	// SealClusterSecrets would return nil-nil and overwrite the original).
	if err := c.UpsertSpec(commitCtx, id, spec, nil); err != nil {
		h.deps.Logger.Warn("cluster: spec write-through failed; FSM spec stale until next mutation",
			"sandbox_id", id, "err", err)
	}
}

// replicateAddExposedPort write-throughs an expose-port intent to the FSM. The
// failure profile is identical to replicateSpecPatch: log warn, don't fail the
// response. The local store already has the exposure recorded; a stale FSM
// only affects what survives an owner failover, and the next mutation
// (re-expose, unexpose, or another sandbox change) will refresh it. ExposePort
// itself is idempotent on the recreated owner so a missed write-through
// degrades gracefully — the user keeps the local route, just not the
// cluster-replicated intent.
func (h *handlers) replicateAddExposedPort(ctx context.Context, id string, port int, route cluster.ExposedPortRoute) {
	c := h.deps.Service.Cluster()
	if c == nil {
		return
	}
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.AddExposedPort(commitCtx, id, port, route); err != nil {
		h.deps.Logger.Warn("cluster: AddExposedPort write-through failed; FSM port intent stale until next mutation",
			"sandbox_id", id, "port", port, "protocol", route.Protocol, "host_port", route.HostPort, "err", err)
	}
}

// replicateRemoveExposedPort is the unexpose counterpart of
// replicateAddExposedPort. Same best-effort semantics.
func (h *handlers) replicateRemoveExposedPort(ctx context.Context, id string, port int) {
	c := h.deps.Service.Cluster()
	if c == nil {
		return
	}
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.RemoveExposedPort(commitCtx, id, port); err != nil {
		h.deps.Logger.Warn("cluster: RemoveExposedPort write-through failed; FSM port intent stale until next mutation",
			"sandbox_id", id, "port", port, "err", err)
	}
}

// capacityRequestFromCreate maps the wire CreateSandboxRequest into a
// capacity.Request used for placement scoring. Defaults track normalizeCreateRequest
// (via models.DefaultCPU / DefaultMemoryMB) so the score we use to pick the
// owner matches the reservation that will actually be charged once the local
// create runs — otherwise a request gets placed on a host that admission then
// rejects.
func capacityRequestFromCreate(req models.CreateSandboxRequest) capacity.Request {
	cpu := req.CPU
	mem := req.MemoryMB
	disk := req.DiskGB
	if cpu <= 0 {
		cpu = models.DefaultCPU
	}
	if mem <= 0 {
		mem = models.DefaultMemoryMB
	}
	if disk <= 0 {
		disk = models.DefaultDiskGB
	}
	out := capacity.Request{CPU: cpu, MemoryMB: mem, DiskGB: disk, Runtime: req.Runtime}
	// GPUs == nil means "no GPU"; a non-nil GPURequest with Count <= 0 is
	// the documented "default 1" path (see GPURequest.Count comment in
	// pkg/models/types.go) and we mirror that here so placement scoring
	// reserves at least one GPU. Count == -1 ("all") is also normalized
	// to 1 for placement purposes — we can't gossip "all" cleanly, and
	// any GPU host that has at least one card satisfies the intent.
	if req.GPUs != nil {
		want := req.GPUs.Count
		if want <= 0 {
			want = 1
		}
		out.GPUs = want
		out.GPUVendor = string(req.GPUs.Vendor)
	}
	return out
}

package v1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clustercreate"
	"github.com/aerol-ai/microvm/pkg/api/clusterlist"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

const (
	clusterCreateTargetHeader = "X-Cluster-Create-Target"
	// clusterCreateIDHeader carries the sandbox ID minted by the router (Node A)
	// before opReserve, so the receiving target (Node T) runs CreateSandboxWithID
	// against the reserved row. Without this, T would mint its own ID and the
	// reservation->placed transition would never match up.
	clusterCreateIDHeader = "X-Cluster-Create-ID"

	// clusterReservationTTL bounds how long a reservation can hold capacity
	// before the leader's GC sweep cancels it. 120s covers slow GPU image
	// pulls; the 5s GC tick makes the worst-case orphan window ~125s.
	clusterReservationTTL = 120 * time.Second

	clusterListMaxFanoutPeers         = 256
	clusterListMaxConcurrentPeerReads = 64
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
			// Route miss: placement says someone else owns the sandbox, but
			// gossip hasn't surfaced any forwarding URL yet (mid-rollover,
			// peer mid-boot, or misconfigured advertise URLs). Bump the
			// counter so operator dashboards see persistent gossip-convergence
			// lag rather than just sporadic 503s.
			service.RecordRouteMiss()
			apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: owner "+owner.NodeID+" URL unknown")
			return
		}
		c.ForwardHTTP(cluster.Endpoint{NodeID: owner.NodeID, InternalURL: owner.InternalURL, APIURL: owner.APIURL}, w, r)
	})
}

// clusterCreateWrap is the handler for POST /v1/sandboxes. It implements the
// reservation-first flow that resolves B1+B2:
//
//  1. parse body
//  2. if forwarded (X-Cluster-Create-Target == self): run locally against the
//     reservation the router already wrote. The forwarded path never re-runs
//     SelectPlacement (B1 fix preserved).
//  3. otherwise: select a placement, mint a sandbox ID, redact secrets, and
//     write opReserve to raft (so the cluster has *intent* before any side
//     effect — B2 fix), then create locally or forward using that reservation.
//
// Steps 2 and 3 live in pkg/api/clustercreate, shared with the daytona and e2b
// facades — this handler only adds the v1 body handling and the local create.
// Keep them there: the copy that used to live here is how v1 went on shipping
// the candidate fleet per create after the bounded selector landed everywhere
// else.
//
// On forward we don't roll back the reservation when ForwardHTTP can't reach
// the peer: ForwardHTTP doesn't return a transport error (it streams the proxy
// response straight to w), and the leader's reservation-GC sweep reclaims the
// row 120s later. This is the documented orphan window in plans/release-blockers.
func (h *handlers) clusterCreateWrap(w http.ResponseWriter, r *http.Request) {
	// Parse the body up front so an invalid JSON request fails fast with 400
	// without consuming a placement slot — and so the test that passes a nil
	// service still observes the same "bad request → 400" contract as the
	// pre-cluster handler.
	raw, err := apihttp.ReadJSONBody(w, r)
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
	if h.deps.Service.Cluster() == nil {
		h.createSandbox(w, r)
		return
	}

	// Placement, reservation and forwarding are the same decision for native
	// v1 as for the daytona/e2b facades, so they run through one
	// implementation. The duplicate that used to live here is what let
	// v1 keep calling SelectPlacementWithCandidates after the bounded
	// selector landed — every create downloading one Member per eligible
	// worker (~1.7 MB at 2k nodes) only to discard the slice.
	decision, ok := clustercreate.Prepare(w, r, h.deps.Service, req, apihttp.WriteError, clustercreate.PrepareOptions{
		Normalize:      normalizeCreateRuntimeForPlacement,
		OwnerRef:       service.OwnerRefForCreate(r.Context()),
		SyncBody:       true,
		MetricPrefix:   "v1.create",
		OnForwardStale: cluster.RecordOwnerForwardStale,
		Logger:         h.deps.Logger,
	})
	if !ok {
		return
	}
	h.createSandboxOnSelectedNode(w, r, req, decision.ReservationID)
}

// createSandboxOnSelectedNode performs the local side effect once placement has
// already selected this node. Two entry points:
//
//   - reservationID == "": local-only image path. No cluster reservation was
//     written because the image cannot be moved to another worker. Create and
//     promote stay sequential (ID isn't fixed before create the same way).
//   - reservationID != "": normal cluster create. The router already wrote
//     the reservation with our redacted spec. CreateSandboxWithID runs in
//     parallel with SealAndDistribute (the seal); RecordPlacement
//     only fires after BOTH legs succeed, so the row stays Reserved — and
//     charged to pending-create backpressure — for the whole local create.
//     Promote-failure retract uses DeletePlacement (mandatory — the commit
//     may have landed despite the error). See
//     plans/warm-create-latency-tier1.5-seal-promote-overlap.md.
func (h *handlers) createSandboxOnSelectedNode(w http.ResponseWriter, r *http.Request, req models.CreateSandboxRequest, reservationID string) {
	createStart := time.Now()
	if err := h.deps.Service.NormalizeCreateImageDistribution(r.Context(), &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := service.NormalizeCreateFailover(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := normalizeCreateRuntimeForPlacement(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		h.createSandbox(w, r)
		return
	}

	// Thread a CreateTiming recorder so the docker create path can attribute
	// readiness (socket vs health) on this — the only path where the readiness
	// socket runs, since the feature is gated on EnableCluster. The plain
	// createSandbox handler does the same; without it the cluster create
	// response carries only create;dur= and UC-96 attribution is lost.
	createCtx, createTiming := docker.WithCreateTiming(r.Context())

	if reservationID != "" {
		service.RecordCreateReservationState("promote_local")
		resp, err := clustercreate.OverlapCreateAndPromote(createCtx, h.deps.Service, h.deps.Logger, req, reservationID, clustercreate.OverlapOptions{
			PromoteWithSpec: true,
			Timing:          createTiming,
		})
		setCreateServerTiming(w, createStart, createTiming, h.deps.ContainerEngine)
		if err != nil {
			h.writeOverlapCreateError(w, err)
			return
		}
		apihttp.WriteJSON(w, http.StatusCreated, resp)
		return
	}

	service.RecordCreateReservationState("self_local")
	resp, err := h.deps.Service.CreateSandbox(createCtx, req)
	if err != nil {
		setCreateServerTiming(w, createStart, createTiming, h.deps.ContainerEngine)
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	// Local-only images keep sequential seal+promote because this path has no
	// pre-minted reservation ID.
	commitCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	secrets, sealErr := h.deps.Service.SealAndDistribute(commitCtx, resp.Sandbox.ID, req, h.deps.Service.SecretRecipientsForSeal(resp.Sandbox.ID))
	if sealErr != nil {
		h.deps.Logger.Error("cluster: store secret ref failed; rolling back create",
			"sandbox_id", resp.Sandbox.ID, "err", sealErr)
		clustercreate.RollbackLocalCreate(context.Background(), h.deps.Service, h.deps.Logger, resp.Sandbox.ID)
		setCreateServerTiming(w, createStart, createTiming, h.deps.ContainerEngine)
		apihttp.WriteError(w, http.StatusInternalServerError, clustercreate.FormatSealError(sealErr))
		return
	}
	if secrets.IncarnationID == "" {
		secrets.IncarnationID = resp.Sandbox.AuditIncarnationID
	}
	secrets.OwnerRef = resp.Sandbox.OwnerRef
	redacted := h.deps.Service.RedactClusterSecretsConfigured(req)
	promoteErr := c.RecordPlacement(commitCtx, resp.Sandbox.ID, &redacted, secrets)

	if promoteErr != nil {
		h.deps.Logger.Error("cluster: RecordPlacement failed; rolling back create",
			"sandbox_id", resp.Sandbox.ID, "err", promoteErr)
		clustercreate.RollbackLocalCreate(context.Background(), h.deps.Service, h.deps.Logger, resp.Sandbox.ID)
		if errors.Is(promoteErr, cluster.ErrNameConflict) {
			setCreateServerTiming(w, createStart, createTiming, h.deps.ContainerEngine)
			apihttp.WriteError(w, http.StatusConflict, "sandbox name already in use cluster-wide")
			return
		}
		setCreateServerTiming(w, createStart, createTiming, h.deps.ContainerEngine)
		apihttp.WriteError(w, http.StatusServiceUnavailable, clustercreate.FormatPromoteError(promoteErr))
		return
	}

	setCreateServerTiming(w, createStart, createTiming, h.deps.ContainerEngine)
	apihttp.WriteJSON(w, http.StatusCreated, resp)
}

func (h *handlers) writeOverlapCreateError(w http.ResponseWriter, err error) {
	if of, ok := clustercreate.AsOverlapFailure(err); ok {
		switch of.Phase {
		case clustercreate.OverlapPhaseSeal:
			apihttp.WriteError(w, http.StatusInternalServerError, clustercreate.FormatSealError(of.Err))
			return
		case clustercreate.OverlapPhasePromote:
			if errors.Is(of.Err, cluster.ErrNameConflict) {
				apihttp.WriteError(w, http.StatusConflict, "sandbox name already in use cluster-wide")
				return
			}
			apihttp.WriteError(w, http.StatusServiceUnavailable, clustercreate.FormatPromoteError(of.Err))
			return
		default:
			apihttp.WriteStoreAwareError(h.deps.Logger, w, of.Err)
			return
		}
	}
	apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
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
// At enterprise topology (thousands of workers) peers are selected from
// placement owners (scoped by tenant OwnerRef when present) rather than every
// alive owner role — unbounded all-peer fan-out previously returned 503 above
// 256 peers. Operators still use /v1/cluster/sandbox-index for paginated
// global enumeration.
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

	ownerRef := clusterlist.OwnerRefFromContext(r.Context())
	limit, pageToken := clusterlist.ParsePageParams(r.URL)
	tagFilter := parseTagFilter(r)
	listOpts := service.GetSandboxOptions{
		IncludeEnv:    parseIncludeEnv(r),
		CorrelationID: correlationIDFromRequest(r),
	}
	local, err := h.deps.Service.ListSandboxesWithOptions(r.Context(), tagFilter, listOpts)
	if err != nil {
		h.deps.Logger.Warn("cluster list: local list failed", "error", err)
		local = nil
	}

	peers, placements, next, viewReady, missingOwners := clusterlist.SelectPeersForPage(c, ownerRef, pageToken, limit)
	if !viewReady {
		// Large fleet with an empty placement index: local-only would look
		// complete. Force clients to retry once the Raft view catches up.
		w.Header().Set("Retry-After", "1")
		clusterlist.WriteCoverageHeaders(w, clusterlist.Coverage{
			Partial:            true,
			PlacementViewReady: false,
			Answered:           []string{"local"},
		}, "")
		apihttp.WriteError(w, http.StatusServiceUnavailable, "placement view is not ready")
		return
	}
	local = clusterlist.FilterLocalToPage(local, placements, pageToken)
	result := clusterlist.Merge(r.Context(), peers, clusterlist.Options{
		OwnerRef:   ownerRef,
		AuthHeader: r.Header.Get("Authorization"),
		RawQuery:   r.URL.RawQuery,
		Path:       PathPrefix + "/sandboxes",
		Local:      local,
		Transport:  clusterlist.TransportFromCluster(c),
		SelfNodeID: c.SelfNodeID(),
		Limit:      limit,
		PageToken:  pageToken,
		WantIDs:    clusterlist.PlacementWantIDs(placements),
		Warn: func(msg, peer string, peerErr error) {
			h.deps.Logger.Warn(msg, "peer", peer, "error", peerErr)
		},
	})
	result.Coverage.PlacementViewReady = viewReady
	if len(missingOwners) > 0 {
		result.Coverage.Missing = append(result.Coverage.Missing, missingOwners...)
		result.Coverage.Partial = true
	}
	result.NextPageToken = next
	clusterlist.WriteCoverageHeaders(w, result.Coverage, result.NextPageToken)
	apihttp.WriteJSON(w, http.StatusOK, result.Sandboxes)
}

func clusterMemberCanOwnSandbox(role string) bool {
	return cluster.CanOwnSandboxRole(role)
}

func parsePositiveIntQuery(r *http.Request, key string) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

func parseRepeatedIntQuery(r *http.Request, key string) []int {
	var out []int
	for _, rawValue := range r.URL.Query()[key] {
		for _, rawPart := range strings.Split(rawValue, ",") {
			rawPart = strings.TrimSpace(rawPart)
			if rawPart == "" {
				continue
			}
			n, err := strconv.Atoi(rawPart)
			if err != nil {
				continue
			}
			out = append(out, n)
		}
	}
	return out
}

func (h *handlers) clusterSandboxIndex(w http.ResponseWriter, r *http.Request) {
	h.writeClusterSandboxIndex(w, r)
}

func (h *handlers) clusterIngressRoute(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "sandbox id required")
		return
	}
	if h.deps.Service == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	// Same membership view the installers hash (cluster.IngressRingMembers);
	// an Agent's Members() is a control-plane snapshot and hashing it here
	// while reconciliation hashes local gossip creates an ingress vacuum
	// during convergence. RingVersion on the response makes a residual
	// disagreement between ingress nodes observable.
	route := cluster.IngressRouteForSandbox(cluster.IngressRingMembers(c), id)
	if len(route.Owners) == 0 {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: no alive ingress route owners")
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, route)
}

// sandboxIndexPlacement extends the cluster.Placement (FSM/Raft state) with
// the local sandbox row's runtime status. The FSM tracks ownership and
// scheduling intent; runtime status (started/stopped/destroyed) lives in
// the per-node store. The dashboard needs runtime status to render
// Start vs Stop action buttons, so the index handler overlays it here
// rather than forcing the UI to fan out an extra GET per row.
// RuntimeStatus is empty for placements owned by another node (we only
// see this node's store) — the UI treats that as "view-only / remote".
type sandboxIndexPlacement struct {
	cluster.Placement
	RuntimeStatus models.SandboxStatus `json:"runtime_status,omitempty"`
}

type sandboxIndexResponse struct {
	Placements    []sandboxIndexPlacement `json:"placements"`
	NextPageToken string                  `json:"next_page_token,omitempty"`
}

func (h *handlers) writeClusterSandboxIndex(w http.ResponseWriter, r *http.Request) {
	if h.deps.Service == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	req := cluster.PlacementPageRequest{
		Limit:     parsePositiveIntQuery(r, "limit"),
		PageToken: strings.TrimSpace(r.URL.Query().Get("page_token")),
		ShardFilter: cluster.PlacementShardFilter{
			ShardCount: parsePositiveIntQuery(r, "shard_count"),
			Shards:     parseRepeatedIntQuery(r, "shard"),
		},
	}
	resp := c.PlacementPage(req)

	// One List call to build the id→status overlay so we don't issue N
	// store.Get calls per page. ListSandboxes already returns local-only
	// rows; placements pointing to another owner stay with empty runtime
	// status and the UI treats them as remote.
	statusByID := map[string]models.SandboxStatus{}
	if locals, err := h.deps.Service.ListSandboxes(r.Context(), nil); err == nil {
		for _, sb := range locals {
			statusByID[sb.ID] = sb.Status
		}
	} else {
		h.deps.Logger.Warn("sandbox-index: local list failed; runtime_status will be empty", "err", err)
	}

	out := sandboxIndexResponse{
		Placements:    make([]sandboxIndexPlacement, len(resp.Placements)),
		NextPageToken: resp.NextPageToken,
	}
	for i := range resp.Placements {
		redactPlacementSecretFields(&resp.Placements[i])
		out.Placements[i] = sandboxIndexPlacement{
			Placement:     resp.Placements[i],
			RuntimeStatus: statusByID[resp.Placements[i].SandboxID],
		}
	}
	apihttp.WriteJSON(w, http.StatusOK, out)
}

func redactPlacementSecretFields(p *cluster.Placement) {
	if p == nil {
		return
	}
	p.SecretRef = ""
	p.SecretVersion = 0
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
	w.WriteHeader(http.StatusNoContent)
}

// memberView extends cluster.Member with the FSM-derived drain bit so the
// members endpoint can show drained nodes without a second API call.
type memberView struct {
	cluster.Member
	Drained bool `json:"drained,omitempty"`
}

// clusterMembers returns the gossiped member list (observability only).
func (h *handlers) clusterMembers(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteJSON(w, http.StatusOK, map[string]any{"members": []any{}})
		return
	}
	members := c.Members()
	view := make([]memberView, 0, len(members))
	for _, m := range members {
		view = append(view, memberView{Member: m, Drained: c.IsNodeDrained(m.NodeID)})
	}
	apihttp.WriteJSON(w, http.StatusOK, map[string]any{"members": view})
}

// clusterRemoveMember explicitly removes a node from the raft configuration.
// It is the operator path for decommissioned control-plane members; worker
// role changes should use /cluster/nodes/{id}/drain before the infrastructure
// replacement, not this endpoint.
func (h *handlers) clusterRemoveMember(w http.ResponseWriter, r *http.Request) {
	if h.deps.Service == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "node id required")
		return
	}
	force := parseBoolQuery(r, "force")
	commitCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := c.RemoveMember(commitCtx, id, force); err != nil {
		switch {
		case errors.Is(err, cluster.ErrNotLeader):
			apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not leader")
		case errors.Is(err, cluster.ErrUnknownMember):
			apihttp.WriteError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, cluster.ErrMemberStillAlive), errors.Is(err, cluster.ErrLastVoter):
			apihttp.WriteError(w, http.StatusConflict, err.Error())
		default:
			apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseBoolQuery(r *http.Request, key string) bool {
	raw := strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key)))
	return raw == "1" || raw == "true" || raw == "yes"
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

// clusterDrainNode marks {id} as drained so future SelectPlacement decisions
// exclude it. Idempotent — calling against an already-drained node returns 204.
// Existing placements on the drained node continue to serve traffic; drain is
// an admission-only signal, not an eviction.
//
// Single-node mode returns 503 (no cluster to drain). Unknown node IDs are
// accepted so an operator can pre-drain a node that hasn't gossiped yet — the
// FSM stores the mark and any future join with that ID inherits it.
func (h *handlers) clusterDrainNode(w http.ResponseWriter, r *http.Request) {
	h.setNodeDrainState(w, r, true)
}

// clusterUncordonNode clears the drain mark for {id}. Idempotent.
func (h *handlers) clusterUncordonNode(w http.ResponseWriter, r *http.Request) {
	h.setNodeDrainState(w, r, false)
}

// clusterReclaimOrphanLocal is the manual false-positive recovery endpoint:
// it only claims an orphan when this node still has the sandbox in its local
// store, and the FSM records this node as the previous orphaned owner (or the
// row predates that metadata). Operators use this after confirming the node
// was marked dead by mistake.
func (h *handlers) clusterReclaimOrphanLocal(w http.ResponseWriter, r *http.Request) {
	if h.deps.Service == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "sandbox id required")
		return
	}
	p, ok := c.PlacementOf(id)
	if !ok {
		apihttp.WriteError(w, http.StatusNotFound, "no placement record")
		return
	}
	if !p.IsOrphaned() {
		apihttp.WriteError(w, http.StatusConflict, "placement is not orphaned")
		return
	}
	if p.OrphanedOwnerNodeID != "" && p.OrphanedOwnerNodeID != c.SelfNodeID() {
		apihttp.WriteError(w, http.StatusConflict, "orphaned placement belongs to previous owner "+p.OrphanedOwnerNodeID)
		return
	}
	if _, err := h.deps.Service.GetSandbox(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apihttp.WriteError(w, http.StatusConflict, "local sandbox row is missing; cannot reclaim locally")
			return
		}
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	commitCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := c.ClaimOrphan(commitCtx, id, nil, cluster.PlacementSecrets{}); err != nil {
		if errors.Is(err, cluster.ErrNotLeader) {
			apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not leader")
			return
		}
		if errors.Is(err, cluster.ErrUnknownSandbox) {
			apihttp.WriteError(w, http.StatusNotFound, "no placement record")
			return
		}
		if errors.Is(err, cluster.ErrOrphanClaimConflict) || errors.Is(err, cluster.ErrReservationConflict) {
			apihttp.WriteError(w, http.StatusConflict, err.Error())
			return
		}
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clusterDeleteOrphan force-deletes only the FSM placement for an orphan. It
// intentionally does not destroy any local sandbox because the owner is, by
// definition, absent from the cluster routing view.
func (h *handlers) clusterDeleteOrphan(w http.ResponseWriter, r *http.Request) {
	if h.deps.Service == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "sandbox id required")
		return
	}
	p, ok := c.PlacementOf(id)
	if !ok {
		apihttp.WriteError(w, http.StatusNotFound, "no placement record")
		return
	}
	if !p.IsOrphaned() {
		apihttp.WriteError(w, http.StatusConflict, "placement is not orphaned")
		return
	}
	commitCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Compare-delete the exact orphan observed above. A concurrent claim or ID
	// reuse must win instead of being erased by a second broad placement read.
	if err := c.DeletePlacementExact(commitCtx, id, p.OwnerNodeID, p.IncarnationID); err != nil {
		if errors.Is(err, cluster.ErrNotLeader) {
			apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not leader")
			return
		}
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clusterRetireNodeStorage records an operator's attestation that {id}'s
// storage has been destroyed, which is the ONLY thing besides an authenticated
// DELETE ACK that may discharge a pending secret-deletion obligation to that
// node. Membership disappearance and TTLs are deliberately not accepted: a
// decommissioned node may still hold a disk full of ciphertext.
//
// Operator-only, and refused while gossip still reports the node alive.
// Idempotent: re-attesting moves the fence forward.
func (h *handlers) clusterRetireNodeStorage(w http.ResponseWriter, r *http.Request) {
	if !clusterOperatorAccess(r) {
		apihttp.WriteError(w, http.StatusForbidden, "storage retirement is operator-only")
		return
	}
	if h.deps.Service == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "node id required")
		return
	}
	var body struct {
		Reason string `json:"reason,omitempty"`
	}
	if r.ContentLength > 0 {
		if err := apihttp.DecodeJSON(w, r, &body); err != nil {
			apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	actor := clusterOperatorActor(r)
	if err := h.deps.Service.RetireNodeStorage(r.Context(), id, actor, body.Reason); err != nil {
		if errors.Is(err, service.ErrNodeStorageRetirementAlive) {
			apihttp.WriteError(w, http.StatusConflict, err.Error())
			return
		}
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clusterInternalNodeStorageRetirements serves the replicated attestation set
// to obligation owners. A worker holds no FSM, and the outbox rows an
// attestation discharges live on the owner — never on the node the operator's
// request reached — so the set has to be readable from the server tier.
func (h *handlers) clusterInternalNodeStorageRetirements(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	peerID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	if strings.TrimSpace(peerID) == "" {
		apihttp.WriteError(w, http.StatusForbidden, "cluster: peer identity required")
		return
	}
	if r.URL.Query().Get("authoritative") == "true" {
		// Discharging a deletion obligation without an ACK is irreversible, so
		// it asks the leader explicitly: a follower whose FSM has not yet
		// applied an operator's revoke would otherwise authorize a removal the
		// operator has already withdrawn.
		if leader := c.Leader(); leader == "" || leader != c.SelfNodeID() {
			apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not leader")
			return
		}
	}
	reader, ok := c.(interface {
		NodeStorageRetirementsForPeer() cluster.NodeStorageRetirementsResponse
	})
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: node holds no placement state")
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, reader.NodeStorageRetirementsForPeer())
}

// clusterInternalArtifactCatalog serves the replicated template / JS-bundle
// metadata to nodes that hold no FSM, and accepts a node's published slice.
// The publisher is the mTLS-authenticated peer identity, never a body field:
// a node may only ever publish its own inventory.
func (h *handlers) clusterInternalArtifactCatalog(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	peerID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	if strings.TrimSpace(peerID) == "" {
		apihttp.WriteError(w, http.StatusForbidden, "cluster: peer identity required")
		return
	}
	var req cluster.ArtifactCatalogRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	reader, ok := c.(interface {
		ArtifactCatalogForPeer(cluster.ArtifactCatalogRequest) cluster.ArtifactCatalogPage
	})
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: node holds no placement state")
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, reader.ArtifactCatalogForPeer(req))
}

// clusterRevokeNodeStorageRetirement withdraws an attestation made in error.
// Obligations to that node become pending again. Idempotent.
func (h *handlers) clusterRevokeNodeStorageRetirement(w http.ResponseWriter, r *http.Request) {
	if !clusterOperatorAccess(r) {
		apihttp.WriteError(w, http.StatusForbidden, "storage retirement is operator-only")
		return
	}
	if h.deps.Service == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "node id required")
		return
	}
	if _, err := h.deps.Service.RevokeNodeStorageRetirement(r.Context(), id); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clusterListNodeStorageRetirements lets an operator see which nodes have an
// attestation on file, so "why is this obligation gone?" has an answer.
func (h *handlers) clusterListNodeStorageRetirements(w http.ResponseWriter, r *http.Request) {
	if !clusterOperatorAccess(r) {
		apihttp.WriteError(w, http.StatusForbidden, "storage retirement is operator-only")
		return
	}
	if h.deps.Service == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	recs, err := h.deps.Service.ListNodeStorageRetirements(r.Context())
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		out = append(out, map[string]any{
			"node_id":     rec.NodeID,
			"attested_at": rec.AttestedAt.UTC(),
			"actor":       rec.Actor,
			"reason":      rec.Reason,
		})
	}
	apihttp.WriteJSON(w, http.StatusOK, map[string]any{"retirements": out})
}

// clusterOperatorAccess gates the storage-retirement endpoints. An open-source
// build carries no control-plane access record, so the PAT that already
// guards /v1/cluster/** is the operator credential there.
func clusterOperatorAccess(r *http.Request) bool {
	access, ok := controlplane.AccessFromContext(r.Context())
	if !ok {
		return true
	}
	return access.Operator
}

func clusterOperatorActor(r *http.Request) string {
	if access, ok := controlplane.AccessFromContext(r.Context()); ok {
		if actor := strings.TrimSpace(access.Identity.ExternalID); actor != "" {
			return actor
		}
		if actor := strings.TrimSpace(access.Identity.OwnerRef); actor != "" {
			return actor
		}
	}
	return "operator"
}

func (h *handlers) setNodeDrainState(w http.ResponseWriter, r *http.Request, drained bool) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "node id required")
		return
	}
	if drained && id == c.SelfNodeID() {
		evacCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		if err := h.deps.Service.EvacuateLocalWasmSandboxesForDrain(evacCtx); err != nil {
			h.deps.Logger.Warn("wasm evacuate on drain failed", "node_id", id, "error", err)
		}
		cancel()
	}
	commitCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := c.SetNodeDrainState(commitCtx, id, drained); err != nil {
		if errors.Is(err, cluster.ErrNotLeader) {
			apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not leader")
			return
		}
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clusterInternalApply receives an encoded raft command from a follower and
// applies it on this node. The handler is gated by node-bound mTLS, live gossip
// membership, and the ordinary API auth layer. We respond 503 (and *not* a
// generic 5xx) when raft says we're not the leader so the forwarder treats it
// as a retry signal rather than a hard failure.
func (h *handlers) clusterInternalApply(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	const maxApplyBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxApplyBody+1))
	_ = r.Body.Close()
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if len(body) > maxApplyBody {
		apihttp.WriteError(w, http.StatusRequestEntityTooLarge, "raft command body exceeds 1 MiB")
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
		if errors.Is(err, cluster.ErrCreateBackpressure) {
			w.Header().Set("Retry-After", strconv.Itoa(cluster.CreateBackpressureRetryAfterSeconds))
			apihttp.WriteError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		if errors.Is(err, cluster.ErrCapacityExceeded) || errors.Is(err, cluster.ErrNoPlacementTarget) {
			w.Header().Set("Retry-After", strconv.Itoa(cluster.CapacityRetryAfterSeconds))
			apihttp.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) clusterInternalPlacement(w http.ResponseWriter, r *http.Request) {
	h.writeInternalPlacement(w, strings.TrimSpace(r.PathValue("id")))
}

func (h *handlers) clusterInternalPlacementByName(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.PathValue("name"))
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid encoded sandbox name")
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	id, owner, err := c.OwnerOfName(string(decoded))
	if err != nil {
		if errors.Is(err, cluster.ErrUnknownSandbox) {
			apihttp.WriteError(w, http.StatusNotFound, "no placement record")
			return
		}
		if errors.Is(err, cluster.ErrOrphaned) {
			if p, ok := c.PlacementOf(id); ok {
				redactPlacementSecretFields(&p)
				apihttp.WriteJSON(w, http.StatusOK, cluster.PlacementLookupResponse{SandboxID: id, Placement: p, Orphaned: true})
				return
			}
		}
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	p, ok := c.PlacementOf(id)
	if !ok {
		apihttp.WriteError(w, http.StatusNotFound, "no placement record")
		return
	}
	redactPlacementSecretFields(&p)
	apihttp.WriteJSON(w, http.StatusOK, cluster.PlacementLookupResponse{SandboxID: id, Placement: p, Owner: owner})
}

func (h *handlers) writeInternalPlacement(w http.ResponseWriter, id string) {
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "sandbox id required")
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	p, ok := c.PlacementOf(id)
	if !ok {
		apihttp.WriteError(w, http.StatusNotFound, "no placement record")
		return
	}
	redactPlacementSecretFields(&p)
	owner, err := c.OwnerOf(id)
	if err != nil {
		if errors.Is(err, cluster.ErrOrphaned) {
			apihttp.WriteJSON(w, http.StatusOK, cluster.PlacementLookupResponse{SandboxID: id, Placement: p, Orphaned: true})
			return
		}
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, cluster.PlacementLookupResponse{SandboxID: id, Placement: p, Owner: owner})
}

// clusterInternalVolume answers an agent-role node's volume metadata read from
// this server node's replicated FSM. Kinds: id, name, list, source. Writes never
// hit this path — they flow through the generic apply endpoint.
func (h *handlers) clusterInternalVolume(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	q := r.URL.Query()
	tenant := q.Get("tenant")
	switch q.Get("kind") {
	case "id":
		v, err := c.VolumeByID(r.Context(), tenant, q.Get("id"))
		if err != nil {
			apihttp.WriteError(w, http.StatusNotFound, "no such volume")
			return
		}
		apihttp.WriteJSON(w, http.StatusOK, cluster.VolumeQueryResponse{Volume: &v})
	case "name":
		v, err := c.VolumeByName(r.Context(), tenant, q.Get("name"))
		if err != nil {
			apihttp.WriteError(w, http.StatusNotFound, "no such volume")
			return
		}
		apihttp.WriteJSON(w, http.StatusOK, cluster.VolumeQueryResponse{Volume: &v})
	case "list":
		vols, err := c.VolumesForTenant(r.Context(), tenant)
		if err != nil {
			apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		apihttp.WriteJSON(w, http.StatusOK, cluster.VolumeQueryResponse{Volumes: vols})
	case "source":
		exists, err := c.VolumeExistsForSource(r.Context(), q.Get("source"))
		if err != nil {
			apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		apihttp.WriteJSON(w, http.StatusOK, cluster.VolumeQueryResponse{Exists: exists})
	case "attachment_count":
		count, err := c.VolumeAttachmentCount(r.Context(), tenant, q.Get("id"))
		if err != nil {
			apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		apihttp.WriteJSON(w, http.StatusOK, cluster.VolumeQueryResponse{Count: count})
	default:
		apihttp.WriteError(w, http.StatusBadRequest, "unknown volume query kind")
	}
}

func (h *handlers) clusterInternalPlacements(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	placements := c.Placements()
	for i := range placements {
		redactPlacementSecretFields(&placements[i])
	}
	apihttp.WriteJSON(w, http.StatusOK, placements)
}

func (h *handlers) clusterInternalPlacementsQuery(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	var filter cluster.PlacementShardFilter
	if err := apihttp.DecodeJSON(w, r, &filter); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	placements := c.PlacementsForShards(filter)
	for i := range placements {
		redactPlacementSecretFields(&placements[i])
	}
	apihttp.WriteJSON(w, http.StatusOK, placements)
}

func (h *handlers) clusterInternalPlacementsPage(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	var req cluster.PlacementPageRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	resp := c.PlacementPage(req)
	for i := range resp.Placements {
		redactPlacementSecretFields(&resp.Placements[i])
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// clusterInternalOwnedRecovery serves a worker its OWN failover-recreate
// placements. A dedicated worker has no FSM, so without this it can never
// learn that the dead-owner reconciler handed it a sandbox — the reassignment
// lands in Raft and nothing materializes it.
//
// The owner is the mTLS-authenticated peer identity, never a request field, so
// a node can only ask for its own work. The response deliberately keeps the
// spec and secret handle that the paged/point placement reads redact: the
// owner is the one party that must be able to rebuild and re-open them, and it
// is the same data a server-role owner reads from its local FSM.
func (h *handlers) clusterInternalOwnedRecovery(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	ownerID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	if strings.TrimSpace(ownerID) == "" {
		apihttp.WriteError(w, http.StatusForbidden, "cluster: peer identity required")
		return
	}
	var req cluster.OwnedRecoveryRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	owned, ok := c.(interface {
		OwnedRecoveryPlacements(string, int, string) cluster.OwnedRecoveryResponse
	})
	if !ok {
		// Only a server-role node holds the FSM this answer comes from.
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: node holds no placement state")
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, owned.OwnedRecoveryPlacements(ownerID, req.Limit, req.PageToken))
}

// clusterInternalReassignStuck lets the current owner of a placement ask the
// leader to move it after repeated local recreate failures. Target selection
// stays with the FSM, which is the only holder of drain state, pending
// reservations and capacity leases.
func (h *handlers) clusterInternalReassignStuck(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	requesterID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	if strings.TrimSpace(requesterID) == "" {
		apihttp.WriteError(w, http.StatusForbidden, "cluster: peer identity required")
		return
	}
	var req cluster.ReassignStuckRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	reassigner, ok := c.(interface {
		ReassignStuckPlacement(context.Context, string, string, string) error
	})
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: node holds no placement state")
		return
	}
	if err := reassigner.ReassignStuckPlacement(r.Context(), requesterID, req.SandboxID, req.IncarnationID); err != nil {
		switch {
		case errors.Is(err, cluster.ErrUnknownSandbox):
			apihttp.WriteError(w, http.StatusNotFound, "no placement record")
		case errors.Is(err, cluster.ErrStuckReassignNotOwner):
			apihttp.WriteError(w, http.StatusConflict, err.Error())
		default:
			apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *handlers) clusterInternalPlacementsByIDs(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	if r.URL.Query().Get("authoritative") == "true" {
		// Destructive lifecycle reconciliation asks the leader explicitly. A
		// follower's locally valid but lagging FSM cannot prove absence. Normal
		// failover-readiness batches remain distributable across server nodes.
		if leader := c.Leader(); leader == "" || leader != c.SelfNodeID() {
			apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not leader")
			return
		}
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.IDs) > cluster.MaxPlacementPageLimit {
		apihttp.WriteError(w, http.StatusBadRequest, "too many placement ids")
		return
	}
	out := c.PlacementsByIDs(req.IDs)
	for id, p := range out {
		minimizePlacementBatchRecord(&p)
		out[id] = p
	}
	apihttp.WriteJSON(w, http.StatusOK, out)
}

// minimizePlacementBatchRecord keeps the 5k-ID internal batch comfortably
// bounded even when each placement carries a maximum-sized recovery spec and
// many routes. Its only consumers are readiness and secret-lifecycle code.
func minimizePlacementBatchRecord(p *cluster.Placement) {
	if p == nil {
		return
	}
	p.OwnerAPIURL = ""
	p.OwnerDataPlaneHost = ""
	p.RecoveryRef = ""
	p.Spec = nil
	p.SecretRef = ""
	p.SecretVersion = 0
	p.OwnerRef = ""
	p.AuditNodeIDs = nil
	p.AuditNodesTruncated = false
	p.ExposedPorts = nil
	p.ExposedPortRoutes = nil
	p.CustomHostnames = nil
}

func (h *handlers) clusterInternalAuditACL(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	acl, ok, err := c.AuditACLForSandbox(r.Context(), r.PathValue("id"), r.URL.Query().Get("incarnation_id"))
	if err != nil {
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if acl.SandboxID == "" {
		acl.SandboxID = r.PathValue("id")
	}
	apihttp.WriteJSON(w, http.StatusOK, cluster.AuditACLResponse{
		ACL:    acl,
		Exists: ok,
	})
}

// clusterRecoveryBlobStore is the read-only surface behind the recovery GET
// endpoint. It exists so a snapshot-joined voter can fetch payloads its
// snapshot references but its local store lacks (fetch-on-miss) — the only
// remaining remote-recovery traffic now that payloads ride inline in raft
// commands. There is deliberately no PUT half: nothing pushes blobs anymore.
type clusterRecoveryBlobStore interface {
	RecoveryBlob(context.Context, string) (cluster.RecoveryBlob, bool, error)
}

func (h *handlers) clusterInternalRecoveryGet(w http.ResponseWriter, r *http.Request) {
	ref := strings.TrimSpace(r.PathValue("ref"))
	if ref == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "recovery ref required")
		return
	}
	c, ok := h.deps.Service.Cluster().(clusterRecoveryBlobStore)
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: recovery store unavailable on this node")
		return
	}
	blob, found, err := c.RecoveryBlob(r.Context(), ref)
	if err != nil {
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		apihttp.WriteError(w, http.StatusNotFound, "recovery blob not found")
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, blob)
}

func (h *handlers) clusterInternalSelectPlacement(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	var req cluster.SelectPlacementRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// A request carrying a sandbox id wants the bounded recipient set chosen
	// here, where the membership already lives. Serializing every eligible
	// worker back to the caller so IT can pick two of them made each create's
	// response scale with the fleet; only an agent on the previous build
	// still needs that shape.
	if sandboxID := strings.TrimSpace(req.SandboxID); sandboxID != "" {
		target, recipients, err := c.SelectPlacementForCreate(req.Request, sandboxID, req.RecipientBackups)
		if err != nil {
			apihttp.WriteJSON(w, http.StatusOK, cluster.SelectPlacementResponse{Error: err.Error()})
			return
		}
		apihttp.WriteJSON(w, http.StatusOK, cluster.SelectPlacementResponse{Target: target, Recipients: recipients})
		return
	}
	// Target-only callers (build, template, JS bundle, local-image routing)
	// get the chosen node and nothing else. Serializing every eligible worker
	// for a one-field answer is the same O(fleet) response shape the
	// sandbox-id path already removed from creates.
	if req.TargetOnly {
		target, err := c.SelectPlacement(req.Request)
		if err != nil {
			apihttp.WriteJSON(w, http.StatusOK, cluster.SelectPlacementResponse{Error: err.Error()})
			return
		}
		apihttp.WriteJSON(w, http.StatusOK, cluster.SelectPlacementResponse{Target: target})
		return
	}
	target, candidates, err := c.SelectPlacementWithCandidates(req.Request)
	if err != nil {
		apihttp.WriteJSON(w, http.StatusOK, cluster.SelectPlacementResponse{Error: err.Error()})
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, cluster.SelectPlacementResponse{Target: target, Candidates: candidates})
}

// A public JSON create is capped at 1 MiB. Encrypting its credentials and then
// embedding the envelope's bytes in SecretBlob applies base64 expansion twice,
// so the peer wire representation can legitimately exceed that public cap.
// Four MiB covers the worst-case expansion while retaining a hard memory bound.
const clusterSecretBlobMaxBodyBytes = 4 << 20

// clusterInternalSecretPut upserts a peer-fanout sealed secret blob into the
// local store. Idempotent (store UPSERT). No-op semantics under Noop cluster
// still accept the write so a misrouted POST doesn't 5xx — the row is local.
func (h *handlers) clusterInternalSecretPut(w http.ResponseWriter, r *http.Request) {
	var blob secrets.SecretBlob
	if err := apihttp.DecodeJSONLimit(w, r, &blob, clusterSecretBlobMaxBodyBytes); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(blob.Ref) == "" || strings.TrimSpace(blob.SandboxID) == "" || len(blob.SealedPayload) == 0 {
		apihttp.WriteError(w, http.StatusBadRequest, "ref, sandbox_id, and sealed_payload are required")
		return
	}
	originatorNodeID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	if err := h.deps.Service.UpsertClusterSecretBlob(r.Context(), blob, originatorNodeID); err != nil {
		if errors.Is(err, service.ErrClusterSecretPlacementUnavailable) {
			apihttp.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		if errors.Is(err, service.ErrClusterSecretOriginatorDenied) {
			apihttp.WriteError(w, http.StatusForbidden, err.Error())
			return
		}
		if errors.Is(err, service.ErrInvalidClusterSecretBlob) {
			apihttp.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, secrets.ErrRecipientDenied) {
			apihttp.WriteError(w, http.StatusForbidden, err.Error())
			return
		}
		// Stale / conflicting seal must not look like an ACK to the originator.
		if errors.Is(err, store.ErrClusterSecretStaleGeneration) || errors.Is(err, store.ErrClusterSecretPayloadConflict) {
			apihttp.WriteError(w, http.StatusConflict, err.Error())
			return
		}
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) clusterInternalSecretDelete(w http.ResponseWriter, r *http.Request) {
	sandboxID := strings.TrimSpace(r.PathValue("sandboxID"))
	if sandboxID == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "sandbox id required")
		return
	}
	rawGeneration := strings.TrimSpace(r.URL.Query().Get("generation"))
	generation, err := strconv.ParseInt(rawGeneration, 10, 64)
	if rawGeneration == "" || err != nil || generation <= 0 {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid generation")
		return
	}
	incarnationID := strings.TrimSpace(r.URL.Query().Get("incarnation_id"))
	if incarnationID == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "incarnation_id required")
		return
	}
	// Local delete only — this IS the peer delete-fanout receiver. Do not
	// re-fanout from here (would loop).
	originatorNodeID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	if err := h.deps.Service.DeleteClusterSecretsLocal(r.Context(), sandboxID, incarnationID, generation, originatorNodeID); err != nil {
		if errors.Is(err, service.ErrClusterSecretOriginatorDenied) {
			apihttp.WriteError(w, http.StatusForbidden, err.Error())
			return
		}
		if errors.Is(err, service.ErrClusterSecretPlacementUnavailable) {
			apihttp.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		if errors.Is(err, store.ErrClusterSecretDeleteGenerationTooNew) {
			apihttp.WriteError(w, http.StatusConflict, err.Error())
			return
		}
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) clusterInternalSecretHead(w http.ResponseWriter, r *http.Request) {
	sandboxID := strings.TrimSpace(r.PathValue("sandboxID"))
	if sandboxID == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "sandbox id required")
		return
	}
	rawGeneration := strings.TrimSpace(r.URL.Query().Get("min_generation"))
	minGen, err := strconv.ParseInt(rawGeneration, 10, 64)
	if rawGeneration == "" || err != nil || minGen <= 0 {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid min_generation")
		return
	}
	incarnationID := strings.TrimSpace(r.URL.Query().Get("incarnation_id"))
	if incarnationID == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "incarnation id required")
		return
	}
	ok, err := h.deps.Service.HasLocalSealedSecretGeneration(r.Context(), sandboxID, incarnationID, minGen)
	if err != nil {
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) clusterInternalDrainState(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, cluster.DrainStateResponse{Drained: c.IsNodeDrained(strings.TrimSpace(r.PathValue("id")))})
}

// clusterWasmMigrate orchestrates §4.8.1 checkpoint export from the current
// owner and import on target_node_id.
func (h *handlers) clusterWasmMigrate(w http.ResponseWriter, r *http.Request) {
	if h.deps.Service == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	if h.deps.Service.Cluster() == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	var req service.WasmMigrateRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	resp, err := h.deps.Service.MigrateWasmSandboxToNode(r.Context(), req.SandboxID, req.TargetNodeID)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

func (h *handlers) clusterInternalWasmMigrateExport(w http.ResponseWriter, r *http.Request) {
	if h.deps.Service == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "sandbox id required")
		return
	}
	owner, err := c.OwnerOf(id)
	if err != nil {
		if errors.Is(err, cluster.ErrUnknownSandbox) {
			apihttp.WriteError(w, http.StatusNotFound, "no placement record")
			return
		}
		if errors.Is(err, cluster.ErrOrphaned) {
			apihttp.WriteError(w, http.StatusConflict, "placement is orphaned")
			return
		}
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	if !owner.IsSelf {
		apihttp.WriteError(w, http.StatusConflict, "sandbox is not owned by this node")
		return
	}
	var buf bytes.Buffer
	cloneGen, err := h.deps.Service.ExportWasmMigration(r.Context(), id, &buf)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.Header().Set(cluster.WasmMigrateCloneGenHeader, cloneGen)
	w.Header().Set("Content-Type", cluster.WasmMigrateTarMediaType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

func (h *handlers) clusterInternalWasmMigrateImport(w http.ResponseWriter, r *http.Request) {
	if h.deps.Service == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "sandbox id required")
		return
	}
	cloneGen := strings.TrimSpace(r.Header.Get(cluster.WasmMigrateCloneGenHeader))
	if err := h.deps.Service.ImportWasmMigration(r.Context(), id, cloneGen, r.Body); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// placementOwner is the snake_case JSON view of cluster.OwnerInfo. We don't
// rely on OwnerInfo's default marshaling here because its struct fields have
// no json tags (PascalCase keys leak), and unifying the response shape lets
// operators script against a single contract.
type placementOwner struct {
	NodeID      string `json:"node_id"`
	APIURL      string `json:"api_url"`
	InternalURL string `json:"internal_url,omitempty"`
	IsSelf      bool   `json:"is_self"`
}

// placementResponse is the enriched /v1/cluster/placements/{id} payload. It
// fuses three FSM reads (owner, exposed routes, placement.Version) with this
// node's ingress reconciler progress so operators can answer "where should
// this sandbox's traffic go, and is the local node ready to serve it?" in
// one request. Converged is the headline signal: false means a TCP client
// dialing the cluster-stable host port via this node may hit "connection
// refused" until the next reconcile tick lands.
type placementResponse struct {
	Owner                placementOwner                      `json:"owner"`
	Orphaned             bool                                `json:"orphaned"`
	OwnerState           cluster.PlacementOwnerState         `json:"owner_state,omitempty"`
	OrphanedOwnerNodeID  string                              `json:"orphaned_owner_node_id,omitempty"`
	OrphanedUnix         int64                               `json:"orphaned_unix,omitempty"`
	ExposedPorts         map[string]cluster.ExposedPortRoute `json:"exposed_ports,omitempty"`
	PlacementVersion     uint64                              `json:"placement_version"`
	NodeInstalledVersion uint64                              `json:"node_installed_version"`
	Converged            bool                                `json:"converged"`
}

// clusterPlacement returns the placement record for one sandbox plus this
// node's per-sandbox convergence status (B6: operators need to spot TCP
// ingress that hasn't propagated to a given node without grepping logs).
// Owner-side requests are trivially converged: exposePort installs the local
// Caddy route synchronously. Non-owner ingress nodes compare the per-
// placement Version against the reconciler's installed-version high-water
// mark — a stale lag flags "client traffic via this node may miss the route".
func (h *handlers) clusterPlacement(w http.ResponseWriter, r *http.Request) {
	c := h.deps.Service.Cluster()
	if c == nil {
		apihttp.WriteError(w, http.StatusNotFound, "cluster not enabled")
		return
	}
	id := r.PathValue("id")
	owner, ownerErr := c.OwnerOf(id)
	if ownerErr != nil && !errors.Is(ownerErr, cluster.ErrOrphaned) {
		if errors.Is(ownerErr, cluster.ErrUnknownSandbox) {
			apihttp.WriteError(w, http.StatusNotFound, "no placement record")
			return
		}
		apihttp.WriteError(w, http.StatusInternalServerError, ownerErr.Error())
		return
	}

	resp := placementResponse{
		NodeInstalledVersion: service.IngressInstalledVersion(),
	}
	if errors.Is(ownerErr, cluster.ErrOrphaned) {
		resp.Orphaned = true
	} else {
		resp.Owner = placementOwner{
			NodeID:      owner.NodeID,
			APIURL:      owner.APIURL,
			InternalURL: owner.InternalURL,
			IsSelf:      owner.IsSelf,
		}
	}

	// PlacementOf returns the full record including per-placement Version and
	// the replicated port routes. Use string keys for the map so operators
	// reading JSON via jq don't trip over numeric-key quirks in some clients.
	if placement, ok := c.PlacementOf(id); ok {
		resp.PlacementVersion = placement.Version
		resp.OwnerState = placement.OwnerState
		resp.OrphanedOwnerNodeID = placement.OrphanedOwnerNodeID
		resp.OrphanedUnix = placement.OrphanedUnix
		if len(placement.ExposedPortRoutes) > 0 {
			resp.ExposedPorts = make(map[string]cluster.ExposedPortRoute, len(placement.ExposedPortRoutes))
			for port, route := range placement.ExposedPortRoutes {
				resp.ExposedPorts[strconv.Itoa(port)] = route
			}
		}
	}

	// Convergence semantics: owner-self is always converged (exposePort
	// installs Caddy synchronously on the owner path). For non-owner nodes,
	// we're converged once the reconciler has installed routes for an FSM
	// version >= this placement's Version. A zero PlacementVersion (no FSM
	// record, e.g. mid-eviction or pre-cluster sandbox) collapses to "owner
	// drives the answer" — there's nothing pending to install.
	resp.Converged = resp.Owner.IsSelf || resp.PlacementVersion == 0 ||
		resp.NodeInstalledVersion >= resp.PlacementVersion

	apihttp.WriteJSON(w, http.StatusOK, resp)
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

// capacityRequestFromCreate builds the placement-scoring request for a create.
// The mapping lives in pkg/api/clustercreate so native v1 and the facades score
// a create identically; this stays as the v1-local name its tests use.
func capacityRequestFromCreate(req models.CreateSandboxRequest) capacity.Request {
	return clustercreate.CapacityRequestFromCreate(req)
}

func diskGBForCapacity(base int, runtimeName string, overlaySizeGB int) int {
	if runtimeName == models.RuntimeFirecracker && overlaySizeGB > 0 {
		return base + overlaySizeGB
	}
	return base
}

func normalizeCreateRuntimeForPlacement(req *models.CreateSandboxRequest) error {
	if req == nil {
		return nil
	}
	chosenRuntime, err := models.ValidRuntime(strings.TrimSpace(req.Runtime))
	if err != nil {
		return err
	}
	req.TemplateID = strings.TrimSpace(req.TemplateID)
	if req.TemplateID != "" {
		if chosenRuntime != "" && chosenRuntime != models.RuntimeFirecracker {
			return fmt.Errorf("template_id requires runtime %q (got %q)",
				models.RuntimeFirecracker, chosenRuntime)
		}
		chosenRuntime = models.RuntimeFirecracker
	}
	req.Runtime = chosenRuntime
	return nil
}

package runloop

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/clusterlist"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	// devboxWaitMax is Runloop's cap on a devbox wait_for_status hold.
	devboxWaitMax = 30 * time.Second
	// statusPollInterval paces wait_for_status re-reads of the sandbox row
	// while no in-flight create can signal the change directly.
	statusPollInterval = 250 * time.Millisecond

	defaultListLimit = 20

	// tombstoneTTL / maxTombstones bound the memory of devboxes this node
	// shut down. A destroyed sandbox leaves no row, so without them a
	// shutdown whose response was lost would 404 on the SDK's retry.
	tombstoneTTL  = 10 * time.Minute
	maxTombstones = 4096
)

func (h *handlers) getDevbox(w http.ResponseWriter, r *http.Request, id string) {
	view, _, err := h.currentView(r.Context(), id)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// currentView resolves a devbox id to its view from the sandbox row, an
// in-flight or recently failed create, or a shutdown tombstone. transitional
// reports a state that will change on its own (only provisioning: every
// other native transition finishes inside the request that started it).
func (h *handlers) currentView(ctx context.Context, id string) (devboxView, bool, error) {
	sandbox, err := h.deps.Service.GetSandbox(ctx, id)
	if err == nil {
		view, err := h.devboxView(ctx, sandbox)
		return view, view.Status == statusProvisioning, err
	}
	if !errors.Is(err, store.ErrNotFound) {
		return devboxView{}, false, err
	}
	if f, ok := h.creates.get(id); ok && visibleTo(ctx, f.meta.owner) {
		if !f.isDone() {
			return provisioningView(f.id, f.started, f.meta.blob, f.meta.metadata), true, nil
		}
		if f.err != nil {
			view := provisioningView(f.id, f.started, f.meta.blob, f.meta.metadata)
			view.Status = statusFailure
			view.FailureReason = stringPtr("execution_failed")
			return view, false, nil
		}
	}
	if view, ok := h.shutdowns.get(ctx, id); ok {
		return view, false, nil
	}
	return devboxView{}, false, store.ErrNotFound
}

// visibleTo applies the service's owner scoping to state the facade keeps
// in memory: a user token sees only its own account's entries, while
// operator and internal callers (owner "") see everything — the same rule
// scopedGet enforces on sandbox rows.
func visibleTo(ctx context.Context, owner string) bool {
	caller := service.OwnerRefForCreate(ctx)
	return caller == "" || caller == owner
}

func (h *handlers) devboxView(ctx context.Context, sandbox *models.Sandbox) (devboxView, error) {
	state, err := h.deps.Service.GetCompatState(ctx, sandbox.ID, models.FacadeRunloop)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return devboxView{}, err
	}
	blob, err := decodeDevboxBlob(state)
	if err != nil {
		return devboxView{}, err
	}
	return newDevboxView(sandbox, blob), nil
}

func (h *handlers) writeDevbox(w http.ResponseWriter, r *http.Request, sandbox *models.Sandbox) {
	view, err := h.devboxView(r.Context(), sandbox)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// waitForDevboxStatus is a real long-poll: both SDKs re-issue it with no
// sleep on 408, so answering 200 with a status the caller did not ask for
// would spin them in a tight loop. It returns early only when the devbox
// can no longer reach a requested status on its own.
func (h *handlers) waitForDevboxStatus(w http.ResponseWriter, r *http.Request, id string) {
	var req waitForStatusRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.Statuses) == 0 {
		WriteError(w, http.StatusBadRequest, "statuses is required")
		return
	}
	want := make(map[string]struct{}, len(req.Statuses))
	for _, status := range req.Statuses {
		want[status] = struct{}{}
	}
	deadline := time.Now().Add(holdFor(req.TimeoutSeconds, devboxWaitMax))
	for {
		view, transitional, err := h.currentView(r.Context(), id)
		if err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
		if _, ok := want[view.Status]; ok || !transitional {
			writeJSON(w, http.StatusOK, view)
			return
		}
		if !time.Now().Before(deadline) {
			writeWaitTimeout(w)
			return
		}
		var signal <-chan struct{}
		if f, ok := h.creates.get(id); ok {
			signal = f.done
		}
		if !sleepUntil(r.Context(), deadline, statusPollInterval, signal) {
			return
		}
	}
}

// holdFor clamps a caller-supplied long-poll timeout (a float in seconds:
// Python sends e.g. 29.98) to the facade's maximum.
func holdFor(timeoutSeconds *float64, max time.Duration) time.Duration {
	if timeoutSeconds == nil || *timeoutSeconds <= 0 {
		return max
	}
	if d := time.Duration(*timeoutSeconds * float64(time.Second)); d < max {
		return d
	}
	return max
}

// writeWaitTimeout answers an expired long-poll. retry-after-ms keeps the
// SDK paths that do retry 408 (Python's Execution.result()) from sleeping
// through their 1-16s backoff before polling again.
func writeWaitTimeout(w http.ResponseWriter) {
	w.Header().Set("retry-after-ms", "1")
	WriteError(w, http.StatusRequestTimeout, "timed out waiting for status")
}

// sleepUntil waits for the next poll, a signal, or the deadline. It
// reports false when the request context ended.
func sleepUntil(ctx context.Context, deadline time.Time, interval time.Duration, signal <-chan struct{}) bool {
	// A deadline already past makes the timer fire at once.
	wait := min(time.Until(deadline), interval)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-signal:
	case <-timer.C:
	}
	return true
}

func (h *handlers) listDevboxes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := defaultListLimit
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			WriteError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}
	if limit > clusterlist.MaxPageLimit {
		limit = clusterlist.MaxPageLimit
	}
	startingAfter := strings.TrimSpace(q.Get("starting_after"))
	statusFilter := strings.TrimSpace(q.Get("status"))
	peerIDs, err := clusterlist.PeerWantIDs(r)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	sandboxes, err := h.deps.Service.ListSandboxes(r.Context(), nil)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	states, err := h.deps.Service.ListCompatState(r.Context(), models.FacadeRunloop)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	local := make([]devboxView, 0, len(sandboxes))
	for _, sandbox := range sandboxes {
		if peerIDs != nil {
			if _, ok := peerIDs[sandbox.ID]; !ok {
				continue
			}
		}
		var blob devboxBlob
		if state, ok := states[sandbox.ID]; ok {
			if blob, err = decodeDevboxBlob(&state); err != nil {
				writeStoreAwareError(h.deps.Logger, w, err)
				return
			}
		}
		view := newDevboxView(sandbox, blob)
		if statusFilter != "" && view.Status != statusFilter {
			continue
		}
		local = append(local, view)
	}

	// A peer hop answers the ingress merge with a bare array.
	if r.Header.Get("X-Cluster-Forwarded") == "1" {
		writeJSON(w, http.StatusOK, local)
		return
	}
	if c := h.clusterClient(); c != nil {
		h.listClusterDevboxes(w, r, c, local, limit, startingAfter)
		return
	}

	sortViews(local)
	total := len(local)
	page := make([]devboxView, 0, limit)
	for _, view := range local {
		if view.ID <= startingAfter {
			continue
		}
		page = append(page, view)
	}
	hasMore := len(page) > limit
	if hasMore {
		page = page[:limit]
	}
	resp := listDevboxesResponse{Devboxes: page, HasMore: hasMore}
	if q.Get("include_total_count") != "false" {
		resp.TotalCount = &total
	}
	writeJSON(w, http.StatusOK, resp)
}

// listClusterDevboxes pages the cluster's placement index, which is
// ordered by sandbox id with the last id as its cursor — exactly
// Runloop's starting_after — and merges the owners' views for that page.
// total_count is left out: counting would mean walking every placement.
func (h *handlers) listClusterDevboxes(w http.ResponseWriter, r *http.Request, c cluster.Client, local []devboxView, limit int, startingAfter string) {
	ownerRef := clusterlist.OwnerRefFromContext(r.Context())
	peers, placements, next, viewReady, missing := clusterlist.SelectPeersForPage(c, ownerRef, startingAfter, limit)
	if !viewReady {
		w.Header().Set("Retry-After", "1")
		WriteError(w, http.StatusServiceUnavailable, "placement view is not ready")
		return
	}
	want := clusterlist.PlacementWantIDs(placements)
	if placements == nil {
		// Cold index on a small fleet: SelectPeersForPage fanned out to
		// every owner, so page by id here instead.
		want = nil
	}
	items, cov := clusterlist.MergeJSON(r.Context(), peers, local, func(v devboxView) string { return v.ID }, clusterlist.Options{
		OwnerRef:   ownerRef,
		AuthHeader: r.Header.Get("Authorization"),
		RawQuery:   stripListPaging(r.URL.Query()),
		Path:       devboxesPath,
		Transport:  clusterlist.TransportFromCluster(c),
		SelfNodeID: c.SelfNodeID(),
		WantIDs:    want,
		Warn: func(msg, peer string, peerErr error) {
			if h.deps.Logger != nil {
				h.deps.Logger.Warn(msg, "peer", peer, "error", peerErr)
			}
		},
	})
	if len(missing) > 0 {
		cov.Missing = append(cov.Missing, missing...)
		cov.Partial = true
	}
	clusterlist.WriteCoverageHeaders(w, cov, next)
	sortViews(items)
	page := make([]devboxView, 0, len(items))
	for _, view := range items {
		if view.ID > startingAfter {
			page = append(page, view)
		}
	}
	hasMore := next != ""
	if want == nil && len(page) > limit {
		page, hasMore = page[:limit], true
	}
	writeJSON(w, http.StatusOK, listDevboxesResponse{Devboxes: page, HasMore: hasMore})
}

// clusterClient returns the cluster client when this node is a real
// cluster member; nil in single-node mode.
func (h *handlers) clusterClient() cluster.Client {
	c := h.deps.Service.Cluster()
	switch c.(type) {
	case nil, *cluster.Noop:
		return nil
	}
	return c
}

// stripListPaging drops the paging keys so each peer returns its whole
// slice of the placement page; the ingress pages once after the merge.
func stripListPaging(query url.Values) string {
	vals := url.Values{}
	for key, values := range query {
		switch key {
		case "limit", "starting_after", "include_total_count":
		default:
			vals[key] = values
		}
	}
	return clusterlist.StripFacadePagination(vals.Encode())
}

func sortViews(views []devboxView) {
	sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })
}

func (h *handlers) updateDevbox(w http.ResponseWriter, r *http.Request, id string) {
	var req updateDevboxRequest
	if !decodeBody(w, r, &req) {
		return
	}
	sandbox, err := h.deps.Service.GetSandbox(r.Context(), id)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	if req.Metadata != nil {
		if err := h.deps.Service.UpdateTags(r.Context(), id, req.Metadata); err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
	}
	if req.Name != nil {
		// The Runloop name lives in the facade blob, not the native name
		// column: Runloop names need not be unique, native names must be.
		state, err := h.deps.Service.GetCompatState(r.Context(), id, models.FacadeRunloop)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
		blob, err := decodeDevboxBlob(state)
		if err == nil {
			blob.Name = strings.TrimSpace(*req.Name)
			var stateJSON string
			if stateJSON, err = encodeDevboxBlob(blob); err == nil {
				err = h.deps.Service.UpsertCompatState(r.Context(), id, models.FacadeRunloop, stateJSON)
			}
		}
		if err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
	}
	if sandbox, err = h.deps.Service.GetSandbox(r.Context(), id); err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	h.writeDevbox(w, r, sandbox)
}

// shutdownDevbox destroys the sandbox: a Runloop shutdown is terminal, and
// keeping the stopped container around would hold its disk forever.
func (h *handlers) shutdownDevbox(w http.ResponseWriter, r *http.Request, id string) {
	sandbox, err := h.deps.Service.GetSandbox(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		if view, ok := h.shutdowns.get(r.Context(), id); ok {
			writeJSON(w, http.StatusOK, view)
			return
		}
	}
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	view, err := h.devboxView(r.Context(), sandbox)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	if err := h.deps.Service.DestroySandbox(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	end := time.Now().UnixMilli()
	view.Status = statusShutdown
	view.EndTimeMs = &end
	view.ShutdownReason = stringPtr("api_shutdown")
	view.FailureReason = nil
	h.shutdowns.put(id, sandbox.OwnerRef, view)
	h.homes.Delete(id)
	h.execs.forgetDevbox(id)
	writeJSON(w, http.StatusOK, view)
}

func (h *handlers) suspendDevbox(w http.ResponseWriter, r *http.Request, id string) {
	sandbox, err := h.deps.Service.GetSandbox(r.Context(), id)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	switch sandbox.Status {
	case models.SandboxStatusStopped:
		// Already suspended: a retried suspend is a no-op.
	case models.SandboxStatusStarted:
		if sandbox, err = h.deps.Service.StopSandbox(r.Context(), id); err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
	default:
		WriteError(w, http.StatusConflict, "devbox is not running")
		return
	}
	h.writeDevbox(w, r, sandbox)
}

func (h *handlers) resumeDevbox(w http.ResponseWriter, r *http.Request, id string) {
	sandbox, err := h.deps.Service.GetSandbox(r.Context(), id)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	switch sandbox.Status {
	case models.SandboxStatusStarted:
		// Already running: a retried resume is a no-op.
	case models.SandboxStatusStopped:
		if sandbox, err = h.deps.Service.StartSandbox(r.Context(), id); err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
	default:
		WriteError(w, http.StatusConflict, "devbox is not suspended")
		return
	}
	h.writeDevbox(w, r, sandbox)
}

// keepAlive resets the idle clock that after_idle policies count from.
func (h *handlers) keepAlive(w http.ResponseWriter, r *http.Request, id string) {
	if _, err := h.deps.Service.GetSandbox(r.Context(), id); err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	if err := h.deps.Service.TouchSandbox(r.Context(), id); err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

// tombstones remembers recently shut-down devboxes so a retried shutdown
// (or a wait for `shutdown`) answers with the terminal view.
type tombstones struct {
	mu    sync.Mutex
	views map[string]tombstone
}

type tombstone struct {
	owner string
	view  devboxView
	at    time.Time
}

func newTombstones() *tombstones {
	return &tombstones{views: make(map[string]tombstone)}
}

func (t *tombstones) put(id, owner string, view devboxView) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if len(t.views) >= maxTombstones {
		for key, entry := range t.views {
			if now.Sub(entry.at) > tombstoneTTL {
				delete(t.views, key)
			}
		}
		if len(t.views) >= maxTombstones {
			// Still full of live entries: drop the oldest.
			oldest := ""
			for key, entry := range t.views {
				if oldest == "" || entry.at.Before(t.views[oldest].at) {
					oldest = key
				}
			}
			delete(t.views, oldest)
		}
	}
	t.views[id] = tombstone{owner: owner, view: view, at: now}
}

func (t *tombstones) get(ctx context.Context, id string) (devboxView, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.views[id]
	if !ok || !visibleTo(ctx, entry.owner) {
		return devboxView{}, false
	}
	if time.Since(entry.at) > tombstoneTTL {
		delete(t.views, id)
		return devboxView{}, false
	}
	return entry.view, true
}

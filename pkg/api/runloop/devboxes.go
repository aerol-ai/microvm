package runloop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
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
	if view, ok := h.shutdownTombstone(ctx, id); ok {
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
		h.listClusterDevboxes(w, r, c, local, limit, startingAfter, statusFilter != "")
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

// maxStatusScanPlacements bounds how many placements one filtered cluster
// list may walk looking for its first match (see listClusterDevboxes). A
// variable only so tests can lower it.
var maxStatusScanPlacements = 10000

// listClusterDevboxes pages the cluster's placement index, which is
// ordered by sandbox id with the last id as its cursor — exactly
// Runloop's starting_after — and merges the owners' views for that page.
// total_count is left out: counting would mean walking every placement.
//
// Two rules keep the SDK's cursor paging from silently dropping devboxes:
//
//   - The SDKs take the next cursor from the last devbox returned and stop
//     on an empty page, whatever has_more says. A status filter can empty a
//     placement page that is followed by matches, so a filtered list keeps
//     walking placement pages until it has a match (or a full page), and a
//     page it returns always ends in a real devbox. If maxStatusScanPlacements
//     pass without one match it fails rather than answer "nothing more".
//   - A page whose owner could not be asked is not answered as if it were
//     complete: the request fails with a retryable 503 instead.
func (h *handlers) listClusterDevboxes(w http.ResponseWriter, r *http.Request, c cluster.Client, local []devboxView, limit int, startingAfter string, filtered bool) {
	ownerRef := clusterlist.OwnerRefFromContext(r.Context())
	page := make([]devboxView, 0, limit)
	cursor, next := startingAfter, ""
	scanned := 0
	coverage := clusterlist.Coverage{PlacementViewReady: true}
	for {
		peers, placements, pageNext, viewReady, missing := clusterlist.SelectPeersForPage(c, ownerRef, cursor, limit)
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
		if cov.Partial {
			clusterlist.WriteCoverageHeaders(w, cov, pageNext)
			w.Header().Set("Retry-After", "2")
			WriteError(w, http.StatusServiceUnavailable, "devbox list is incomplete: some owner nodes did not answer")
			return
		}
		coverage.Answered = append(coverage.Answered, cov.Answered...)
		for _, view := range items {
			if view.ID > cursor {
				page = append(page, view)
			}
		}
		next = pageNext
		scanned += len(placements)
		if want == nil || !filtered || len(page) > 0 || next == "" {
			break
		}
		if scanned >= maxStatusScanPlacements {
			w.Header().Set("x-should-retry", "false")
			WriteError(w, http.StatusServiceUnavailable, fmt.Sprintf("no devbox matching the status filter among the next %d; page with a later starting_after or list without the filter", scanned))
			return
		}
		cursor = next
	}
	clusterlist.WriteCoverageHeaders(w, coverage, next)
	sortViews(page)
	hasMore := next != ""
	if len(page) > limit {
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
		if view, ok := h.shutdownTombstone(r.Context(), id); ok {
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
	if err := h.putShutdownTombstone(r.Context(), id, sandbox.OwnerRef, view); err != nil {
		// The sandbox is already gone; a tombstone write failure only costs a
		// retried shutdown its replay (it would 404 instead of 200). Log and
		// still return the terminal view for this call.
		if h.deps.Logger != nil {
			h.deps.Logger.Warn("record shutdown tombstone failed", "devbox", id, "error", err)
		}
	}
	h.homes.forget(id)
	h.execs.forgetDevbox(id)
	writeJSON(w, http.StatusOK, view)
}

func (h *handlers) suspendDevbox(w http.ResponseWriter, r *http.Request, id string) {
	// The "running" precondition and the stop are one locked transition in the
	// service (D7); ErrSandboxNotRunning classifies to a 409 reworded here.
	sandbox, err := h.deps.Service.PauseSandbox(r.Context(), id)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	h.writeDevbox(w, r, sandbox)
}

func (h *handlers) resumeDevbox(w http.ResponseWriter, r *http.Request, id string) {
	// The "suspended" precondition and the start are one locked transition in
	// the service (D7); ErrSandboxNotResumable classifies to a 409 reworded here.
	sandbox, err := h.deps.Service.ResumeSandbox(r.Context(), id)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
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

// putShutdownTombstone durably records the terminal view of a devbox this
// handler just shut down, so a retried shutdown (or a GET/wait that races the
// delete) answers with it instead of 404 even across a restart (D6). The
// owner scopes who may read it back.
func (h *handlers) putShutdownTombstone(ctx context.Context, id, owner string, view devboxView) error {
	blob, err := json.Marshal(view)
	if err != nil {
		return err
	}
	return h.deps.Service.RecordDeletedSandboxView(ctx, id, models.FacadeRunloop, owner, string(blob))
}

// shutdownTombstone returns the recorded terminal view for a gone devbox, if
// the caller may see it and it is still within the replay window. The owner
// and window checks live in the service.
func (h *handlers) shutdownTombstone(ctx context.Context, id string) (devboxView, bool) {
	blob, ok, err := h.deps.Service.GetDeletedSandboxView(ctx, id, models.FacadeRunloop)
	if err != nil || !ok {
		return devboxView{}, false
	}
	var view devboxView
	if err := json.Unmarshal([]byte(blob), &view); err != nil {
		return devboxView{}, false
	}
	return view, true
}

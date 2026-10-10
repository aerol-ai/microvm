package runloop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Snapshot ids. A snapshot taken through this facade is snp-<devbox>.<hash>:
// the source devbox id is embedded so the status/update/delete routes can
// be forwarded to the node holding the snapshot while that devbox lives,
// and the hash makes a retried snapshot_disk land on the same snapshot.
// Snapshots taken through other APIs are addressed by their native name,
// base64url-encoded behind snx- because native names are image refs
// ("repo/name:tag") that cannot sit in a URL path segment.
const (
	snapshotPrefix       = "snp-"
	nativeSnapshotPrefix = "snx-"
)

var (
	// snapshotHold bounds how long snapshot_disk_async waits before
	// answering; the SDK then polls the status route every second.
	snapshotHold = 2 * time.Second
	// snapshotTimeout bounds the detached snapshot. Committing a large
	// container can outlast any client timeout.
	snapshotTimeout = 30 * time.Minute
)

// snapshotBlob is the facade-private state on the snapshot's alias row.
type snapshotBlob struct {
	Name          string            `json:"name,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CommitMessage string            `json:"commit_message,omitempty"`
}

// encode marshals the blob; strings and a string map cannot fail to.
func (b snapshotBlob) encode() string {
	encoded, _ := json.Marshal(b)
	return string(encoded)
}

type snapshotMeta struct {
	owner    string
	devboxID string
	blob     snapshotBlob
}

type snapshotTracker = flightTracker[snapshotMeta, *models.SandboxSnapshot]

func newSnapshotTracker() *snapshotTracker {
	return newFlightTracker[snapshotMeta, *models.SandboxSnapshot]()
}

// snapshotSourceDevbox extracts the devbox id embedded in a facade
// snapshot id.
func snapshotSourceDevbox(id string) (string, bool) {
	rest, ok := strings.CutPrefix(id, snapshotPrefix)
	if !ok {
		return "", false
	}
	devboxID, hash, found := strings.Cut(rest, ".")
	if !found || models.ValidateSandboxID(devboxID) != nil || !isHex(hash) {
		return "", false
	}
	return devboxID, true
}

// nativeSnapshotName is the image ref the snapshot is committed under.
func nativeSnapshotName(snapshotID string) string {
	return "runloop/" + shortHash(snapshotID) + ":latest"
}

func snapshotIDForName(name string) string {
	return nativeSnapshotPrefix + base64.RawURLEncoding.EncodeToString([]byte(name))
}

// lookupSnapshot resolves any snapshot id this facade hands out — or a
// native id/name, or another facade's alias — to the native row.
func (h *handlers) lookupSnapshot(ctx context.Context, id string) (*models.SandboxSnapshot, error) {
	snapshot, _, err := h.lookupSnapshotWithAlias(ctx, id)
	return snapshot, err
}

func (h *handlers) lookupSnapshotWithAlias(ctx context.Context, id string) (*models.SandboxSnapshot, *models.SnapshotAlias, error) {
	if alias, err := h.deps.Service.GetSnapshotAlias(ctx, id); err == nil {
		snapshot, err := h.deps.Service.GetSnapshot(ctx, alias.SnapshotName)
		if err != nil {
			return nil, nil, err
		}
		if alias.Facade != models.FacadeRunloop {
			alias = nil
		}
		return snapshot, alias, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, nil, err
	}
	if encoded, ok := strings.CutPrefix(id, nativeSnapshotPrefix); ok {
		name, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, nil, store.ErrNotFound
		}
		snapshot, err := h.deps.Service.GetSnapshot(ctx, string(name))
		return snapshot, nil, err
	}
	if strings.HasPrefix(id, snapshotPrefix) {
		return nil, nil, store.ErrNotFound
	}
	snapshot, err := h.deps.Service.GetSnapshot(ctx, id)
	return snapshot, nil, err
}

func newSnapshotView(snapshot *models.SandboxSnapshot, alias *models.SnapshotAlias) (snapshotView, error) {
	view := snapshotView{
		ID:             snapshotIDForName(snapshot.Name),
		CreateTimeMs:   unixMillis(snapshot.CreatedAt),
		Metadata:       map[string]string{},
		SourceDevboxID: snapshot.SourceSandboxID,
	}
	if alias == nil {
		return view, nil
	}
	view.ID = alias.Alias
	if strings.TrimSpace(alias.StateJSON) != "" {
		var blob snapshotBlob
		if err := json.Unmarshal([]byte(alias.StateJSON), &blob); err != nil {
			return snapshotView{}, err
		}
		view.Name = stringPtr(blob.Name)
		view.CommitMessage = stringPtr(blob.CommitMessage)
		if blob.Metadata != nil {
			view.Metadata = cloneStringMap(blob.Metadata)
		}
	}
	return view, nil
}

func pendingSnapshotView(f *flight[snapshotMeta, *models.SandboxSnapshot]) snapshotView {
	metadata := cloneStringMap(f.meta.blob.Metadata)
	return snapshotView{
		ID:             f.id,
		CreateTimeMs:   unixMillis(f.started),
		Metadata:       metadata,
		SourceDevboxID: f.meta.devboxID,
		Name:           stringPtr(f.meta.blob.Name),
		CommitMessage:  stringPtr(f.meta.blob.CommitMessage),
	}
}

func (h *handlers) snapshotDisk(w http.ResponseWriter, r *http.Request, devboxID string) {
	f, ok := h.startSnapshot(w, r, devboxID)
	if !ok {
		return
	}
	select {
	case <-f.done:
	case <-r.Context().Done():
		return
	}
	h.writeSnapshotFlight(w, r, f)
}

func (h *handlers) snapshotDiskAsync(w http.ResponseWriter, r *http.Request, devboxID string) {
	f, ok := h.startSnapshot(w, r, devboxID)
	if !ok {
		return
	}
	timer := time.NewTimer(snapshotHold)
	defer timer.Stop()
	select {
	case <-f.done:
	case <-timer.C:
	case <-r.Context().Done():
		return
	}
	if !f.isDone() {
		writeJSON(w, http.StatusOK, pendingSnapshotView(f))
		return
	}
	h.writeSnapshotFlight(w, r, f)
}

func (h *handlers) writeSnapshotFlight(w http.ResponseWriter, r *http.Request, f *flight[snapshotMeta, *models.SandboxSnapshot]) {
	if f.err != nil {
		writeStoreAwareError(h.deps.Logger, w, f.err)
		return
	}
	snapshot, alias, err := h.lookupSnapshotWithAlias(r.Context(), f.id)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	view, err := newSnapshotView(snapshot, alias)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// startSnapshot claims the snapshot for this request's retry-stable id and
// starts it in the background when this is the first attempt.
func (h *handlers) startSnapshot(w http.ResponseWriter, r *http.Request, devboxID string) (*flight[snapshotMeta, *models.SandboxSnapshot], bool) {
	var req snapshotRequest
	raw, ok := readBody(w, r, &req)
	if !ok {
		return nil, false
	}
	if _, err := h.deps.Service.GetSandbox(r.Context(), devboxID); err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return nil, false
	}
	key := strings.TrimSpace(r.Header.Get("X-Request-Id"))
	if key == "" {
		key = randomHex()
	}
	id := snapshotPrefix + devboxID + "." + shortHash(service.OwnerRefForCreate(r.Context()), key, string(raw))
	blob := snapshotBlob{Name: trimPtr(req.Name), Metadata: cloneStringMap(req.Metadata), CommitMessage: trimPtr(req.CommitMessage)}
	f, started := h.snapshots.claim(id, snapshotMeta{owner: service.OwnerRefForCreate(r.Context()), devboxID: devboxID, blob: blob})
	if started {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), snapshotTimeout)
		go func() {
			defer cancel()
			snapshot, err := h.runSnapshot(ctx, devboxID, id, blob)
			h.snapshots.finish(f, snapshot, err)
		}()
	}
	return f, true
}

// runSnapshot commits the devbox and records the alias carrying the
// Runloop attributes. The alias is part of the snapshot: without it the
// id the caller holds resolves to nothing, so a failed alias write rolls
// the commit back (only when this run created it).
func (h *handlers) runSnapshot(ctx context.Context, devboxID, id string, blob snapshotBlob) (*models.SandboxSnapshot, error) {
	snapshot, created, err := h.deps.Service.CreateSnapshotWithOwnership(ctx, devboxID, models.CreateSandboxSnapshotRequest{Name: nativeSnapshotName(id)})
	if err != nil {
		return nil, err
	}
	err = h.deps.Service.UpsertSnapshotAlias(ctx, models.SnapshotAlias{
		Alias:        id,
		SnapshotName: snapshot.Name,
		Facade:       models.FacadeRunloop,
		StateJSON:    blob.encode(),
	})
	if err != nil {
		if created {
			if deleteErr := h.deps.Service.DeleteSnapshot(context.WithoutCancel(ctx), snapshot.Name); deleteErr != nil && h.deps.Logger != nil {
				h.deps.Logger.Warn("runloop snapshot rollback failed", "snapshot", snapshot.Name, "error", deleteErr)
			}
		}
		return nil, err
	}
	return snapshot, nil
}

func (h *handlers) snapshotStatus(w http.ResponseWriter, r *http.Request, id string) {
	if f, ok := h.snapshots.get(id); ok && visibleTo(r.Context(), f.meta.owner) {
		switch {
		case !f.isDone():
			writeJSON(w, http.StatusOK, snapshotStatusView{Status: "in_progress"})
			return
		case f.err != nil:
			writeJSON(w, http.StatusOK, snapshotStatusView{Status: "error", ErrorMessage: stringPtr(truncateMessage(f.err.Error()))})
			return
		}
	}
	snapshot, alias, err := h.lookupSnapshotWithAlias(r.Context(), id)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	view, err := newSnapshotView(snapshot, alias)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshotStatusView{Status: "complete", Snapshot: &view})
}

func (h *handlers) listSnapshots(w http.ResponseWriter, r *http.Request) {
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
	startingAfter := strings.TrimSpace(q.Get("starting_after"))
	devboxFilter := strings.TrimSpace(q.Get("devbox_id"))
	metadataFilter := metadataQuery(q)

	snapshots, err := h.deps.Service.ListSnapshots(r.Context())
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	aliases, err := h.deps.Service.ListSnapshotAliases(r.Context(), models.FacadeRunloop)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	byName := make(map[string]models.SnapshotAlias, len(aliases))
	for _, alias := range aliases {
		byName[alias.SnapshotName] = alias
	}
	views := make([]snapshotView, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if devboxFilter != "" && snapshot.SourceSandboxID != devboxFilter {
			continue
		}
		var alias *models.SnapshotAlias
		if a, ok := byName[snapshot.Name]; ok {
			alias = &a
		}
		view, err := newSnapshotView(snapshot, alias)
		if err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
		if !metadataMatches(view.Metadata, metadataFilter) {
			continue
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })
	total := len(views)
	page := make([]snapshotView, 0, limit)
	for _, view := range views {
		if view.ID > startingAfter {
			page = append(page, view)
		}
	}
	hasMore := len(page) > limit
	if hasMore {
		page = page[:limit]
	}
	resp := listSnapshotsResponse{Snapshots: page, HasMore: hasMore}
	if q.Get("include_total_count") != "false" {
		resp.TotalCount = &total
	}
	writeJSON(w, http.StatusOK, resp)
}

// metadataQuery reads Runloop's `metadata[key]=value` and
// `metadata[key][in]=a,b` filters, which both SDKs send as literal keys.
func metadataQuery(q map[string][]string) map[string][]string {
	filters := map[string][]string{}
	for rawKey, values := range q {
		key, ok := strings.CutPrefix(rawKey, "metadata[")
		if !ok || len(values) == 0 {
			continue
		}
		if name, ok := strings.CutSuffix(key, "][in]"); ok {
			filters[name] = strings.Split(values[0], ",")
		} else if name, ok := strings.CutSuffix(key, "]"); ok {
			filters[name] = []string{values[0]}
		}
	}
	return filters
}

func metadataMatches(metadata map[string]string, filters map[string][]string) bool {
	for key, allowed := range filters {
		value, ok := metadata[key]
		if !ok {
			return false
		}
		found := false
		for _, candidate := range allowed {
			if strings.TrimSpace(candidate) == value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// updateSnapshot replaces the snapshot's Runloop attributes. Omitted
// fields stay as they were; metadata, when sent, is replaced wholesale.
func (h *handlers) updateSnapshot(w http.ResponseWriter, r *http.Request, id string) {
	var req snapshotRequest
	if !decodeBody(w, r, &req) {
		return
	}
	snapshot, alias, err := h.lookupSnapshotWithAlias(r.Context(), id)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	var blob snapshotBlob
	if alias != nil && strings.TrimSpace(alias.StateJSON) != "" {
		if err := json.Unmarshal([]byte(alias.StateJSON), &blob); err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
	}
	if req.Name != nil {
		blob.Name = strings.TrimSpace(*req.Name)
	}
	if req.CommitMessage != nil {
		blob.CommitMessage = strings.TrimSpace(*req.CommitMessage)
	}
	if req.Metadata != nil {
		blob.Metadata = cloneStringMap(req.Metadata)
	}
	// A snapshot taken outside this facade gets its first runloop alias
	// here, under its snx- id — never under the id the caller passed,
	// which may be another facade's alias row that this upsert would
	// otherwise take over.
	updated := models.SnapshotAlias{Alias: snapshotIDForName(snapshot.Name), SnapshotName: snapshot.Name, Facade: models.FacadeRunloop, StateJSON: blob.encode()}
	if alias != nil {
		updated.Alias, updated.ExtraNames, updated.CreatedAt = alias.Alias, alias.ExtraNames, alias.CreatedAt
	}
	if err := h.deps.Service.UpsertSnapshotAlias(r.Context(), updated); err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	view, err := newSnapshotView(snapshot, &updated)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// deleteSnapshot is idempotent: a snapshot that is already gone is the
// state the caller asked for, so a retried delete succeeds.
func (h *handlers) deleteSnapshot(w http.ResponseWriter, r *http.Request, id string) {
	snapshot, _, err := h.lookupSnapshotWithAlias(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, struct{}{})
		return
	}
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	// The alias row goes with the snapshot (FK cascade).
	if err := h.deps.Service.DeleteSnapshot(r.Context(), snapshot.Name); err != nil && !errors.Is(err, store.ErrNotFound) {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

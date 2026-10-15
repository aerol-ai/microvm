package runloop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/clusterlist"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Snapshot ids. A snapshot lives in the catalogue (and the image store) of
// the node that took it, and nowhere else. In a cluster, every id this
// facade hands out therefore names that node: snp-<node>.<hash> for a
// snapshot taken here, snx-<node>.<name> for one taken through another API.
// Status, update, delete and create-from-snapshot route on the node in the
// id, so they keep working after the source devbox is shut down or moves,
// and through any ingress — an indexed lookup, never a fleet-wide search.
// <node> is the base32 node affinity (models.EncodeNodeAffinity), which
// cannot contain the '.' separator. Single-node ids leave the node out.
//
// <hash> makes a retried snapshot_disk land on the same snapshot. <name>
// is the native name base64url-encoded, because native names are image
// refs ("repo/name:tag") that cannot sit in a URL path segment.
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

// snapshotNodeSegment is the node prefix ids minted on this node carry:
// "<affinity>." in a cluster, "" on a single node.
func (h *handlers) snapshotNodeSegment() string {
	c := h.clusterClient()
	if c == nil {
		return ""
	}
	encoded, ok := models.EncodeNodeAffinity(c.SelfNodeID())
	if !ok {
		return ""
	}
	return encoded + "."
}

// splitSnapshotID splits an id this facade minted into its home node
// (empty for a single-node id) and the rest. ok is false for anything
// else, including a node segment that does not decode.
func splitSnapshotID(id string) (prefix, nodeID, rest string, ok bool) {
	for _, p := range []string{snapshotPrefix, nativeSnapshotPrefix} {
		body, found := strings.CutPrefix(id, p)
		if !found {
			continue
		}
		if encoded, tail, bound := strings.Cut(body, "."); bound {
			node, valid := models.DecodeNodeAffinity(encoded)
			if !valid || tail == "" {
				return "", "", "", false
			}
			return p, node, tail, true
		}
		if body == "" {
			return "", "", "", false
		}
		return p, "", body, true
	}
	return "", "", "", false
}

// snapshotHomeNode reports the node a snapshot id is bound to.
func snapshotHomeNode(id string) (string, bool) {
	_, node, _, ok := splitSnapshotID(id)
	return node, ok && node != ""
}

// nativeSnapshotName is the image ref the snapshot is committed under.
func nativeSnapshotName(snapshotID string) string {
	return "runloop/" + shortHash(snapshotID) + ":latest"
}

func (h *handlers) snapshotIDForName(name string) string {
	return nativeSnapshotPrefix + h.snapshotNodeSegment() + base64.RawURLEncoding.EncodeToString([]byte(name))
}

// snapshotNameForID is the native name behind an id, without a lookup —
// the list cursor. Ids this facade did not mint are taken as native names.
func snapshotNameForID(id string) string {
	prefix, _, rest, ok := splitSnapshotID(id)
	switch {
	case !ok:
		return id
	case prefix == snapshotPrefix:
		return nativeSnapshotName(id)
	}
	name, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return id
	}
	return string(name)
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
	prefix, _, rest, ok := splitSnapshotID(id)
	switch {
	case ok && prefix == nativeSnapshotPrefix:
		name, err := base64.RawURLEncoding.DecodeString(rest)
		if err != nil {
			return nil, nil, store.ErrNotFound
		}
		snapshot, err := h.deps.Service.GetSnapshot(ctx, string(name))
		return snapshot, nil, err
	case strings.HasPrefix(id, snapshotPrefix), strings.HasPrefix(id, nativeSnapshotPrefix):
		return nil, nil, store.ErrNotFound
	}
	snapshot, err := h.deps.Service.GetSnapshot(ctx, id)
	return snapshot, nil, err
}

func (h *handlers) newSnapshotView(snapshot *models.SandboxSnapshot, alias *models.SnapshotAlias) (snapshotView, error) {
	view := snapshotView{
		ID:             h.snapshotIDForName(snapshot.Name),
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
	view, err := h.newSnapshotView(snapshot, alias)
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
	id := snapshotPrefix + h.snapshotNodeSegment() + shortHash(service.OwnerRefForCreate(r.Context()), devboxID, key, string(raw))
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
	// Commit the devbox and its Runloop alias (carrying the attributes blob)
	// in one service call, which rolls the commit back if the alias fails (D8).
	snapshot, _, err := h.deps.Service.CreateSnapshotWithAlias(ctx, devboxID,
		models.CreateSandboxSnapshotRequest{Name: nativeSnapshotName(id)},
		models.SnapshotAlias{
			Alias:     id,
			Facade:    models.FacadeRunloop,
			StateJSON: blob.encode(),
		})
	if err != nil {
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
	view, err := h.newSnapshotView(snapshot, alias)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshotStatusView{Status: "complete", Snapshot: &view})
}

// snapshotScanBatch is how many catalogue rows listSnapshots reads per
// query while filling a page.
const snapshotScanBatch = 200

// listSnapshots pages the caller's catalogue in native-name order, which
// the store can seek: starting_after maps to a name without a lookup
// (snapshotNameForID), and each page reads only the rows it needs. The
// metadata filter lives in the facade's alias state, so rows are scanned in
// batches until the page fills; memory stays bounded by the page, never by
// the catalogue or the caller's limit.
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
	limit = min(limit, clusterlist.MaxPageLimit)
	after := ""
	if raw := strings.TrimSpace(q.Get("starting_after")); raw != "" {
		after = snapshotNameForID(raw)
	}
	devboxFilter := strings.TrimSpace(q.Get("devbox_id"))
	metadataFilter := metadataQuery(q)

	page := make([]snapshotView, 0, limit+1)
	err := h.scanSnapshots(r.Context(), devboxFilter, after, metadataFilter, func(view snapshotView) bool {
		page = append(page, view)
		return len(page) <= limit
	})
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	hasMore := len(page) > limit
	if hasMore {
		page = page[:limit]
	}
	resp := listSnapshotsResponse{Snapshots: page, HasMore: hasMore}
	if q.Get("include_total_count") != "false" {
		total, err := h.countSnapshots(r.Context(), devboxFilter, metadataFilter)
		if err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
		resp.TotalCount = &total
	}
	writeJSON(w, http.StatusOK, resp)
}

// scanSnapshots walks the caller's catalogue after the name `after`,
// calling yield with each view that passes the metadata filter until yield
// returns false or the catalogue ends.
func (h *handlers) scanSnapshots(ctx context.Context, devboxFilter, after string, metadataFilter map[string][]string, yield func(snapshotView) bool) error {
	for {
		rows, err := h.deps.Service.ListSnapshotPage(ctx, devboxFilter, models.FacadeRunloop, after, snapshotScanBatch)
		if err != nil {
			return err
		}
		for _, row := range rows {
			view, err := h.newSnapshotView(row.Snapshot, row.Alias)
			if err != nil {
				return err
			}
			if metadataMatches(view.Metadata, metadataFilter) && !yield(view) {
				return nil
			}
		}
		if len(rows) < snapshotScanBatch {
			return nil
		}
		after = rows[len(rows)-1].Snapshot.Name
	}
}

// countSnapshots is total_count. Without a metadata filter the store
// counts; with one, the matching rows are counted in a streaming scan.
func (h *handlers) countSnapshots(ctx context.Context, devboxFilter string, metadataFilter map[string][]string) (int, error) {
	if len(metadataFilter) == 0 {
		return h.deps.Service.CountSnapshots(ctx, devboxFilter)
	}
	total := 0
	err := h.scanSnapshots(ctx, devboxFilter, "", metadataFilter, func(snapshotView) bool {
		total++
		return true
	})
	return total, err
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
	updated := models.SnapshotAlias{Alias: h.snapshotIDForName(snapshot.Name), SnapshotName: snapshot.Name, Facade: models.FacadeRunloop, StateJSON: blob.encode()}
	if alias != nil {
		updated.Alias, updated.ExtraNames, updated.CreatedAt = alias.Alias, alias.ExtraNames, alias.CreatedAt
	}
	if err := h.deps.Service.UpsertSnapshotAlias(r.Context(), updated); err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	view, err := h.newSnapshotView(snapshot, &updated)
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

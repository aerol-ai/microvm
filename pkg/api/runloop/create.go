package runloop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clustercreate"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Holds and timeouts are variables only so tests can shorten them.
var (
	// createHold bounds how long a create request is held open. Both SDKs
	// give the call a 30s client timeout and re-POST on expiry, so the
	// answer has to come back inside it: a create still running at the
	// hold returns its `provisioning` view and the SDK moves on to
	// wait_for_status, which tracks the same in-flight create.
	createHold = 25 * time.Second
	// createTimeout bounds the background create. It runs detached from
	// the request so a client timeout does not cancel (and roll back) a
	// slow create — e.g. a cold image pull — that the retry would only
	// have to start over.
	createTimeout = 10 * time.Minute
)

// createMeta is what an in-flight create can already answer with before
// its sandbox row exists.
type createMeta struct {
	owner    string
	blob     devboxBlob
	metadata map[string]string
}

// createTracker joins duplicate creates of one devbox id. The deterministic
// id makes a retry after the create finished idempotent durably —
// CreateSandboxWithID returns the existing row — but two attempts in flight
// at once would both run the runtime create before either persisted the
// row. In a cluster the reservation conflict already routes a duplicate to
// the node holding the original, so the join happens there.
type createTracker = flightTracker[createMeta, *models.Sandbox]

func newCreateTracker() *createTracker { return newFlightTracker[createMeta, *models.Sandbox]() }

func (h *handlers) createDevbox(w http.ResponseWriter, r *http.Request) {
	h.handleCreate(w, r)
}

// createAndAwaitRunning is what both high-level SDKs call. Creates here
// are synchronous up to createHold, so it shares the plain create path:
// a devbox that comes back `running` needs no wait_for_status at all.
func (h *handlers) createAndAwaitRunning(w http.ResponseWriter, r *http.Request) {
	h.handleCreate(w, r)
}

func (h *handlers) handleCreate(w http.ResponseWriter, r *http.Request) {
	raw, err := readJSONBody(w, r)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	var req createDevboxRequest
	if err := decodeJSONBytes(raw, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	serviceReq, blob, err := h.translateCreate(r.Context(), req)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}

	// Derive the id from the retry-stable request id, or mint a fresh one.
	// A forwarded create re-derives the same id on the target (same
	// header, body and caller); Prepare's reservation id is authoritative
	// either way. The cluster id header is deliberately not read here: in
	// single-node mode nothing authenticates it, and a caller must not
	// pick its own devbox id.
	var id string
	if requestID := strings.TrimSpace(r.Header.Get("X-Request-Id")); requestID != "" {
		id = devboxIDForRequest(service.OwnerRefForCreate(r.Context()), requestID, raw)
	} else if id, err = service.GenerateSandboxID(); err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}

	// Retry of a create that already finished: answer from the row.
	if sandbox, err := h.deps.Service.GetSandbox(r.Context(), id); err == nil {
		h.writeDevbox(w, r, sandbox)
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	// Retry of a create still running on this node: join it.
	if f, ok := h.creates.get(id); ok && !f.isDone() {
		h.awaitCreate(w, r, f)
		return
	}

	// Prepare may forward the request to the placement target, which
	// re-translates the original wire body, so put it back.
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))
	decision, ok := clustercreate.Prepare(w, r, h.deps.Service, serviceReq, WriteError, clustercreate.PrepareOptions{
		PreferredSandboxID: id,
		MetricPrefix:       "runloop.create",
		Logger:             h.deps.Logger,
	})
	if !ok {
		return
	}
	if decision.ReservationID != "" {
		id = decision.ReservationID
	}

	f, started := h.creates.claim(id, createMeta{owner: service.OwnerRefForCreate(r.Context()), blob: blob, metadata: cloneStringMap(serviceReq.Tags)})
	if started {
		// Detached from the request: keep its values (the caller's Access
		// scopes the create to its owner) but not its cancellation.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), createTimeout)
		go func() {
			defer cancel()
			sandbox, err := h.runCreate(ctx, serviceReq, decision.ReservationID, id, blob)
			h.creates.finish(f, sandbox, err)
		}()
	}
	h.awaitCreate(w, r, f)
}

// runCreate performs the create and persists the facade state. The state
// write is part of the create: a devbox without it would answer GETs with
// its blueprint/name/launch parameters missing, so a failed write rolls
// the sandbox back rather than leaving it half-described.
func (h *handlers) runCreate(ctx context.Context, req models.CreateSandboxRequest, reservationID, id string, blob devboxBlob) (*models.Sandbox, error) {
	if reservationID == "" {
		reservationID = id
	}
	// A duplicate that checked the store just before the original's row
	// landed, and claimed just after its flight retired, ends up here with
	// nothing left to do. Answering from the row keeps it from re-running
	// the reserved-create path against a placement that is already
	// promoted.
	if existing, err := h.deps.Service.GetSandbox(ctx, reservationID); err == nil {
		return existing, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	resp, err := clustercreate.CreateOnSelectedNode(ctx, h.deps.Service, h.deps.Logger, req, reservationID, clustercreate.CreateOptions{PromoteWithSpec: true})
	if err != nil {
		return nil, err
	}
	stateJSON, err := encodeDevboxBlob(blob)
	if err == nil {
		err = h.deps.Service.UpsertCompatState(ctx, resp.Sandbox.ID, models.FacadeRunloop, stateJSON)
	}
	if err != nil {
		clustercreate.RollbackLocalCreate(context.Background(), h.deps.Service, h.deps.Logger, resp.Sandbox.ID)
		return nil, err
	}
	return &resp.Sandbox, nil
}

// awaitCreate holds the request until the create finishes or createHold
// passes, then answers with whatever state the devbox is in.
func (h *handlers) awaitCreate(w http.ResponseWriter, r *http.Request, f *flight[createMeta, *models.Sandbox]) {
	timer := time.NewTimer(createHold)
	defer timer.Stop()
	select {
	case <-f.done:
	case <-timer.C:
	case <-r.Context().Done():
		return
	}
	if !f.isDone() {
		writeJSON(w, http.StatusOK, provisioningView(f.id, f.started, f.meta.blob, f.meta.metadata))
		return
	}
	if f.err != nil {
		writeStoreAwareError(h.deps.Logger, w, f.err)
		return
	}
	writeJSON(w, http.StatusOK, newDevboxView(f.result, f.meta.blob))
}

// translateCreate maps a Runloop create body onto the native request plus
// the facade-private blob persisted beside it.
func (h *handlers) translateCreate(ctx context.Context, req createDevboxRequest) (models.CreateSandboxRequest, devboxBlob, error) {
	if fields := unsupportedCreateFields(req); len(fields) > 0 {
		return models.CreateSandboxRequest{}, devboxBlob{}, notImplemented("unsupported by this AerolVM Runloop facade: " + strings.Join(fields, ", "))
	}
	image, blob, err := h.resolveImage(ctx, req)
	if err != nil {
		return models.CreateSandboxRequest{}, devboxBlob{}, err
	}
	cpu, memoryMB, diskGB, err := resources(req.LaunchParameters)
	if err != nil {
		return models.CreateSandboxRequest{}, devboxBlob{}, err
	}
	lifecycle, err := lifecycleFor(req.LaunchParameters)
	if err != nil {
		return models.CreateSandboxRequest{}, devboxBlob{}, err
	}
	if req.Name != nil {
		blob.Name = strings.TrimSpace(*req.Name)
	}
	if req.LaunchParameters != nil {
		blob.LaunchParameters = *req.LaunchParameters
	}
	// Runloop devboxes are reachable only through tunnels, which this
	// facade does not offer, so there is no reason to open a public route.
	private := false
	serviceReq := models.CreateSandboxRequest{
		Image:              image,
		CPU:                cpu,
		MemoryMB:           memoryMB,
		DiskGB:             diskGB,
		Env:                cloneStringMap(req.EnvironmentVariables),
		Lifecycle:          lifecycle,
		AllowPublicTraffic: &private,
		// Runloop metadata is label-shaped, so it goes in the native tags
		// and round-trips through every API surface, not just /runloop.
		Tags: cloneStringMap(req.Metadata),
	}
	return serviceReq, blob, nil
}

// resolveImage picks the image from at most one of snapshot_id,
// blueprint_id and blueprint_name, falling back to the default blueprint.
func (h *handlers) resolveImage(ctx context.Context, req createDevboxRequest) (string, devboxBlob, error) {
	var blob devboxBlob
	snapshotID := trimPtr(req.SnapshotID)
	blueprintID := trimPtr(req.BlueprintID)
	blueprintName := trimPtr(req.BlueprintName)
	set := 0
	for _, value := range []string{snapshotID, blueprintID, blueprintName} {
		if value != "" {
			set++
		}
	}
	if set > 1 {
		return "", blob, badRequest("set at most one of snapshot_id, blueprint_id, blueprint_name")
	}
	switch {
	case snapshotID != "":
		snapshot, err := h.lookupSnapshot(ctx, snapshotID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return "", blob, badRequest(fmt.Sprintf("snapshot %q not found", snapshotID))
			}
			return "", blob, err
		}
		blob.SnapshotID = snapshotID
		return snapshot.Name, blob, nil
	case blueprintID != "" || blueprintName != "":
		key := blueprintID
		if key == "" {
			key = blueprintName
		}
		image, ok := h.blueprints[key]
		if !ok {
			return "", blob, badRequest(fmt.Sprintf("unknown blueprint %q (map it in %s)", key, blueprintMapEnv))
		}
		blob.BlueprintID = key
		return image, blob, nil
	default:
		return h.blueprints[defaultBlueprintKey], blob, nil
	}
}

func trimPtr(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

// readJSONBody reads the capped request body. The TS SDK sends
// Content-Type: application/json with no body on every bodiless POST, so
// an empty body is a valid empty object here.
func readJSONBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	return apihttp.ReadJSONBody(w, r)
}

func decodeJSONBytes(raw []byte, dst any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("request body must contain exactly one JSON value")
	}
	return nil
}

// decodeBody reads and decodes an optional JSON body in one step.
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	raw, err := readJSONBody(w, r)
	if err == nil {
		err = decodeJSONBytes(raw, dst)
	}
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

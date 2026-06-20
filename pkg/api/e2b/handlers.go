package e2b

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	svcmetrics "github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clustercreate"
	"github.com/aerol-ai/microvm/pkg/api/facadeutil"
	"github.com/aerol-ai/microvm/pkg/models"
)

type handlers struct {
	deps           Deps
	templateMap    map[string]string
	clientID       string
	defaultDomain  *string
	defaultEnvdVer string
	snapshotMu     sync.Mutex
}

func newHandlers(d Deps) *handlers {
	return &handlers{
		deps:           d,
		templateMap:    loadTemplateMap(d.Logger),
		clientID:       loadClientID(),
		defaultEnvdVer: defaultEnvdVersion,
	}
}

func (h *handlers) createSandbox(w http.ResponseWriter, r *http.Request) {
	var req createSandboxRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	serviceReq, meta, err := h.translateCreateSandboxRequest(r.Context(), req)
	if err != nil {
		if !writeKnownError(w, err) {
			writeStoreAwareError(h.deps.Logger, w, err)
		}
		return
	}
	fingerprint, err := createRequestFingerprint(req.TemplateID, serviceReq, meta)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	deterministicID := sandboxIDFromFingerprint(fingerprint)
	decision, ok := clustercreate.Prepare(w, r, h.deps.Service, serviceReq, WriteError, clustercreate.PrepareOptions{PreferredSandboxID: deterministicID})
	if !ok {
		return
	}
	cleanupReservation := func() {
		if err := h.deps.Service.DeleteIdempotentRequest(r.Context(), idempotencyScopeCreate, fingerprint); err != nil && !errors.Is(err, store.ErrNotFound) && h.deps.Logger != nil {
			h.deps.Logger.Warn("e2b create reservation cleanup failed", "fingerprint", fingerprint, "error", err)
		}
	}

	for {
		record, acquired, err := h.deps.Service.ClaimIdempotentRequest(r.Context(), idempotencyScopeCreate, fingerprint, time.Now().UTC(), e2bCreatePendingTTL)
		if err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
		if acquired {
			break
		}

		if record.State == models.RequestStateReady {
			sandbox, storedMeta, replayed, err := h.loadReplayableCreateResult(r.Context(), record)
			if err != nil {
				writeStoreAwareError(h.deps.Logger, w, err)
				return
			}
			if replayed {
				svcmetrics.RecordFacadeIdempotencyReplay(idempotencyScopeCreate)
				writeJSON(w, http.StatusCreated, h.toSandboxResponse(r, sandbox, storedMeta))
				return
			}
			continue
		}

		sandbox, storedMeta, replayed, err := h.waitForCreateReplay(r.Context(), fingerprint)
		if err != nil {
			if !writeKnownError(w, err) {
				writeStoreAwareError(h.deps.Logger, w, err)
			}
			return
		}
		if replayed {
			svcmetrics.RecordFacadeIdempotencyReplay(idempotencyScopeCreate)
			writeJSON(w, http.StatusCreated, h.toSandboxResponse(r, sandbox, storedMeta))
			return
		}
	}

	response, err := clustercreate.CreateOnSelectedNode(r.Context(), h.deps.Service, h.deps.Logger, serviceReq, decision.ReservationID, clustercreate.CreateOptions{PromoteWithSpec: true})
	if err != nil {
		cleanupReservation()
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}

	if err := h.persistSandboxMeta(r.Context(), response.ID, meta); err != nil {
		if destroyErr := h.deps.Service.DestroySandbox(r.Context(), response.ID); destroyErr != nil && h.deps.Logger != nil {
			h.deps.Logger.Warn("e2b metadata rollback failed", "sandbox_id", response.ID, "error", destroyErr)
		}
		clustercreate.DeletePlacementBestEffort(context.Background(), h.deps.Service, h.deps.Logger, response.ID)
		cleanupReservation()
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}

	if err := h.deps.Service.CompleteIdempotentRequest(r.Context(), idempotencyScopeCreate, fingerprint, response.ID, time.Now().UTC(), e2bCreateReplayWindow); err != nil {
		if destroyErr := h.deps.Service.DestroySandbox(r.Context(), response.ID); destroyErr != nil && h.deps.Logger != nil {
			h.deps.Logger.Warn("e2b create idempotency rollback failed", "sandbox_id", response.ID, "error", destroyErr)
		}
		clustercreate.DeletePlacementBestEffort(context.Background(), h.deps.Service, h.deps.Logger, response.ID)
		cleanupReservation()
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	writeJSON(w, http.StatusCreated, h.toSandboxResponse(r, &response.Sandbox, meta))
}

func sandboxIDFromFingerprint(fingerprint string) string {
	hexPart := strings.TrimPrefix(strings.TrimSpace(fingerprint), "fingerprint:")
	if len(hexPart) < 16 {
		return ""
	}
	return "sb-" + hexPart[:16]
}

func (h *handlers) listSandboxes(w http.ResponseWriter, r *http.Request) {
	sandboxes, err := h.deps.Service.ListSandboxes(r.Context(), nil)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}

	limit, offset, err := parsePagination(r, 100)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	metadataFilter, err := parseMetadataFilter(r.URL.Query().Get("metadata"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	stateFilter, err := parseStateFilter(r.URL.Query().Get("state"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	stored, err := h.deps.Service.ListCompatState(r.Context(), models.FacadeE2B)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}

	items := make([]listedSandboxResponse, 0, len(sandboxes))
	for _, sandbox := range sandboxes {
		if sandbox == nil {
			continue
		}
		var statePtr *models.SandboxCompatState
		if s, ok := stored[sandbox.ID]; ok {
			copied := s
			statePtr = &copied
		}
		meta, err := sandboxMetaFromState(statePtr, sandbox)
		if err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
		state := mapSandboxState(sandbox.Status)
		if len(stateFilter) > 0 {
			if _, ok := stateFilter[state]; !ok {
				continue
			}
		}
		if len(metadataFilter) > 0 && !metadataContains(meta.Metadata, metadataFilter) {
			continue
		}
		items = append(items, h.toListedSandboxResponse(sandbox, meta))
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].StartedAt == items[j].StartedAt {
			return items[i].SandboxID < items[j].SandboxID
		}
		return items[i].StartedAt > items[j].StartedAt
	})

	page, nextToken := paginateListedSandboxes(items, offset, limit)
	if nextToken != "" {
		w.Header().Set("x-next-token", nextToken)
	}
	writeJSON(w, http.StatusOK, page)
}

func (h *handlers) getSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := h.deps.Service.GetSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "Sandbox not found")
			return
		}
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	meta, err := h.loadSandboxMeta(r.Context(), sandbox)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.toSandboxDetailResponse(r, sandbox, meta))
}

func (h *handlers) deleteSandbox(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Service.DestroySandbox(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "Sandbox not found")
			return
		}
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	clustercreate.DeletePlacementBestEffort(context.Background(), h.deps.Service, h.deps.Logger, r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) connectSandbox(w http.ResponseWriter, r *http.Request) {
	var req connectSandboxRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if req.Timeout <= 0 {
		WriteError(w, http.StatusBadRequest, "timeout must be greater than zero")
		return
	}

	sandbox, err := h.deps.Service.GetSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "Sandbox not found")
			return
		}
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	meta, err := h.loadSandboxMeta(r.Context(), sandbox)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}

	if sandbox.Status == models.SandboxStatusStopped {
		sandbox, err = h.deps.Service.StartSandbox(r.Context(), sandbox.ID)
		if err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
	} else if sandbox.Status != models.SandboxStatusStarted {
		WriteError(w, http.StatusConflict, "Sandbox is not available for connect")
		return
	}

	currentDeadline, hasDeadline := timeoutDeadline(sandbox, meta)
	desiredLifecycle := lifecycleForTimeout(sandbox, meta.OnTimeout, req.Timeout)
	desiredDeadline, _ := timeoutDeadline(&models.Sandbox{CreatedAt: sandbox.CreatedAt, Lifecycle: desiredLifecycle}, meta)
	if !hasDeadline || desiredDeadline.After(currentDeadline) {
		sandbox, err = h.deps.Service.UpdateLifecycle(r.Context(), sandbox.ID, desiredLifecycle)
		if err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
		meta.TimeoutSeconds = req.Timeout
		if err := h.persistSandboxMeta(r.Context(), sandbox.ID, meta); err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
	}

	writeJSON(w, http.StatusOK, h.toSandboxResponse(r, sandbox, meta))
}

func (h *handlers) pauseSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := h.deps.Service.GetSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "Sandbox not found")
			return
		}
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	if sandbox.Status == models.SandboxStatusStopped {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if sandbox.Status != models.SandboxStatusStarted {
		WriteError(w, http.StatusConflict, "Sandbox is not running")
		return
	}
	if _, err := h.deps.Service.StopSandbox(r.Context(), sandbox.ID); err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) updateTimeout(w http.ResponseWriter, r *http.Request) {
	var req timeoutRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if req.Timeout <= 0 {
		WriteError(w, http.StatusBadRequest, "timeout must be greater than zero")
		return
	}

	sandbox, err := h.deps.Service.GetSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "Sandbox not found")
			return
		}
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	meta, err := h.loadSandboxMeta(r.Context(), sandbox)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}

	lifecycle := lifecycleForTimeout(sandbox, meta.OnTimeout, req.Timeout)
	if _, err := h.deps.Service.UpdateLifecycle(r.Context(), sandbox.ID, lifecycle); err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	meta.TimeoutSeconds = req.Timeout
	if err := h.persistSandboxMeta(r.Context(), sandbox.ID, meta); err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) createSnapshot(w http.ResponseWriter, r *http.Request) {
	var req createSnapshotRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	sandbox, err := h.deps.Service.GetSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "Sandbox not found")
			return
		}
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}

	snapshotName := canonicalSnapshotName(req.Name)
	if snapshotName == "" {
		snapshotName = defaultSnapshotName(sandbox.ID)
	}

	h.snapshotMu.Lock()
	defer h.snapshotMu.Unlock()

	snapshot, createdSnapshot, err := h.deps.Service.CreateSnapshotWithOwnership(r.Context(), sandbox.ID, models.CreateSandboxSnapshotRequest{Name: snapshotName})
	if err != nil {
		if errors.Is(err, store.ErrSnapshotNameConflict) {
			WriteError(w, http.StatusConflict, "Snapshot name already in use")
			return
		}
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}

	resp := snapshotInfoResponse{
		SnapshotID: snapshotIDFromName(snapshot.Name),
		Names:      []string{canonicalSnapshotName(snapshot.Name)},
	}
	if err := h.deps.Service.UpsertSnapshotAlias(r.Context(), models.SnapshotAlias{
		Alias:        resp.SnapshotID,
		SnapshotName: snapshot.Name,
		Facade:       models.FacadeE2B,
		ExtraNames:   resp.Names,
	}); err != nil {
		if createdSnapshot {
			if deleteErr := h.deps.Service.DeleteSnapshot(r.Context(), snapshot.Name); deleteErr != nil && h.deps.Logger != nil {
				h.deps.Logger.Warn("e2b snapshot metadata rollback failed", "snapshot_name", snapshot.Name, "error", deleteErr)
			}
		}
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *handlers) listSnapshots(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := parsePagination(r, 100)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	sandboxFilter := strings.TrimSpace(r.URL.Query().Get("sandboxID"))

	snapshots, err := h.deps.Service.ListSnapshots(r.Context())
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	aliases, err := h.deps.Service.ListSnapshotAliases(r.Context(), models.FacadeE2B)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	// Index aliases by native snapshot name for the per-snapshot join below.
	aliasesByName := make(map[string]models.SnapshotAlias, len(aliases))
	for _, alias := range aliases {
		aliasesByName[strings.TrimSpace(alias.SnapshotName)] = alias
	}

	type snapshotRow struct {
		response  snapshotInfoResponse
		createdAt time.Time
	}
	rows := make([]snapshotRow, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if snapshot == nil {
			continue
		}
		if sandboxFilter != "" && snapshot.SourceSandboxID != sandboxFilter {
			continue
		}
		alias, ok := aliasesByName[strings.TrimSpace(snapshot.Name)]
		response := snapshotInfoResponse{
			SnapshotID: snapshotIDFromName(snapshot.Name),
			Names:      []string{canonicalSnapshotName(snapshot.Name)},
		}
		createdAt := snapshot.CreatedAt
		if ok {
			if strings.TrimSpace(alias.Alias) != "" {
				response.SnapshotID = strings.TrimSpace(alias.Alias)
			}
			if len(alias.ExtraNames) > 0 {
				response.Names = cloneStringSlice(alias.ExtraNames)
			}
			if !alias.CreatedAt.IsZero() {
				createdAt = alias.CreatedAt
			}
		}
		rows = append(rows, snapshotRow{response: response, createdAt: createdAt})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].createdAt.Equal(rows[j].createdAt) {
			return rows[i].response.SnapshotID < rows[j].response.SnapshotID
		}
		return rows[i].createdAt.After(rows[j].createdAt)
	})

	items := make([]snapshotInfoResponse, len(rows))
	for i, row := range rows {
		items[i] = row.response
	}
	page, nextToken := paginateSnapshots(items, offset, limit)
	if nextToken != "" {
		w.Header().Set("x-next-token", nextToken)
	}
	writeJSON(w, http.StatusOK, page)
}

func (h *handlers) deleteSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshotID := strings.TrimSpace(r.PathValue("id"))
	if snapshotID == "" {
		WriteError(w, http.StatusNotFound, "Snapshot not found")
		return
	}

	targetName, storedID, err := h.resolveSnapshotDeleteTarget(r.Context(), snapshotID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "Snapshot not found")
			return
		}
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	if err := h.deps.Service.DeleteSnapshot(r.Context(), targetName); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "Snapshot not found")
			return
		}
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	// The FK cascade on snapshot_aliases.snapshot_name → sandbox_snapshots.name
	// already removed the alias when DeleteSnapshot ran. We still delete by
	// alias explicitly to absorb the case where the caller addressed the
	// snapshot by its native name and the alias has a different identifier.
	if storedID != "" {
		if err := h.deps.Service.DeleteSnapshotAlias(r.Context(), storedID); err != nil && !errors.Is(err, store.ErrNotFound) {
			writeStoreAwareError(h.deps.Logger, w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) translateCreateSandboxRequest(ctx context.Context, req createSandboxRequest) (models.CreateSandboxRequest, sandboxMeta, error) {
	templateID := strings.TrimSpace(req.TemplateID)
	if templateID == "" {
		return models.CreateSandboxRequest{}, sandboxMeta{}, badRequest("templateID is required")
	}
	if req.MCP != nil {
		return models.CreateSandboxRequest{}, sandboxMeta{}, notImplemented("MCP template startup is not implemented yet")
	}
	// Translate E2B volumeMounts → the neutral platform-volume references the
	// service resolves against the operator's shared backend. The facade only
	// carries name+path; the service owns tenant scoping, credentials, and the
	// enabled/runtime/quota gates. E2B's DTO has no read-only flag, so volumes
	// mount read-write.
	platformVolumes := make([]models.PlatformVolumeMount, 0, len(req.VolumeMounts))
	volumeMountPayloads := make([]sandboxVolumeMountPayload, 0, len(req.VolumeMounts))
	for _, vm := range req.VolumeMounts {
		platformVolumes = append(platformVolumes, models.PlatformVolumeMount{
			Name: vm.Name,
			Path: vm.Path,
		})
		volumeMountPayloads = append(volumeMountPayloads, sandboxVolumeMountPayload{
			Name: vm.Name,
			Path: vm.Path,
		})
	}

	metadata, err := stringMap(req.Metadata, "metadata")
	if err != nil {
		return models.CreateSandboxRequest{}, sandboxMeta{}, err
	}
	envVars, err := stringMap(req.EnvVars, "envVars")
	if err != nil {
		return models.CreateSandboxRequest{}, sandboxMeta{}, err
	}

	networkAllowOut := []string{}
	networkDenyOut := []string{}
	allowPublicTraffic := (*bool)(nil)
	maskRequestHost := ""
	if req.Network != nil {
		networkAllowOut = cloneStringSlice(req.Network.AllowOut)
		networkDenyOut = cloneStringSlice(req.Network.DenyOut)
		allowPublicTraffic = cloneBoolPtr(req.Network.AllowPublicTraffic)
		maskRequestHost = strings.TrimSpace(req.Network.MaskRequestHost)
	}

	secure := true
	if req.Secure != nil {
		secure = *req.Secure
	}
	allowInternetAccess := cloneBoolPtr(req.AllowInternetAccess)
	networkBlockAll := false
	if allowInternetAccess != nil && !*allowInternetAccess {
		networkBlockAll = true
	}
	if len(networkDenyOut) == 1 && networkDenyOut[0] == "0.0.0.0/0" {
		networkBlockAll = true
		if allowInternetAccess == nil {
			value := false
			allowInternetAccess = &value
		}
	}

	// Effective egress CIDR policy handed to the service. A full block is
	// carried by NetworkBlockAll (the blanket DROP), so we must not also pass a
	// 0.0.0.0/0 deny — the service rejects it and it would duplicate the block.
	// allowOut/denyOut are mutually exclusive per the E2B schema.
	egressAllowOut := networkAllowOut
	egressDenyOut := networkDenyOut
	if networkBlockAll {
		egressAllowOut = nil
		egressDenyOut = nil
	}

	timeoutSeconds := defaultSandboxTimeout
	if req.Timeout != nil {
		timeoutSeconds = *req.Timeout
	}
	if timeoutSeconds <= 0 {
		return models.CreateSandboxRequest{}, sandboxMeta{}, badRequest("timeout must be greater than zero")
	}

	autoPause := req.AutoPause != nil && *req.AutoPause
	autoResume := req.AutoResume != nil && req.AutoResume.Enabled
	onTimeout := "kill"
	if autoPause || autoResume {
		onTimeout = "pause"
	}

	serverless := serverlessFromMetadata(metadata)
	lifecycle := lifecyclePtr(timeoutSeconds, onTimeout)
	if serverless {
		lifecycle.Serverless = true
		if lifecycle.StopAtAge > 0 {
			lifecycle.StopIfIdleFor = lifecycle.StopAtAge
			lifecycle.StopAtAge = 0
		} else if lifecycle.DestroyAtAge > 0 {
			lifecycle.StopIfIdleFor = lifecycle.DestroyAtAge
			lifecycle.DestroyAtAge = 0
		}
	}

	if wasmReq, ok, err := facadeutil.TranslateWasmCreate(ctx, h.deps.Service, templateID, metadata); err != nil {
		return models.CreateSandboxRequest{}, sandboxMeta{}, err
	} else if ok {
		// WASM sandboxes are host-mediated with no container IP, so the
		// DOCKER-USER egress rules cannot be enforced on them — reject rather
		// than silently leave the workload unrestricted.
		if len(egressAllowOut) > 0 || len(egressDenyOut) > 0 {
			return models.CreateSandboxRequest{}, sandboxMeta{}, notImplemented("selective egress (network.allowOut / network.denyOut) is not supported for wasm sandboxes")
		}
		// WASM has no container filesystem, so a bind-mounted volume could
		// never appear. Reject rather than silently drop it.
		if len(platformVolumes) > 0 {
			return models.CreateSandboxRequest{}, sandboxMeta{}, notImplemented("volume mounts are not supported for wasm sandboxes")
		}
		wasmReq.Env = envVars
		wasmReq.NetworkBlockAll = networkBlockAll
		wasmReq.AllowPublicTraffic = allowPublicTraffic
		wasmReq.MaskRequestHost = maskRequestHost
		wasmReq.Lifecycle = lifecycle
		wasmReq.Tags = cloneStringMap(metadata)
		meta := sandboxMeta{
			TemplateID:          templateID,
			Metadata:            metadata,
			TimeoutSeconds:      timeoutSeconds,
			OnTimeout:           onTimeout,
			AutoResume:          autoResume,
			Secure:              secure,
			AllowInternetAccess: allowInternetAccess,
			NetworkAllowOut:     networkAllowOut,
			NetworkDenyOut:      networkDenyOut,
			AllowPublicTraffic:  allowPublicTraffic,
			MaskRequestHost:     maskRequestHost,
		}
		return wasmReq, meta, nil
	}

	resolvedImage, templateAlias, err := h.resolveTemplate(ctx, templateID)
	if err != nil {
		return models.CreateSandboxRequest{}, sandboxMeta{}, err
	}

	serviceReq := models.CreateSandboxRequest{
		Image:              resolvedImage,
		Env:                envVars,
		NetworkBlockAll:    networkBlockAll,
		NetworkAllowOut:    egressAllowOut,
		NetworkDenyOut:     egressDenyOut,
		AllowPublicTraffic: allowPublicTraffic,
		MaskRequestHost:    maskRequestHost,
		PlatformVolumes:    platformVolumes,
		Lifecycle:          lifecycle,
		// E2B's metadata is the same shape as Daytona's labels — write it
		// into the native tags column so it round-trips through any API
		// surface, not just /e2b.
		Tags: cloneStringMap(metadata),
	}
	meta := sandboxMeta{
		TemplateID:          templateID,
		TemplateAlias:       templateAlias,
		Metadata:            metadata,
		TimeoutSeconds:      timeoutSeconds,
		OnTimeout:           onTimeout,
		AutoResume:          autoResume,
		Secure:              secure,
		AllowInternetAccess: allowInternetAccess,
		NetworkAllowOut:     networkAllowOut,
		NetworkDenyOut:      networkDenyOut,
		AllowPublicTraffic:  allowPublicTraffic,
		MaskRequestHost:     maskRequestHost,
		VolumeMounts:        volumeMountPayloads,
	}
	return serviceReq, meta, nil
}

func (h *handlers) resolveTemplate(ctx context.Context, templateID string) (string, string, error) {
	if alias, err := h.deps.Service.GetSnapshotAlias(ctx, templateID); err == nil {
		return strings.TrimSpace(alias.SnapshotName), "", nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", "", err
	}
	if decoded, ok := snapshotNameFromID(templateID); ok {
		if snapshot, err := h.deps.Service.GetSnapshot(ctx, decoded); err == nil {
			return snapshot.Name, "", nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return "", "", err
		}
	}
	if snapshot, err := h.deps.Service.GetSnapshot(ctx, templateID); err == nil {
		return snapshot.Name, "", nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", "", err
	}
	if canonical := canonicalSnapshotName(templateID); canonical != templateID {
		if snapshot, err := h.deps.Service.GetSnapshot(ctx, canonical); err == nil {
			return snapshot.Name, "", nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return "", "", err
		}
	}
	if image, ok := h.templateMap[templateID]; ok {
		return image, "", nil
	}
	return "", "", badRequest(fmt.Sprintf("unsupported templateID %q", templateID))
}

func (h *handlers) loadSandboxMeta(ctx context.Context, sandbox *models.Sandbox) (sandboxMeta, error) {
	if sandbox == nil {
		return defaultSandboxMeta(nil), nil
	}
	stored, err := h.deps.Service.GetCompatState(ctx, sandbox.ID, models.FacadeE2B)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return defaultSandboxMeta(sandbox), nil
		}
		return sandboxMeta{}, err
	}
	return sandboxMetaFromState(stored, sandbox)
}

func (h *handlers) persistSandboxMeta(ctx context.Context, sandboxID string, meta sandboxMeta) error {
	if h.deps.Service == nil {
		return nil
	}
	stateJSON, err := sandboxMetaToState(meta)
	if err != nil {
		return err
	}
	return h.deps.Service.UpsertCompatState(ctx, sandboxID, models.FacadeE2B, stateJSON)
}

func (h *handlers) loadReplayableCreateResult(ctx context.Context, record *models.IdempotentRequestRecord) (*models.Sandbox, sandboxMeta, bool, error) {
	if record == nil || strings.TrimSpace(record.TargetID) == "" {
		return nil, sandboxMeta{}, false, nil
	}
	sandbox, err := h.deps.Service.GetSandbox(ctx, record.TargetID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if deleteErr := h.deps.Service.DeleteIdempotentRequest(ctx, record.Scope, record.Fingerprint); deleteErr != nil && !errors.Is(deleteErr, store.ErrNotFound) {
				return nil, sandboxMeta{}, false, deleteErr
			}
			return nil, sandboxMeta{}, false, nil
		}
		return nil, sandboxMeta{}, false, err
	}
	meta, err := h.loadSandboxMeta(ctx, sandbox)
	if err != nil {
		return nil, sandboxMeta{}, false, err
	}
	return sandbox, meta, true, nil
}

func (h *handlers) waitForCreateReplay(ctx context.Context, fingerprint string) (*models.Sandbox, sandboxMeta, bool, error) {
	deadline := time.Now().UTC().Add(e2bCreateWaitTimeout)
	for {
		if err := ctx.Err(); err != nil {
			return nil, sandboxMeta{}, false, err
		}
		now := time.Now().UTC()
		if !now.Before(deadline) {
			return nil, sandboxMeta{}, false, serviceUnavailable("An identical sandbox create is already in progress; retry shortly.")
		}

		record, err := h.deps.Service.GetIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, sandboxMeta{}, false, nil
			}
			return nil, sandboxMeta{}, false, err
		}

		if record.State == models.RequestStateReady {
			if record.ReplayUntil.IsZero() || !record.ReplayUntil.After(now) {
				if err := h.deps.Service.DeleteIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint); err != nil && !errors.Is(err, store.ErrNotFound) {
					return nil, sandboxMeta{}, false, err
				}
				return nil, sandboxMeta{}, false, nil
			}
			return h.loadReplayableCreateResult(ctx, record)
		}
		if record.State != models.RequestStatePending || !record.LockedUntil.After(now) {
			return nil, sandboxMeta{}, false, nil
		}

		waitFor := e2bCreatePollInterval
		if remaining := time.Until(deadline); remaining > 0 && remaining < waitFor {
			waitFor = remaining
		}
		if remaining := time.Until(record.LockedUntil); remaining > 0 && remaining < waitFor {
			waitFor = remaining
		}
		timer := time.NewTimer(waitFor)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, sandboxMeta{}, false, ctx.Err()
		case <-timer.C:
		}
	}
}

func (h *handlers) resolveSnapshotDeleteTarget(ctx context.Context, snapshotID string) (string, string, error) {
	if alias, err := h.deps.Service.GetSnapshotAlias(ctx, snapshotID); err == nil {
		return strings.TrimSpace(alias.SnapshotName), strings.TrimSpace(alias.Alias), nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", "", err
	}
	if decoded, ok := snapshotNameFromID(snapshotID); ok {
		return decoded, snapshotID, nil
	}
	if snapshot, err := h.deps.Service.GetSnapshot(ctx, snapshotID); err == nil {
		return snapshot.Name, snapshotIDFromName(snapshot.Name), nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", "", err
	}
	if canonical := canonicalSnapshotName(snapshotID); canonical != snapshotID {
		if snapshot, err := h.deps.Service.GetSnapshot(ctx, canonical); err == nil {
			return snapshot.Name, snapshotIDFromName(snapshot.Name), nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return "", "", err
		}
	}
	return "", "", store.ErrNotFound
}

func (h *handlers) toSandboxResponse(r *http.Request, sandbox *models.Sandbox, meta sandboxMeta) sandboxResponse {
	return sandboxResponse{
		ClientID:        h.clientID,
		EnvdVersion:     h.defaultEnvdVer,
		SandboxID:       sandbox.ID,
		TemplateID:      firstNonEmpty(meta.TemplateID, sandbox.Image),
		Alias:           meta.TemplateAlias,
		Domain:          requestDomain(r),
		EnvdAccessToken: envdAccessToken(sandbox, meta),
	}
}

func (h *handlers) toListedSandboxResponse(sandbox *models.Sandbox, meta sandboxMeta) listedSandboxResponse {
	endAt := timeoutEndAt(sandbox, meta)
	return listedSandboxResponse{
		ClientID:     h.clientID,
		CPUCount:     sandboxCPUCount(sandbox),
		DiskSizeMB:   sandbox.DiskGB * 1024,
		EndAt:        endAt.Format(time.RFC3339Nano),
		EnvdVersion:  h.defaultEnvdVer,
		MemoryMB:     sandbox.MemoryMB,
		SandboxID:    sandbox.ID,
		StartedAt:    startedAt(sandbox).Format(time.RFC3339Nano),
		State:        mapSandboxState(sandbox.Status),
		TemplateID:   firstNonEmpty(meta.TemplateID, sandbox.Image),
		Alias:        meta.TemplateAlias,
		Metadata:     cloneStringMap(meta.Metadata),
		VolumeMounts: cloneVolumeMounts(meta.VolumeMounts),
	}
}

func (h *handlers) toSandboxDetailResponse(r *http.Request, sandbox *models.Sandbox, meta sandboxMeta) sandboxDetailResponse {
	endAt := timeoutEndAt(sandbox, meta)
	return sandboxDetailResponse{
		ClientID:            h.clientID,
		CPUCount:            sandboxCPUCount(sandbox),
		DiskSizeMB:          sandbox.DiskGB * 1024,
		EndAt:               endAt.Format(time.RFC3339Nano),
		EnvdVersion:         h.defaultEnvdVer,
		MemoryMB:            sandbox.MemoryMB,
		SandboxID:           sandbox.ID,
		StartedAt:           startedAt(sandbox).Format(time.RFC3339Nano),
		State:               mapSandboxState(sandbox.Status),
		TemplateID:          firstNonEmpty(meta.TemplateID, sandbox.Image),
		Alias:               meta.TemplateAlias,
		AllowInternetAccess: cloneBoolPtr(meta.AllowInternetAccess),
		Domain:              requestDomain(r),
		EnvdAccessToken:     envdAccessToken(sandbox, meta),
		Lifecycle:           lifecyclePayload(meta),
		Metadata:            cloneStringMap(meta.Metadata),
		Network:             networkPayload(meta),
		VolumeMounts:        cloneVolumeMounts(meta.VolumeMounts),
	}
}

func lifecyclePayload(meta sandboxMeta) *sandboxLifecyclePayload {
	if strings.TrimSpace(meta.OnTimeout) == "" {
		return nil
	}
	return &sandboxLifecyclePayload{AutoResume: meta.AutoResume, OnTimeout: meta.OnTimeout}
}

func networkPayload(meta sandboxMeta) *sandboxNetworkPayload {
	if len(meta.NetworkAllowOut) == 0 && len(meta.NetworkDenyOut) == 0 && meta.AllowPublicTraffic == nil && strings.TrimSpace(meta.MaskRequestHost) == "" {
		return nil
	}
	return &sandboxNetworkPayload{
		AllowOut:           cloneStringSlice(meta.NetworkAllowOut),
		AllowPublicTraffic: cloneBoolPtr(meta.AllowPublicTraffic),
		DenyOut:            cloneStringSlice(meta.NetworkDenyOut),
		MaskRequestHost:    strings.TrimSpace(meta.MaskRequestHost),
	}
}

func lifecyclePtr(timeoutSeconds int, onTimeout string) *models.Lifecycle {
	lifecycle := models.Lifecycle{}
	duration := time.Duration(timeoutSeconds) * time.Second
	if strings.EqualFold(onTimeout, "pause") {
		lifecycle.StopAtAge = duration
	} else {
		lifecycle.DestroyAtAge = duration
	}
	return &lifecycle
}

func lifecycleForTimeout(sandbox *models.Sandbox, onTimeout string, timeoutSeconds int) models.Lifecycle {
	base := models.Lifecycle{}
	if sandbox != nil {
		base = sandbox.Lifecycle
	}
	base.StopAtAge = 0
	base.DestroyAtAge = 0
	duration := time.Duration(timeoutSeconds) * time.Second
	if sandbox != nil && !sandbox.CreatedAt.IsZero() {
		elapsed := time.Since(sandbox.CreatedAt)
		if elapsed > 0 {
			duration += elapsed
		}
	}
	if strings.EqualFold(onTimeout, "pause") {
		base.StopAtAge = duration
	} else {
		base.DestroyAtAge = duration
	}
	return base
}

func timeoutDeadline(sandbox *models.Sandbox, meta sandboxMeta) (time.Time, bool) {
	if sandbox == nil || sandbox.CreatedAt.IsZero() {
		return time.Time{}, false
	}
	switch strings.ToLower(strings.TrimSpace(meta.OnTimeout)) {
	case "pause":
		if sandbox.Lifecycle.StopAtAge > 0 {
			return sandbox.CreatedAt.Add(sandbox.Lifecycle.StopAtAge), true
		}
	case "kill":
		if sandbox.Lifecycle.DestroyAtAge > 0 {
			return sandbox.CreatedAt.Add(sandbox.Lifecycle.DestroyAtAge), true
		}
	}
	if sandbox.Lifecycle.DestroyAtAge > 0 {
		return sandbox.CreatedAt.Add(sandbox.Lifecycle.DestroyAtAge), true
	}
	if sandbox.Lifecycle.StopAtAge > 0 {
		return sandbox.CreatedAt.Add(sandbox.Lifecycle.StopAtAge), true
	}
	return time.Time{}, false
}

func timeoutEndAt(sandbox *models.Sandbox, meta sandboxMeta) time.Time {
	if deadline, ok := timeoutDeadline(sandbox, meta); ok {
		return deadline
	}
	if sandbox != nil && meta.TimeoutSeconds > 0 {
		return sandbox.CreatedAt.Add(time.Duration(meta.TimeoutSeconds) * time.Second)
	}
	if sandbox != nil && !sandbox.CreatedAt.IsZero() {
		return sandbox.CreatedAt
	}
	return time.Now().UTC()
}

func envdAccessToken(sandbox *models.Sandbox, meta sandboxMeta) string {
	if sandbox == nil || !meta.Secure {
		return ""
	}
	return sandbox.ToolboxToken
}

func sandboxCPUCount(sandbox *models.Sandbox) int {
	if sandbox == nil || sandbox.CPU <= 0 {
		return 1
	}
	return int(math.Ceil(sandbox.CPU))
}

func startedAt(sandbox *models.Sandbox) time.Time {
	if sandbox == nil || sandbox.CreatedAt.IsZero() {
		return time.Now().UTC()
	}
	return sandbox.CreatedAt
}

func mapSandboxState(status models.SandboxStatus) string {
	if status == models.SandboxStatusStarted {
		return "running"
	}
	return "paused"
}

func metadataContains(values map[string]string, filter map[string]string) bool {
	for key, value := range filter {
		if values[key] != value {
			return false
		}
	}
	return true
}

func parseMetadataFilter(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parsed, err := url.ParseQuery(raw)
	if err != nil {
		return nil, badRequest("invalid metadata filter")
	}
	result := make(map[string]string, len(parsed))
	for key, values := range parsed {
		if len(values) == 0 {
			result[key] = ""
			continue
		}
		result[key] = values[len(values)-1]
	}
	return result, nil
}

func parseStateFilter(raw string) (map[string]struct{}, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	result := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		state := strings.ToLower(strings.TrimSpace(part))
		switch state {
		case "running", "paused":
			result[state] = struct{}{}
		default:
			return nil, badRequest(fmt.Sprintf("invalid state %q", part))
		}
	}
	return result, nil
}

func parsePagination(r *http.Request, defaultLimit int) (int, int, error) {
	limit := defaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return 0, 0, badRequest("invalid limit")
		}
		limit = parsed
	}
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("nextToken")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return 0, 0, badRequest("invalid nextToken")
		}
		offset = parsed
	}
	return limit, offset, nil
}

func paginateListedSandboxes(items []listedSandboxResponse, offset, limit int) ([]listedSandboxResponse, string) {
	if offset > len(items) {
		offset = len(items)
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	page := items[offset:end]
	if end < len(items) {
		return page, strconv.Itoa(end)
	}
	return page, ""
}

func paginateSnapshots(items []snapshotInfoResponse, offset, limit int) ([]snapshotInfoResponse, string) {
	if offset > len(items) {
		offset = len(items)
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	page := items[offset:end]
	if end < len(items) {
		return page, strconv.Itoa(end)
	}
	return page, ""
}

func stringMap(input map[string]any, field string) (map[string]string, error) {
	if len(input) == 0 {
		return map[string]string{}, nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		stringValue, ok := value.(string)
		if !ok {
			return nil, badRequest(fmt.Sprintf("%s values must be strings", field))
		}
		result[key] = stringValue
	}
	return result, nil
}

func loadTemplateMap(logger *slog.Logger) map[string]string {
	aliases := map[string]string{"base": "ubuntu:22.04"}
	raw := strings.TrimSpace(os.Getenv("SB_E2B_TEMPLATE_MAP_JSON"))
	if raw == "" {
		return aliases
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		if logger != nil {
			logger.Warn("invalid SB_E2B_TEMPLATE_MAP_JSON, using defaults", "error", err)
		}
		return aliases
	}
	for key, value := range parsed {
		trimmedKey := strings.TrimSpace(key)
		trimmedValue := strings.TrimSpace(value)
		if trimmedKey != "" && trimmedValue != "" {
			aliases[trimmedKey] = trimmedValue
		}
	}
	if _, ok := aliases["base"]; !ok {
		aliases["base"] = "ubuntu:22.04"
	}
	return aliases
}

func loadClientID() string {
	clientID := strings.TrimSpace(os.Getenv("SB_E2B_CLIENT_ID"))
	if clientID == "" {
		return defaultClientID
	}
	return clientID
}

func requestDomain(r *http.Request) *string {
	if r == nil {
		return nil
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		return nil
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	return &host
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

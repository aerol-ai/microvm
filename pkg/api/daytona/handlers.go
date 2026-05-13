package daytona

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/models"
)

type handlers struct {
	deps       Deps
	meta       *metadataStore
	httpClient *http.Client
}

func newHandlers(d Deps) *handlers {
	return &handlers{
		deps:       d,
		meta:       newMetadataStore(),
		httpClient: &http.Client{},
	}
}

func (h *handlers) createSandbox(w http.ResponseWriter, r *http.Request) {
	var req createSandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.Public != nil && !*req.Public {
		apihttp.WriteError(w, http.StatusBadRequest, "public=false is not supported by the Daytona facade")
		return
	}
	if req.NetworkAllowList != nil && strings.TrimSpace(*req.NetworkAllowList) != "" {
		apihttp.WriteError(w, http.StatusBadRequest, "networkAllowList is not supported by the Daytona facade")
		return
	}
	if req.Gpu != nil && *req.Gpu > 0 {
		apihttp.WriteError(w, http.StatusBadRequest, "gpu allocation is not supported by the Daytona facade")
		return
	}
	if len(req.Volumes) > 0 {
		apihttp.WriteError(w, http.StatusBadRequest, "volumes are not supported by the Daytona facade")
		return
	}
	if req.BuildInfo != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "buildInfo is not supported by the Daytona facade")
		return
	}

	requestedName := trimmedString(req.Name)
	if requestedName != "" {
		if h.meta.nameInUse(requestedName) {
			apihttp.WriteError(w, http.StatusConflict, errNameConflict.Error())
			return
		}
		if _, err := h.deps.Service.GetSandbox(r.Context(), requestedName); err == nil {
			apihttp.WriteError(w, http.StatusConflict, errNameConflict.Error())
			return
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
			return
		}
	}

	lifecycle := models.Lifecycle{}
	if req.AutoStopInterval != nil && *req.AutoStopInterval > 0 {
		lifecycle.StopIfIdleFor = durationFromMinutes(float32(*req.AutoStopInterval))
	}
	if req.AutoDeleteInterval != nil && *req.AutoDeleteInterval > 0 {
		lifecycle.DestroyIfIdleFor = durationFromMinutes(float32(*req.AutoDeleteInterval))
	}

	serviceReq := models.CreateSandboxRequest{
		Image:           h.createImage(req),
		CPU:             float64(int32Value(req.Cpu, 0)),
		MemoryMB:        int(int32Value(req.Memory, 0)) * 1024,
		DiskGB:          int(int32Value(req.Disk, 0)),
		Env:             cloneStringMap(mapValue(req.Env)),
		OSUser:          trimmedString(req.User),
		NetworkBlockAll: boolValue(req.NetworkBlockAll),
	}
	if !lifecycle.IsZero() {
		serviceReq.Lifecycle = &lifecycle
	}

	response, err := h.deps.Service.CreateSandbox(r.Context(), serviceReq)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	meta := sandboxMeta{
		Name:                requestedName,
		Snapshot:            nonEmptyStringPtr(req.Snapshot),
		User:                firstNonEmpty(trimmedString(req.User), response.OSUser),
		Labels:              cloneStringMap(mapValue(req.Labels)),
		Target:              trimmedString(req.Target),
		AutoStopInterval:    int32MinutesPtr(req.AutoStopInterval),
		AutoArchiveInterval: int32MinutesPtr(req.AutoArchiveInterval),
		AutoDeleteInterval:  int32MinutesPtr(req.AutoDeleteInterval),
	}
	if err := h.meta.upsert(response.ID, meta); err != nil {
		if destroyErr := h.deps.Service.DestroySandbox(r.Context(), response.ID); destroyErr != nil && h.deps.Logger != nil {
			h.deps.Logger.Warn("daytona metadata conflict cleanup failed", "sandbox_id", response.ID, "error", destroyErr)
		}
		apihttp.WriteError(w, http.StatusConflict, err.Error())
		return
	}

	apihttp.WriteJSON(w, http.StatusCreated, h.toSandboxResponse(r, &response.Sandbox))
}

func (h *handlers) listSandboxes(w http.ResponseWriter, r *http.Request) {
	sandboxes, err := h.deps.Service.ListSandboxes(r.Context())
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	filters, err := parseListFilters(r)
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	items := h.filteredSandboxes(r, sandboxes, filters)
	apihttp.WriteJSON(w, http.StatusOK, items)
}

func (h *handlers) listSandboxesPaginated(w http.ResponseWriter, r *http.Request) {
	sandboxes, err := h.deps.Service.ListSandboxes(r.Context())
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	filters, err := parseListFilters(r)
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	page, err := parsePositiveFloatQuery(r, "page", 1)
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, err := parsePositiveFloatQuery(r, "limit", 100)
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	items := h.filteredSandboxes(r, sandboxes, filters)
	total := len(items)
	start := int((page - 1) * limit)
	if start > total {
		start = total
	}
	end := start + int(limit)
	if end > total {
		end = total
	}
	totalPages := float32(0)
	if total > 0 {
		totalPages = float32((total + int(limit) - 1) / int(limit))
	}

	apihttp.WriteJSON(w, http.StatusOK, paginatedSandboxesResponse{
		Items:      items[start:end],
		Total:      float32(total),
		Page:       page,
		TotalPages: totalPages,
	})
}

func (h *handlers) getSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, _, err := h.resolveSandbox(r.Context(), r.PathValue("idOrName"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, sandbox))
}

func (h *handlers) destroySandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("idOrName"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	if err := h.deps.Service.DestroySandbox(r.Context(), sandboxID); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	h.meta.delete(sandboxID)
	snapshot := *sandbox
	snapshot.Status = models.SandboxStatusDestroyed
	now := time.Now().UTC()
	snapshot.UpdatedAt = now
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, &snapshot))
}

func (h *handlers) startSandbox(w http.ResponseWriter, r *http.Request) {
	_, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("idOrName"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	sandbox, err := h.deps.Service.StartSandbox(r.Context(), sandboxID)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, sandbox))
}

func (h *handlers) stopSandbox(w http.ResponseWriter, r *http.Request) {
	_, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("idOrName"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	sandbox, err := h.deps.Service.StopSandbox(r.Context(), sandboxID)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, sandbox))
}

func (h *handlers) resizeSandbox(w http.ResponseWriter, r *http.Request) {
	_, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("idOrName"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	var req resizeSandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	sandbox, err := h.deps.Service.ResizeSandbox(r.Context(), sandboxID, models.ResizeSandboxRequest{
		CPU:      float64(int32Value(req.Cpu, 0)),
		MemoryMB: int(int32Value(req.Memory, 0)) * 1024,
		DiskGB:   int(int32Value(req.Disk, 0)),
	})
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, sandbox))
}

func (h *handlers) toolboxProxyURL(w http.ResponseWriter, r *http.Request) {
	_, _, err := h.resolveSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, toolboxProxyURLResponse{URL: h.toolboxProxyBaseURL(r)})
}

func (h *handlers) previewURL(w http.ResponseWriter, r *http.Request) {
	_, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("idOrName"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid port")
		return
	}
	preview, err := h.deps.Service.ExposePort(r.Context(), sandboxID, port, models.ExposedPortProtocolHTTP)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, portPreviewURLResponse{
		SandboxID: sandboxID,
		URL:       preview.PublicURL,
		Token:     "",
	})
}

func (h *handlers) replaceLabels(w http.ResponseWriter, r *http.Request) {
	sandbox, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("idOrName"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	var req sandboxLabelsResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	meta, ok := h.meta.get(sandboxID)
	if !ok {
		meta = sandboxMeta{Name: sandbox.ID, User: sandbox.OSUser}
	}
	meta.Labels = cloneStringMap(req.Labels)
	if err := h.meta.upsert(sandboxID, meta); err != nil {
		apihttp.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, sandboxLabelsResponse{Labels: cloneStringMap(req.Labels)})
}

func (h *handlers) setAutoStopInterval(w http.ResponseWriter, r *http.Request) {
	h.updateIdleLifecycle(w, r, true)
}

func (h *handlers) setAutoDeleteInterval(w http.ResponseWriter, r *http.Request) {
	h.updateIdleLifecycle(w, r, false)
}

func (h *handlers) setAutoArchiveInterval(w http.ResponseWriter, r *http.Request) {
	sandbox, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("idOrName"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	interval, err := parseFloat32Path(r, "interval")
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid interval")
		return
	}
	meta, ok := h.meta.get(sandboxID)
	if !ok {
		meta = sandboxMeta{Name: sandbox.ID, User: sandbox.OSUser}
	}
	meta.AutoArchiveInterval = float32Ptr(interval)
	if err := h.meta.upsert(sandboxID, meta); err != nil {
		apihttp.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, sandbox))
}

func (h *handlers) updateIdleLifecycle(w http.ResponseWriter, r *http.Request, stop bool) {
	sandbox, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("idOrName"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	interval, err := parseFloat32Path(r, "interval")
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid interval")
		return
	}
	lifecycle := sandbox.Lifecycle
	if stop {
		if interval <= 0 {
			lifecycle.StopIfIdleFor = 0
		} else {
			lifecycle.StopIfIdleFor = durationFromMinutes(interval)
		}
	} else {
		if interval <= 0 {
			lifecycle.DestroyIfIdleFor = 0
		} else {
			lifecycle.DestroyIfIdleFor = durationFromMinutes(interval)
		}
	}
	updated, err := h.deps.Service.UpdateLifecycle(r.Context(), sandboxID, lifecycle)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	meta, ok := h.meta.get(sandboxID)
	if !ok {
		meta = sandboxMeta{Name: sandbox.ID, User: sandbox.OSUser}
	}
	if stop {
		meta.AutoStopInterval = float32Ptr(interval)
	} else {
		meta.AutoDeleteInterval = float32Ptr(interval)
	}
	if err := h.meta.upsert(sandboxID, meta); err != nil {
		apihttp.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, updated))
}

func (h *handlers) resolveSandbox(ctx context.Context, idOrName string) (*models.Sandbox, string, error) {
	trimmed := strings.TrimSpace(idOrName)
	sandbox, err := h.deps.Service.GetSandbox(ctx, trimmed)
	if err == nil {
		return sandbox, sandbox.ID, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, "", err
	}
	resolved := h.meta.resolve(trimmed)
	if resolved == trimmed {
		return nil, "", err
	}
	sandbox, err = h.deps.Service.GetSandbox(ctx, resolved)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.meta.delete(resolved)
		}
		return nil, "", err
	}
	return sandbox, sandbox.ID, nil
}

func (h *handlers) filteredSandboxes(r *http.Request, sandboxes []*models.Sandbox, filters listFilters) []sandboxResponse {
	items := make([]sandboxResponse, 0, len(sandboxes))
	for _, sandbox := range sandboxes {
		if sandbox == nil {
			continue
		}
		item := h.toSandboxResponse(r, sandbox)
		if filters.ID != "" && !strings.Contains(item.ID, filters.ID) {
			continue
		}
		if filters.Name != "" && !strings.Contains(strings.ToLower(item.Name), strings.ToLower(filters.Name)) {
			continue
		}
		if len(filters.Labels) > 0 && !labelsMatch(item.Labels, filters.Labels) {
			continue
		}
		if len(filters.States) > 0 {
			state := ""
			if item.State != nil {
				state = *item.State
			}
			if _, ok := filters.States[state]; !ok {
				continue
			}
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		left := ""
		right := ""
		if items[i].CreatedAt != nil {
			left = *items[i].CreatedAt
		}
		if items[j].CreatedAt != nil {
			right = *items[j].CreatedAt
		}
		return left > right
	})
	return items
}

func labelsMatch(labels map[string]string, wanted map[string]string) bool {
	for key, value := range wanted {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func parseListFilters(r *http.Request) (listFilters, error) {
	filters := listFilters{
		ID:   strings.TrimSpace(r.URL.Query().Get("id")),
		Name: strings.TrimSpace(r.URL.Query().Get("name")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("labels")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &filters.Labels); err != nil {
			return listFilters{}, errors.New("labels must be a JSON object")
		}
	}
	if states := r.URL.Query()["states"]; len(states) > 0 {
		filters.States = make(map[string]struct{}, len(states))
		for _, state := range states {
			trimmed := strings.TrimSpace(state)
			if trimmed != "" {
				filters.States[trimmed] = struct{}{}
			}
		}
	}
	return filters, nil
}

func (h *handlers) toSandboxResponse(r *http.Request, sandbox *models.Sandbox) sandboxResponse {
	meta, _ := h.meta.get(sandbox.ID)
	name := firstNonEmpty(meta.Name, sandbox.ID)
	user := firstNonEmpty(meta.User, sandbox.OSUser)
	labels := cloneStringMap(meta.Labels)
	state := stringPtr(mapSandboxState(sandbox.Status))
	var errorReason *string
	if strings.TrimSpace(sandbox.LastError) != "" {
		errorReason = stringPtr(strings.TrimSpace(sandbox.LastError))
	}
	gpu := float32(0)
	if sandbox.GPUs != nil && sandbox.GPUs.Count != 0 {
		gpu = float32(sandbox.GPUs.Count)
	}
	return sandboxResponse{
		ID:                  sandbox.ID,
		OrganizationID:      strings.TrimSpace(r.Header.Get("X-Daytona-Organization-ID")),
		Name:                name,
		Snapshot:            cloneStringPtr(meta.Snapshot),
		User:                user,
		Env:                 cloneStringMap(sandbox.Env),
		Labels:              labels,
		Public:              true,
		NetworkBlockAll:     sandbox.NetworkBlockAll,
		NetworkAllowList:    cloneStringPtr(meta.NetworkAllowList),
		Target:              meta.Target,
		CPU:                 float32(sandbox.CPU),
		GPU:                 gpu,
		Memory:              float32(sandbox.MemoryMB) / 1024,
		Disk:                float32(sandbox.DiskGB),
		State:               state,
		ErrorReason:         errorReason,
		AutoStopInterval:    firstFloat32Ptr(meta.AutoStopInterval, durationMinutesPtr(sandbox.Lifecycle.StopIfIdleFor)),
		AutoArchiveInterval: cloneFloat32Ptr(meta.AutoArchiveInterval),
		AutoDeleteInterval:  firstFloat32Ptr(meta.AutoDeleteInterval, durationMinutesPtr(sandbox.Lifecycle.DestroyIfIdleFor)),
		CreatedAt:           timePtr(sandbox.CreatedAt),
		UpdatedAt:           timePtr(sandbox.UpdatedAt),
		LastActivityAt:      timePtr(sandbox.LastActiveAt),
		ToolboxProxyURL:     h.toolboxProxyBaseURL(r),
	}
}

func (h *handlers) toolboxProxyBaseURL(r *http.Request) string {
	return requestBaseURL(r) + ToolboxPrefix
}

func (h *handlers) createImage(req createSandboxRequest) string {
	if snapshot := strings.TrimSpace(valueOrEmpty(req.Snapshot)); snapshot != "" {
		return snapshot
	}
	if configured := strings.TrimSpace(os.Getenv("SB_DAYTONA_DEFAULT_IMAGE")); configured != "" {
		return configured
	}
	return "ubuntu:22.04"
}

func parsePositiveFloatQuery(r *http.Request, key string, fallback float32) (float32, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseFloat(raw, 32)
	if err != nil || value <= 0 {
		return 0, errors.New(key + " must be a positive number")
	}
	return float32(value), nil
}

func parseFloat32Path(r *http.Request, name string) (float32, error) {
	value, err := strconv.ParseFloat(strings.TrimSpace(r.PathValue(name)), 32)
	if err != nil {
		return 0, err
	}
	return float32(value), nil
}

func mapSandboxState(status models.SandboxStatus) string {
	switch status {
	case models.SandboxStatusCreating:
		return "creating"
	case models.SandboxStatusStarted:
		return "started"
	case models.SandboxStatusStopped:
		return "stopped"
	case models.SandboxStatusDestroyed:
		return "destroyed"
	case models.SandboxStatusError:
		return "error"
	default:
		return "unknown"
	}
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = strings.Split(forwarded, ",")[0]
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

func durationFromMinutes(value float32) time.Duration {
	if value <= 0 {
		return 0
	}
	return time.Duration(float64(value) * float64(time.Minute))
}

func durationMinutesPtr(value time.Duration) *float32 {
	if value <= 0 {
		return nil
	}
	v := float32(float64(value) / float64(time.Minute))
	return &v
}

func timePtr(value time.Time) *string {
	if value.IsZero() {
		return nil
	}
	v := value.UTC().Format(time.RFC3339)
	return &v
}

func int32MinutesPtr(value *int32) *float32 {
	if value == nil {
		return nil
	}
	v := float32(*value)
	return &v
}

func int32Value(value *int32, fallback int32) int32 {
	if value == nil {
		return fallback
	}
	return *value
}

func boolValue(value *bool) bool {
	return value != nil && *value
}

func mapValue(value *map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	return *value
}

func trimmedString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func nonEmptyStringPtr(value *string) *string {
	trimmed := trimmedString(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func stringPtr(value string) *string {
	return &value
}

func float32Ptr(value float32) *float32 {
	return &value
}

func firstFloat32Ptr(primary *float32, fallback *float32) *float32 {
	if primary != nil {
		return cloneFloat32Ptr(primary)
	}
	return cloneFloat32Ptr(fallback)
}

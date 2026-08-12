package daytona

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clustercreate"
	"github.com/aerol-ai/microvm/pkg/api/clusterlist"
	"github.com/aerol-ai/microvm/pkg/api/facadeutil"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

type handlers struct {
	deps       Deps
	httpClient *http.Client
}

func newHandlers(d Deps) *handlers {
	return &handlers{
		deps:       d,
		httpClient: &http.Client{},
	}
}

func (h *handlers) createSandbox(w http.ResponseWriter, r *http.Request) {
	var req createSandboxRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	placementReq, err := h.clusterPlacementRequest(r.Context(), req)
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	decision, ok := clustercreate.Prepare(w, r, h.deps.Service, placementReq, apihttp.WriteError, clustercreate.PrepareOptions{})
	if !ok {
		return
	}

	serviceReq, freshlyBuiltImage, err := h.translateCreateSandboxRequest(r.Context(), req)
	if err != nil {
		clustercreate.CancelReservationBestEffort(context.Background(), h.deps.Service, h.deps.Logger, decision.ReservationID)
		// Image-build failures are operational, not user-input errors:
		// reporting them as 400 would mislead retry/alerting (a transient
		// daemon hiccup looks identical to bad client input). Distinguish
		// timeouts (504) and build/registry failures (502) from validation
		// errors that fail before BuildImage is reached (400).
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			apihttp.WriteError(w, http.StatusGatewayTimeout, err.Error())
		case errors.Is(err, errBuildOperational):
			apihttp.WriteError(w, http.StatusBadGateway, err.Error())
		case errors.Is(err, models.ErrPlatformVolumesDisabled):
			apihttp.WriteError(w, http.StatusPreconditionFailed, err.Error())
		default:
			apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	response, err := clustercreate.CreateOnSelectedNode(r.Context(), h.deps.Service, h.deps.Logger, serviceReq, decision.ReservationID, clustercreate.CreateOptions{PromoteWithSpec: true})
	if err != nil {
		// If we built the image in this request and the create failed, the
		// image is now orphaned: no sandbox row references it, so the normal
		// reference-counted GC (service.maybeRemoveImage on destroy) will
		// never see it. Roll it back here so a build storm of failed creates
		// doesn't fill the daemon's image store.
		//
		// Use context.Background so cancellation of r.Context() (e.g. client
		// disconnect on the failure response) doesn't skip the cleanup.
		if freshlyBuiltImage != "" && h.deps.Builder != nil {
			if rmErr := h.deps.Builder.RemoveImage(context.Background(), freshlyBuiltImage); rmErr != nil && h.deps.Logger != nil {
				h.deps.Logger.Warn("daytona image rollback failed", "tag", freshlyBuiltImage, "error", rmErr)
			}
		}
		// Native uniqueness constraint on sandboxes.name surfaces as
		// ErrSandboxNameConflict — translate to Daytona's wire-shape
		// 409 message before falling through to the generic mapper.
		if errors.Is(err, store.ErrSandboxNameConflict) {
			apihttp.WriteError(w, http.StatusConflict, errNameConflict.Error())
			return
		}
		// Service-side createSandbox timeout fires as DeadlineExceeded;
		// map it to 504 consistent with the v1 and image-build handlers.
		if errors.Is(err, context.DeadlineExceeded) {
			apihttp.WriteError(w, http.StatusGatewayTimeout, "sandbox create exceeded timeout")
			return
		}
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	meta := sandboxMetaFromNative(&response.Sandbox, compatBlob{
		Snapshot:            strings.TrimSpace(valueOrEmpty(req.Snapshot)),
		Target:              trimmedString(req.Target),
		NetworkAllowList:    strings.TrimSpace(valueOrEmpty(req.NetworkAllowList)),
		AutoArchiveInterval: float32(int32Value(req.AutoArchiveInterval, 0)),
	})
	if err := h.persistSandboxMeta(r.Context(), response.ID, meta); err != nil {
		if destroyErr := h.deps.Service.DestroySandbox(r.Context(), response.ID); destroyErr != nil && h.deps.Logger != nil {
			h.deps.Logger.Warn("daytona metadata persist cleanup failed", "sandbox_id", response.ID, "error", destroyErr)
		}
		clustercreate.DeletePlacementBestEffort(context.Background(), h.deps.Service, h.deps.Logger, response.ID)
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	apihttp.WriteJSON(w, http.StatusCreated, h.toSandboxResponse(r, &response.Sandbox, meta))
}

func (h *handlers) clusterPlacementRequest(ctx context.Context, req createSandboxRequest) (models.CreateSandboxRequest, error) {
	if req.NetworkAllowList != nil && strings.TrimSpace(*req.NetworkAllowList) != "" {
		return models.CreateSandboxRequest{}, errors.New("networkAllowList is not supported by the Daytona facade")
	}
	if req.Gpu != nil && *req.Gpu > 0 {
		return models.CreateSandboxRequest{}, errors.New("gpu allocation is not supported by the Daytona facade")
	}
	// Volumes are resolved + gated on the real create path
	// (translateCreateSandboxRequest + the service); placement doesn't need the
	// mount set, so we let volume-bearing requests through here.
	image := "daytona-create"
	var distribution models.ImageDistributionMetadata
	if snapshotName := strings.TrimSpace(valueOrEmpty(req.Snapshot)); snapshotName != "" {
		image = snapshotName
		if h.deps.Service != nil {
			if resolved, err := h.deps.Service.GetSnapshot(ctx, snapshotName); err == nil && resolved != nil {
				if resolvedImage := strings.TrimSpace(resolved.Image); resolvedImage != "" {
					image = resolvedImage
				}
				distribution = resolved.ImageDistribution()
			}
		}
	}
	out := models.CreateSandboxRequest{
		Image:              "daytona-create",
		CPU:                float64(int32Value(req.Cpu, 0)),
		MemoryMB:           int(int32Value(req.Memory, 0)) * 1024,
		DiskGB:             int(int32Value(req.Disk, 0)),
		Name:               trimmedString(req.Name),
		Tags:               cloneStringMap(mapValue(req.Labels)),
		NetworkBlockAll:    boolValue(req.NetworkBlockAll),
		AllowPublicTraffic: daytonaPublicFlag(req.Public),
	}
	out.Image = image
	if !distribution.IsZero() {
		out.ApplyImageDistribution(distribution)
	}
	return out, nil
}

func (h *handlers) listSnapshots(w http.ResponseWriter, r *http.Request) {
	filters, page, limit, err := parseSnapshotListFilters(r)
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	snapshots, err := h.deps.Service.ListSnapshots(r.Context())
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	items := h.filteredSnapshots(r, snapshots, filters)
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

	apihttp.WriteJSON(w, http.StatusOK, paginatedSnapshotsResponse{
		Items:      items[start:end],
		Total:      float32(total),
		Page:       page,
		TotalPages: totalPages,
	})
}

func (h *handlers) getSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot, err := h.deps.Service.GetSnapshot(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeSnapshotError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSnapshotResponse(r, snapshot))
}

func (h *handlers) deleteSnapshot(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Service.DeleteSnapshot(r.Context(), r.PathValue("id")); err != nil {
		h.writeSnapshotError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// createSnapshotFromImage handles POST /daytona/snapshots — the Daytona SDK's
// snapshot.create({ name, imageName | buildInfo, resources, regionId }) call.
//
// Two image-resolution paths:
//
//  1. imageName: caller hands us a pre-built registry reference. We register
//     the snapshot row pointing at that reference and trust the runtime's
//     docker pull at sandbox-create time to fail loudly if the image
//     doesn't exist.
//  2. buildInfo: caller hands us a Dockerfile (and optionally contextHashes,
//     which today require operator-side object-store wiring — gated by
//     SB_IMAGE_BUILD_CONTEXT_ENABLED). The same resolveBuildInfo used by the
//     create-sandbox path produces a local image tag we then register.
//
// The SDK polls the snapshot until state hits a terminal value; we return
// state=active synchronously, so its poll loop exits on the first read.
func (h *handlers) createSnapshotFromImage(w http.ResponseWriter, r *http.Request) {
	var req createSnapshotRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}

	imageName := strings.TrimSpace(valueOrEmpty(req.ImageName))
	hasBuildInfo := req.BuildInfo != nil && strings.TrimSpace(valueOrEmpty(req.BuildInfo.DockerfileContent)) != ""
	if imageName == "" && !hasBuildInfo {
		apihttp.WriteError(w, http.StatusBadRequest, "imageName or buildInfo.dockerfileContent is required")
		return
	}
	if imageName != "" && hasBuildInfo {
		apihttp.WriteError(w, http.StatusBadRequest, "imageName and buildInfo are mutually exclusive")
		return
	}

	var (
		resolvedImage   string
		freshlyBuiltTag string
		err             error
	)
	if hasBuildInfo {
		resolvedImage, freshlyBuiltTag, err = h.resolveBuildInfo(r.Context(), req.BuildInfo)
		if err != nil {
			// Mirror the createSandbox classification: timeouts and
			// build/registry failures are operational (502/504); everything
			// else is a 400 because it's a payload validation failure
			// (e.g. contextHashes-without-flag).
			switch {
			case errors.Is(err, context.DeadlineExceeded):
				apihttp.WriteError(w, http.StatusGatewayTimeout, err.Error())
			case errors.Is(err, errBuildOperational):
				apihttp.WriteError(w, http.StatusBadGateway, err.Error())
			default:
				apihttp.WriteError(w, http.StatusBadRequest, err.Error())
			}
			return
		}
	} else {
		resolvedImage = imageName
	}

	snapshot := &models.SandboxSnapshot{
		Name:       req.Name,
		Image:      resolvedImage,
		Entrypoint: append([]string{}, req.Entrypoint...),
		RegionID:   strings.TrimSpace(valueOrEmpty(req.RegionID)),
		CPU:        float64(float32Value(req.CPU)),
		GPU:        float64(float32Value(req.GPU)),
		MemoryMB:   int(float32Value(req.Memory)) * 1024,
		DiskGB:     int(float32Value(req.Disk)),
	}
	registered, err := h.deps.Service.RegisterSnapshot(r.Context(), snapshot)
	if err != nil {
		// We may have just freshly built a tag that's now orphaned (no
		// snapshot row pointing to it). Roll it back so the built-image
		// janitor doesn't leak the layer.
		if freshlyBuiltTag != "" && h.deps.Builder != nil {
			if rbErr := h.deps.Builder.RemoveImage(r.Context(), freshlyBuiltTag); rbErr != nil && h.deps.Logger != nil {
				h.deps.Logger.Warn("daytona snapshot rollback failed", "tag", freshlyBuiltTag, "error", rbErr)
			}
		}
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	apihttp.WriteJSON(w, http.StatusCreated, h.toSnapshotResponse(r, registered))
}

// listFacadeClusterItems merges local facade list items with peer facade lists
// so remote owner nodes contribute their own compat metadata (not the ingress
// node's empty local map).
func (h *handlers) listFacadeClusterItems(r *http.Request, local []sandboxResponse) ([]sandboxResponse, clusterlist.Coverage, string) {
	cov := clusterlist.Coverage{Answered: []string{"local"}, PlacementViewReady: true}
	if h.deps.Service == nil || r.Header.Get("X-Cluster-Forwarded") == "1" {
		return local, cov, ""
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		return local, cov, ""
	}
	ownerRef := clusterlist.OwnerRefFromContext(r.Context())
	limit, pageToken := clusterlist.ParsePageParams(r.URL)
	peers, placements, next, viewReady, missingOwners := clusterlist.SelectPeersForPage(c, ownerRef, pageToken, limit)
	if len(placements) > 0 {
		want := make(map[string]struct{}, len(placements))
		for _, p := range placements {
			want[p.SandboxID] = struct{}{}
		}
		filtered := local[:0]
		for _, it := range local {
			if _, ok := want[it.ID]; ok {
				filtered = append(filtered, it)
			}
		}
		local = filtered
	}
	items, cov := clusterlist.MergeJSON(r.Context(), peers, local, func(it sandboxResponse) string { return it.ID }, clusterlist.Options{
		OwnerRef:   ownerRef,
		AuthHeader: r.Header.Get("Authorization"),
		// Peers must not re-apply facade page/limit — ingress paginates after merge.
		RawQuery:  clusterlist.StripFacadePagination(r.URL.RawQuery),
		Path:      PathPrefix + "/sandbox",
		Transport: clusterlist.TransportFromCluster(c),
		Warn: func(msg, peer string, peerErr error) {
			if h.deps.Logger != nil {
				h.deps.Logger.Warn(msg, "peer", peer, "error", peerErr)
			}
		},
	})
	cov.PlacementViewReady = viewReady
	if len(missingOwners) > 0 {
		cov.Missing = append(cov.Missing, missingOwners...)
		cov.Partial = true
	}
	if !viewReady {
		cov.Partial = true
	}
	return items, cov, next
}

func (h *handlers) listSandboxes(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(clusterlist.ApplyOwnerRefScope(r))
	filters, err := parseListFilters(r)
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if h.deps.Service == nil {
		apihttp.WriteJSON(w, http.StatusOK, []sandboxResponse{})
		return
	}
	sandboxes, err := h.deps.Service.ListSandboxes(r.Context(), nil)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	metadata, err := h.listSandboxMeta(r.Context())
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	localItems := h.filteredSandboxes(r, sandboxes, metadata, filters)
	items, cov, next := h.listFacadeClusterItems(r, localItems)
	clusterlist.WriteCoverageHeaders(w, cov, next)
	apihttp.WriteJSON(w, http.StatusOK, items)
}

func (h *handlers) listSandboxesPaginated(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(clusterlist.ApplyOwnerRefScope(r))
	filters, err := parseListFilters(r)
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if h.deps.Service == nil {
		apihttp.WriteJSON(w, http.StatusOK, paginatedSandboxesResponse{})
		return
	}
	sandboxes, err := h.deps.Service.ListSandboxes(r.Context(), nil)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	metadata, err := h.listSandboxMeta(r.Context())
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
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

	localItems := h.filteredSandboxes(r, sandboxes, metadata, filters)
	items, cov, next := h.listFacadeClusterItems(r, localItems)
	clusterlist.WriteCoverageHeaders(w, cov, next)
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
	meta, err := h.loadSandboxMeta(r.Context(), sandbox)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, sandbox, meta))
}

func (h *handlers) destroySandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("idOrName"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	meta, err := h.loadSandboxMeta(r.Context(), sandbox)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	if err := h.deps.Service.DestroySandbox(r.Context(), sandboxID); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	clustercreate.DeletePlacementBestEffort(context.Background(), h.deps.Service, h.deps.Logger, sandboxID)
	snapshot := *sandbox
	snapshot.Status = models.SandboxStatusDestroyed
	now := time.Now().UTC()
	snapshot.UpdatedAt = now
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, &snapshot, meta))
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
	meta, err := h.loadSandboxMeta(r.Context(), sandbox)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, sandbox, meta))
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
	meta, err := h.loadSandboxMeta(r.Context(), sandbox)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, sandbox, meta))
}

func (h *handlers) createSnapshot(w http.ResponseWriter, r *http.Request) {
	var req createSandboxSnapshotRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	sandbox, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("idOrName"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	if _, err := h.deps.Service.CreateSnapshot(r.Context(), sandboxID, models.CreateSandboxSnapshotRequest{Name: req.Name}); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	meta, err := h.loadSandboxMeta(r.Context(), sandbox)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, sandbox, meta))
}

func (h *handlers) resizeSandbox(w http.ResponseWriter, r *http.Request) {
	_, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("idOrName"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	var req resizeSandboxRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
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
	meta, err := h.loadSandboxMeta(r.Context(), sandbox)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, sandbox, meta))
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
	_, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("idOrName"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	var req sandboxLabelsResponse
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// Labels are stored natively on sandboxes.tags_json — no compat-state
	// write is needed for this endpoint. The compat blob never carried
	// label data after the consolidation; only echo-back fields remain.
	if err := h.deps.Service.UpdateTags(r.Context(), sandboxID, cloneStringMap(req.Labels)); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
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
	intervalPtr, err := intervalMetadataPtr(interval)
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	meta, err := h.loadSandboxMeta(r.Context(), sandbox)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	meta.AutoArchiveInterval = intervalPtr
	if err := h.persistSandboxMeta(r.Context(), sandboxID, meta); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, sandbox, meta))
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
	intervalPtr, err := intervalMetadataPtr(interval)
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	lifecycle := sandbox.Lifecycle
	if stop {
		if intervalPtr == nil {
			lifecycle.StopIfIdleFor = 0
		} else {
			lifecycle.StopIfIdleFor = durationFromMinutes(interval)
		}
	} else {
		if intervalPtr == nil {
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
	// Auto-stop / auto-delete intervals are derived from Lifecycle on
	// read, so the UpdateLifecycle call above is the only persistence
	// step. Load meta against the updated sandbox so the response
	// reflects the new interval.
	meta, err := h.loadSandboxMeta(r.Context(), updated)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, h.toSandboxResponse(r, updated, meta))
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
	resolved, err := h.deps.Service.ResolveSandboxIDByName(ctx, trimmed)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", err
	}
	if err != nil {
		return nil, "", err
	}
	sandbox, err = h.deps.Service.GetSandbox(ctx, resolved)
	if err != nil {
		return nil, "", err
	}
	return sandbox, sandbox.ID, nil
}

func (h *handlers) filteredSandboxes(r *http.Request, sandboxes []*models.Sandbox, metadata map[string]compatBlob, filters listFilters) []sandboxResponse {
	items := make([]sandboxResponse, 0, len(sandboxes))
	for _, sandbox := range sandboxes {
		if sandbox == nil {
			continue
		}
		meta := sandboxMetaFromNative(sandbox, metadata[sandbox.ID])
		item := h.toSandboxResponse(r, sandbox, meta)
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

func (h *handlers) filteredSnapshots(r *http.Request, snapshots []*models.SandboxSnapshot, filters snapshotListFilters) []snapshotResponse {
	items := make([]snapshotResponse, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if snapshot == nil {
			continue
		}
		item := h.toSnapshotResponse(r, snapshot)
		if filters.Name != "" && !strings.Contains(strings.ToLower(item.Name), strings.ToLower(filters.Name)) {
			continue
		}
		items = append(items, item)
	}

	sort.SliceStable(items, func(i, j int) bool {
		left, right := snapshotSortKey(items[i], filters.Sort), snapshotSortKey(items[j], filters.Sort)
		if left == right {
			if filters.Order == "asc" {
				return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
			}
			return strings.ToLower(items[i].Name) > strings.ToLower(items[j].Name)
		}
		if filters.Order == "asc" {
			return left < right
		}
		return left > right
	})
	return items
}

func (h *handlers) persistSandboxMeta(ctx context.Context, sandboxID string, meta sandboxMeta) error {
	stateJSON, err := sandboxMetaToState(meta)
	if err != nil {
		return err
	}
	return h.deps.Service.UpsertCompatState(ctx, sandboxID, models.FacadeDaytona, stateJSON)
}

func (h *handlers) loadSandboxMeta(ctx context.Context, sandbox *models.Sandbox) (sandboxMeta, error) {
	if sandbox == nil {
		return sandboxMeta{Labels: map[string]string{}}, nil
	}
	stored, err := h.deps.Service.GetCompatState(ctx, sandbox.ID, models.FacadeDaytona)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return defaultSandboxMeta(sandbox), nil
		}
		return sandboxMeta{}, err
	}
	return sandboxMetaFromState(stored, sandbox)
}

// listSandboxMeta returns a sandbox-id keyed map of the persisted compat
// blobs for the Daytona facade. Sandboxes with no compat row are absent
// from the map; their native fields still shape the response via the
// zero-valued blob the map default returns at lookup time.
func (h *handlers) listSandboxMeta(ctx context.Context) (map[string]compatBlob, error) {
	stored, err := h.deps.Service.ListCompatState(ctx, models.FacadeDaytona)
	if err != nil {
		return nil, err
	}
	items := make(map[string]compatBlob, len(stored))
	for sandboxID, state := range stored {
		var blob compatBlob
		if strings.TrimSpace(state.StateJSON) != "" {
			if err := json.Unmarshal([]byte(state.StateJSON), &blob); err != nil {
				return nil, err
			}
		}
		items[sandboxID] = blob
	}
	return items, nil
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

func parseSnapshotListFilters(r *http.Request) (snapshotListFilters, float32, float32, error) {
	page, err := parsePositiveFloatQuery(r, "page", 1)
	if err != nil {
		return snapshotListFilters{}, 0, 0, err
	}
	limit, err := parsePositiveFloatQuery(r, "limit", 100)
	if err != nil {
		return snapshotListFilters{}, 0, 0, err
	}
	if limit > 200 {
		return snapshotListFilters{}, 0, 0, errors.New("limit must be less than or equal to 200")
	}

	filters := snapshotListFilters{
		Name:  strings.TrimSpace(r.URL.Query().Get("name")),
		Sort:  strings.TrimSpace(r.URL.Query().Get("sort")),
		Order: strings.TrimSpace(r.URL.Query().Get("order")),
	}
	if filters.Sort == "" {
		filters.Sort = "lastUsedAt"
	}
	switch filters.Sort {
	case "name", "state", "lastUsedAt", "createdAt":
	default:
		return snapshotListFilters{}, 0, 0, errors.New("sort must be one of: name, state, lastUsedAt, createdAt")
	}
	if filters.Order == "" {
		filters.Order = "desc"
	}
	if filters.Order != "asc" && filters.Order != "desc" {
		return snapshotListFilters{}, 0, 0, errors.New("order must be one of: asc, desc")
	}
	return filters, page, limit, nil
}

func (h *handlers) toSandboxResponse(r *http.Request, sandbox *models.Sandbox, meta sandboxMeta) sandboxResponse {
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
		Public:              sandbox.AllowPublicTraffic == nil || *sandbox.AllowPublicTraffic,
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

func (h *handlers) toSnapshotResponse(r *http.Request, snapshot *models.SandboxSnapshot) snapshotResponse {
	createdAt := snapshot.CreatedAt.UTC().Format(time.RFC3339)
	organizationID := strings.TrimSpace(r.Header.Get("X-Daytona-Organization-ID"))
	imageName := nonEmptyStringPtr(&snapshot.Image)
	id := firstNonEmpty(strings.TrimSpace(snapshot.ImageID), snapshot.Name)

	entrypoint := snapshot.Entrypoint
	if entrypoint == nil {
		entrypoint = []string{}
	}

	var regionIDs []string
	if region := strings.TrimSpace(snapshot.RegionID); region != "" {
		regionIDs = []string{region}
	}

	// MemoryMB is stored on the model in MB; the Daytona API reports it
	// in GB to match the create payload's units.
	memGB := float32(0)
	if snapshot.MemoryMB > 0 {
		memGB = float32(snapshot.MemoryMB) / 1024
	}

	state, errorReason := daytonaSnapshotState(snapshot)

	return snapshotResponse{
		ID:             id,
		OrganizationID: nonEmptyStringPtr(&organizationID),
		General:        false,
		Name:           snapshot.Name,
		ImageName:      imageName,
		State:          state,
		Size:           nil,
		Entrypoint:     entrypoint,
		CPU:            float32(snapshot.CPU),
		GPU:            float32(snapshot.GPU),
		Mem:            memGB,
		Disk:           float32(snapshot.DiskGB),
		ErrorReason:    errorReason,
		CreatedAt:      createdAt,
		UpdatedAt:      createdAt,
		LastUsedAt:     nil,
		Ref:            cloneStringPtr(imageName),
		RegionIDs:      regionIDs,
	}
}

// daytonaSnapshotState maps the internal snapshot push lifecycle to
// Daytona's published snapshot states. The Daytona SDK polls until state
// reaches "active" or "error" — `pulling_image` keeps it in the polling
// loop without surfacing a transient error to the caller.
//
// Pre-feature snapshot rows that exist on warm-upgrade disks have an empty
// PushState; the store migration defaults them to "active", so the empty
// case here only fires for rows constructed in-memory without going
// through the store (e.g. some test setups). Treating empty as "active"
// keeps the response identical to today's behavior.
func daytonaSnapshotState(snapshot *models.SandboxSnapshot) (string, *string) {
	switch snapshot.PushState {
	case models.SnapshotPushStatePending, models.SnapshotPushStatePushing:
		return "pulling_image", nil
	case models.SnapshotPushStateError:
		reason := strings.TrimSpace(snapshot.PushError)
		if reason == "" {
			reason = "snapshot push failed"
		}
		return "error", &reason
	default:
		return "active", nil
	}
}

func (h *handlers) toolboxProxyBaseURL(r *http.Request) string {
	return requestBaseURL(r) + ToolboxPrefix
}

// translateCreateSandboxRequest converts the Daytona-shaped payload into the
// native CreateSandboxRequest. The second return value is the image tag of a
// fresh build performed during this call (empty when the image came from a
// snapshot, a bare reference, or the build cache). Callers use it to roll
// back the image if the subsequent CreateSandbox fails — that's the only
// path that can orphan a built image, since the normal reference-counted
// GC (service.maybeRemoveImage) needs a sandbox row to fire.
func (h *handlers) translateCreateSandboxRequest(ctx context.Context, req createSandboxRequest) (models.CreateSandboxRequest, string, error) {
	if req.NetworkAllowList != nil && strings.TrimSpace(*req.NetworkAllowList) != "" {
		return models.CreateSandboxRequest{}, "", errors.New("networkAllowList is not supported by the Daytona facade")
	}
	if req.Gpu != nil && *req.Gpu > 0 {
		return models.CreateSandboxRequest{}, "", errors.New("gpu allocation is not supported by the Daytona facade")
	}
	// Resolve attach-at-create volumes ({volumeId, mountPath}) to the neutral
	// platform-volume references the service mounts. The id → name lookup is
	// tenant-scoped, so a caller can only attach its own volumes.
	platformVolumes, err := h.resolveDaytonaVolumes(ctx, req.Volumes)
	if err != nil {
		return models.CreateSandboxRequest{}, "", err
	}

	lifecycle := models.Lifecycle{}
	if req.AutoStopInterval != nil && *req.AutoStopInterval > 0 {
		lifecycle.StopIfIdleFor = durationFromMinutes(float32(*req.AutoStopInterval))
	}
	if req.AutoDeleteInterval != nil && *req.AutoDeleteInterval > 0 {
		lifecycle.DestroyIfIdleFor = durationFromMinutes(float32(*req.AutoDeleteInterval))
	}

	catalogueID := strings.TrimSpace(valueOrEmpty(req.Snapshot))
	if catalogueID == "" {
		catalogueID = strings.TrimSpace(valueOrEmpty(req.Name))
	}
	if wasmReq, ok, err := facadeutil.TranslateWasmCreate(ctx, h.deps.Service, catalogueID, mapValue(req.Labels)); err != nil {
		return models.CreateSandboxRequest{}, "", err
	} else if ok {
		// WASM has no container filesystem, so a bind-mounted volume could
		// never appear. Reject rather than silently drop it.
		if len(platformVolumes) > 0 {
			return models.CreateSandboxRequest{}, "", errors.New("volume mounts are not supported for wasm sandboxes")
		}
		wasmReq.CPU = float64(int32Value(req.Cpu, 0))
		wasmReq.MemoryMB = int(int32Value(req.Memory, 0)) * 1024
		wasmReq.DiskGB = int(int32Value(req.Disk, 0))
		wasmReq.Env = cloneStringMap(mapValue(req.Env))
		wasmReq.OSUser = trimmedString(req.User)
		wasmReq.NetworkBlockAll = boolValue(req.NetworkBlockAll)
		wasmReq.Name = trimmedString(req.Name)
		wasmReq.Tags = cloneStringMap(mapValue(req.Labels))
		wasmReq.AllowPublicTraffic = daytonaPublicFlag(req.Public)
		if !lifecycle.IsZero() {
			wasmReq.Lifecycle = &lifecycle
		}
		return wasmReq, "", nil
	}

	image, freshlyBuilt, err := h.createImage(ctx, req)
	if err != nil {
		return models.CreateSandboxRequest{}, "", err
	}

	serviceReq := models.CreateSandboxRequest{
		Image:              image,
		CPU:                float64(int32Value(req.Cpu, 0)),
		MemoryMB:           int(int32Value(req.Memory, 0)) * 1024,
		DiskGB:             int(int32Value(req.Disk, 0)),
		Env:                cloneStringMap(mapValue(req.Env)),
		OSUser:             trimmedString(req.User),
		NetworkBlockAll:    boolValue(req.NetworkBlockAll),
		Name:               trimmedString(req.Name),
		Tags:               cloneStringMap(mapValue(req.Labels)),
		PlatformVolumes:    platformVolumes,
		AllowPublicTraffic: daytonaPublicFlag(req.Public),
	}
	if !lifecycle.IsZero() {
		serviceReq.Lifecycle = &lifecycle
	}
	return serviceReq, freshlyBuilt, nil
}

// daytonaPublicFlag maps the Daytona create "public" field onto the core
// allow_public_traffic flag. Daytona's platform default is public preview
// links, so an omitted field opts in; an explicit public=false maps to a
// fully private sandbox — stricter than Daytona (which still serves
// token-authenticated previews), because AerolVM has no auth-gated public
// route.
func daytonaPublicFlag(public *bool) *bool {
	v := public == nil || *public
	return &v
}

// resolveDaytonaVolumes turns the Daytona attach-at-create shape
// (volumes: [{volumeId, mountPath}]) into neutral platform-volume references.
// Each volumeId is resolved to its name through the tenant-scoped store, so a
// caller can only mount volumes it owns; an unknown id surfaces as a 400/404
// upstream via the service's store.ErrNotFound.
func (h *handlers) resolveDaytonaVolumes(ctx context.Context, raw []map[string]any) ([]models.PlatformVolumeMount, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]models.PlatformVolumeMount, 0, len(raw))
	for _, entry := range raw {
		volumeID := strings.TrimSpace(stringFromAny(entry["volumeId"]))
		mountPath := strings.TrimSpace(stringFromAny(entry["mountPath"]))
		if volumeID == "" || mountPath == "" {
			return nil, errors.New("each volume requires volumeId and mountPath")
		}
		vol, err := h.deps.Service.GetPlatformVolume(ctx, volumeID)
		if err != nil {
			return nil, err
		}
		out = append(out, models.PlatformVolumeMount{Name: vol.Name, Path: mountPath})
	}
	return out, nil
}

func stringFromAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (h *handlers) createImage(ctx context.Context, req createSandboxRequest) (string, string, error) {
	if snapshot := strings.TrimSpace(valueOrEmpty(req.Snapshot)); snapshot != "" {
		// First check the snapshot store — the Daytona SDK's
		// daytona.snapshot.create() + daytona.create({snapshot: name}) flow
		// passes a snapshot *name*, which the facade resolves to the
		// underlying image reference here. Fall back to treating the string
		// as a direct image reference for backwards compatibility with
		// callers that already pass a registry path (e.g. create-vm example).
		if resolved, err := h.deps.Service.GetSnapshot(ctx, snapshot); err == nil {
			image := strings.TrimSpace(resolved.Image)
			if image == "" {
				image = strings.TrimSpace(resolved.ImageID)
			}
			if image != "" {
				return image, "", nil
			}
		}
		return snapshot, "", nil
	}
	if req.BuildInfo != nil {
		return h.resolveBuildInfo(ctx, req.BuildInfo)
	}
	if configured := strings.TrimSpace(os.Getenv("SB_DAYTONA_DEFAULT_IMAGE")); configured != "" {
		return configured, "", nil
	}
	return "ubuntu:22.04", "", nil
}

// resolveBuildInfo turns a Daytona-shaped buildInfo payload into a runnable
// local image reference. Three cases:
//
//  1. Single-line `FROM <image>` Dockerfile, no context  → return the bare
//     image string; the runtime layer will `docker pull` it as usual. This
//     preserves the legacy fast path for callers (Daytona SDK with a string
//     image) that don't need a real build.
//  2. Multi-line Dockerfile, no context                  → build locally with
//     docker.Client.BuildImage; tag is content-addressed for idempotent
//     retries.
//  3. Any payload with contextHashes                     → gated behind the
//     SB_IMAGE_BUILD_CONTEXT_ENABLED operator flag. With the flag off, we
//     return a clear error pointing operators at the flag. With the flag on,
//     a hash-resolved context tar is supplied to BuildImage (today that
//     resolver is not wired — the flag returns "not yet implemented" so the
//     contract is honored at the type level without misleading users).
//
// resolveBuildInfo returns (imageTag, freshlyBuiltTag, error). freshlyBuiltTag
// is non-empty only when this call actually invoked BuildImage and produced
// a new image (cache hits return the tag in the first slot only). Callers
// use freshlyBuiltTag to roll back the image if the downstream sandbox
// create fails — see createSandbox.
func (h *handlers) resolveBuildInfo(ctx context.Context, info *buildInfoRequest) (string, string, error) {
	dockerfile := strings.TrimSpace(valueOrEmpty(info.DockerfileContent))
	if dockerfile == "" {
		return "", "", errors.New("buildInfo is only supported when dockerfileContent is present")
	}
	if base, ok := singleLineFromImage(dockerfile); ok && len(info.ContextHashes) == 0 {
		return base, "", nil
	}
	if len(info.ContextHashes) > 0 {
		if !h.deps.Build.ContextEnabled {
			return "", "", errors.New("buildInfo.contextHashes requires operator-side context upload support (set SB_IMAGE_BUILD_CONTEXT_ENABLED=true on the daemon)")
		}
		// Context-resolver wiring is a separate piece of work (needs an
		// object store + registry push). Fail loud so callers don't think
		// their COPY/ADD steps silently no-op.
		return "", "", errors.New("buildInfo.contextHashes is enabled but no context resolver is configured on this daemon")
	}
	if h.deps.Builder == nil {
		return "", "", errors.New("multi-line buildInfo Dockerfiles require an image builder; daemon was started without one")
	}

	tag := docker.BuildTagFor(dockerfile, info.ContextHashes)
	exists, err := h.deps.Builder.ImageExists(ctx, tag)
	if err != nil {
		return "", "", fmt.Errorf("%w: check built image cache: %v", errBuildOperational, err)
	}
	if exists {
		// Bump LastTagTime so the built-image janitor doesn't GC a tag we
		// just handed back to the caller. Best-effort: a refresh failure
		// only narrows the GC window for this tag, so we log and continue.
		if rtErr := h.deps.Builder.RefreshTag(ctx, tag); rtErr != nil && h.deps.Logger != nil {
			h.deps.Logger.Warn("daytona build cache refresh-tag failed", "tag", tag, "error", rtErr)
		}
		return tag, "", nil
	}

	buildCtx, cancel := buildContextWithTimeout(ctx, h.deps.Build.Timeout)
	defer cancel()
	logger := h.deps.Logger
	err = h.deps.Builder.BuildImage(buildCtx, docker.BuildImageRequest{
		Tag:               tag,
		DockerfileContent: dockerfile,
		OnLog: func(line string) {
			if logger != nil {
				logger.Debug("daytona build", "tag", tag, "line", line)
			}
		},
	})
	if err != nil {
		// Surface DeadlineExceeded and the build-operational marker so the
		// caller can return 504 / 502 instead of 400. Wrap with both: %w
		// only chains one error, so emit a fmt.Errorf that errors.Is sees
		// errBuildOperational; if the underlying err is DeadlineExceeded,
		// the caller's first switch arm catches that via the chain.
		if errors.Is(err, context.DeadlineExceeded) {
			return "", "", fmt.Errorf("build image timed out: %w", err)
		}
		return "", "", fmt.Errorf("%w: build image: %v", errBuildOperational, err)
	}
	return tag, tag, nil
}

// errBuildOperational marks errors that originate from the local Docker
// daemon (build, image inspect) rather than from caller validation. The
// daytona createSandbox handler maps it to HTTP 502 so that retries and
// alerting can distinguish "daemon is sad" from "client sent garbage".
var errBuildOperational = errors.New("build operational error")

// singleLineFromImage detects the legacy `FROM <image>` shape and returns
// the base image when matched. Comments and blank lines are ignored.
func singleLineFromImage(dockerfile string) (string, bool) {
	lines := make([]string, 0, 4)
	for _, line := range strings.Split(dockerfile, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
	}
	if len(lines) != 1 {
		return "", false
	}
	parts := strings.Fields(lines[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "FROM") {
		return "", false
	}
	return parts[1], true
}

func buildContextWithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
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
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, errors.New(name + " must be finite")
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

func snapshotSortKey(item snapshotResponse, sortBy string) string {
	switch sortBy {
	case "name":
		return strings.ToLower(item.Name)
	case "state":
		return strings.ToLower(item.State)
	case "createdAt":
		return item.CreatedAt
	default:
		if item.LastUsedAt != nil && *item.LastUsedAt != "" {
			return *item.LastUsedAt
		}
		return item.CreatedAt
	}
}

func (h *handlers) writeSnapshotError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		apihttp.WriteError(w, http.StatusNotFound, "snapshot not found")
		return
	}
	apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
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
	if *value <= 0 {
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

func intervalMetadataPtr(value float32) (*float32, error) {
	if value < 0 {
		return nil, errors.New("interval must be non-negative")
	}
	if value == 0 {
		return nil, nil
	}
	return float32Ptr(value), nil
}

func firstFloat32Ptr(primary *float32, fallback *float32) *float32 {
	if primary != nil {
		return cloneFloat32Ptr(primary)
	}
	return cloneFloat32Ptr(fallback)
}

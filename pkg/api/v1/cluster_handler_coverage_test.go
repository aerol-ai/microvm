package v1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

type applyStubCluster struct {
	*cluster.Noop
	applyBody []byte
	applyErr  error
}

func (c *applyStubCluster) ApplyEncoded(_ context.Context, body []byte) error {
	c.applyBody = append([]byte(nil), body...)
	return c.applyErr
}

type recoveryBlobStubCluster struct {
	*cluster.Noop
	blobs  map[string]cluster.RecoveryBlob
	getErr error
}

func (c *recoveryBlobStubCluster) RecoveryBlob(_ context.Context, ref string) (cluster.RecoveryBlob, bool, error) {
	if c.getErr != nil {
		return cluster.RecoveryBlob{}, false, c.getErr
	}
	b, ok := c.blobs[ref]
	return b, ok, nil
}

type placementPageStubCluster struct {
	*cluster.Noop
	placements []cluster.Placement
	pageResp   cluster.PlacementPageResponse
}

func (c *placementPageStubCluster) Placements() []cluster.Placement {
	return c.placements
}

func (c *placementPageStubCluster) PlacementPage(req cluster.PlacementPageRequest) cluster.PlacementPageResponse {
	_ = req
	return c.pageResp
}

func (c *placementPageStubCluster) PlacementsForShards(filter cluster.PlacementShardFilter) []cluster.Placement {
	_ = filter
	return c.placements
}

type internalPlacementStubCluster struct {
	*cluster.Noop
	placement cluster.Placement
	hasPlace  bool
	owner     cluster.OwnerInfo
	ownerErr  error
}

func (c *internalPlacementStubCluster) PlacementOf(string) (cluster.Placement, bool) {
	return c.placement, c.hasPlace
}

func (c *internalPlacementStubCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return c.owner, c.ownerErr
}

func (c *internalPlacementStubCluster) OwnerOfName(name string) (string, cluster.OwnerInfo, error) {
	if name != "known" {
		return "", cluster.OwnerInfo{}, cluster.ErrUnknownSandbox
	}
	return "sb-named", c.owner, c.ownerErr
}

func TestClusterListWrap_MergesPeerResults(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Cluster-Forwarded") != "1" {
			http.Error(w, "missing forward header", http.StatusBadRequest)
			return
		}
		if r.URL.Path != "/v1/sandboxes" {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode([]*models.Sandbox{{ID: "sb-remote", Image: "alpine"}})
	}))
	t.Cleanup(peer.Close)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-local", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&membersStubCluster{
		Noop: cluster.NewNoop("node-a", peer.URL, ""),
		members: []cluster.Member{
			{NodeID: "node-a", APIURL: peer.URL, Alive: true, Role: config.NodeRoleMixed},
			{NodeID: "node-b", APIURL: peer.URL, Alive: true, Role: config.NodeRoleWorker},
		},
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	h.clusterListWrap(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got []*models.Sandbox
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	ids := map[string]bool{}
	for _, sb := range got {
		ids[sb.ID] = true
	}
	if !ids["sb-local"] || !ids["sb-remote"] {
		t.Fatalf("merged ids = %v, want sb-local and sb-remote", ids)
	}
}

func TestClusterListWrap_ForwardedFallsThrough(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	req.Header.Set("X-Cluster-Forwarded", "1")
	h.clusterListWrap(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestClusterInternalApply_SuccessAndErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &applyStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/apply", strings.NewReader(`{"op":1}`))
	h.clusterInternalApply(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rr.Code)
	}
	if len(stub.applyBody) == 0 {
		t.Fatal("expected ApplyEncoded body")
	}

	stub.applyErr = cluster.ErrNotLeader
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/apply", strings.NewReader(`{"op":2}`))
	h.clusterInternalApply(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("not leader status = %d, want 503", rr.Code)
	}

	stub.applyErr = cluster.ErrCreateBackpressure
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/apply", strings.NewReader(`{"op":3}`))
	h.clusterInternalApply(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("backpressure status = %d, want 429", rr.Code)
	}

	stub.applyErr = cluster.ErrCapacityExceeded
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/apply", strings.NewReader(`{"op":4}`))
	h.clusterInternalApply(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity status = %d, want 503", rr.Code)
	}

	stub.applyErr = errors.New("boom")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/apply", strings.NewReader(`{"op":5}`))
	h.clusterInternalApply(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("generic status = %d, want 500", rr.Code)
	}
}

func TestClusterInternalPlacement_Reads(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &internalPlacementStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-1", OwnerNodeID: "node-a", SecretRef: "secret",
		},
		hasPlace: true,
		owner:    cluster.OwnerInfo{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
	}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placement/sb-1", nil)
	req.SetPathValue("id", "sb-1")
	h.clusterInternalPlacement(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	placement, _ := body["placement"].(map[string]any)
	if placement == nil || placement["secret_ref"] != nil {
		t.Fatalf("placement secrets not redacted: %+v", placement)
	}
}

func TestClusterInternalPlacementByName_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &internalPlacementStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-named", OwnerNodeID: "node-a",
		},
		hasPlace: true,
		owner:    cluster.OwnerInfo{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
	}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	encoded := base64.RawURLEncoding.EncodeToString([]byte("known"))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placement-by-name/"+encoded, nil)
	req.SetPathValue("name", encoded)
	h.clusterInternalPlacementByName(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterInternalRecoveryGet(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	// The recovery surface is GET-only: nothing pushes blobs anymore, so the
	// stub is seeded directly (as the FSM's storePlacementLocked would).
	stub := &recoveryBlobStubCluster{
		Noop:  cluster.NewNoop("node-a", "http://node-a", ""),
		blobs: map[string]cluster.RecoveryBlob{"ref-1": {Ref: "ref-1", SandboxID: "sb-1"}},
	}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/recovery/ref-1", nil)
	req.SetPathValue("ref", "ref-1")
	h.clusterInternalRecoveryGet(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/recovery/missing", nil)
	req.SetPathValue("ref", "missing")
	h.clusterInternalRecoveryGet(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d, want 404", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/recovery/", nil)
	req.SetPathValue("ref", "")
	h.clusterInternalRecoveryGet(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty ref status = %d, want 400", rr.Code)
	}
}

func TestClusterSandboxIndex_WithRuntimeOverlay(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-index", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&placementPageStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		pageResp: cluster.PlacementPageResponse{
			Placements: []cluster.Placement{{SandboxID: "sb-index", OwnerNodeID: "node-a", SecretRef: "s"}},
		},
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/sandbox-index?limit=10&shard=0&shard_count=8", nil)
	h.clusterSandboxIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var body sandboxIndexResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Placements) != 1 || body.Placements[0].RuntimeStatus != models.SandboxStatusStarted {
		t.Fatalf("placements = %+v, want runtime overlay", body.Placements)
	}
	if body.Placements[0].SecretRef != "" {
		t.Fatal("expected secret fields redacted in sandbox index")
	}
}

func TestClusterForwardWrap_OwnerLookupError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &ownerOfStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		err:  errors.New("fsm read failed"),
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	wrapped := h.clusterForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("local handler must not run")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-x", nil)
	req.SetPathValue("id", "sb-x")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestClusterForwardWrap_ForwardsToOwner(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &ownerOfStubCluster{
		Noop:  cluster.NewNoop("node-a", "http://node-a", ""),
		owner: cluster.OwnerInfo{NodeID: "node-b", APIURL: "http://node-b:21212", IsSelf: false},
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	wrapped := h.clusterForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("local handler must not run")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-fwd", nil)
	req.SetPathValue("id", "sb-fwd")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}
	if !fake.forwardCalled {
		t.Fatal("expected ForwardHTTP")
	}
}

func TestClusterPlacement_UnknownSandbox(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &placementOfStubCluster{
		Noop:     cluster.NewNoop("node-a", "http://node-a", ""),
		ownerErr: cluster.ErrUnknownSandbox,
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/placements/missing", nil)
	req.SetPathValue("id", "missing")
	rr := httptest.NewRecorder()
	h.clusterPlacement(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestClusterIngressRoute_ValidationAndEmptyOwners(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&membersStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		members: []cluster.Member{
			{NodeID: "worker-a", APIURL: "http://worker-a", Alive: true, Role: config.NodeRoleWorker},
		},
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/ingress-route/", nil)
	req.SetPathValue("id", "")
	h.clusterIngressRoute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty id status = %d, want 400", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/cluster/ingress-route/sb-none", nil)
	req.SetPathValue("id", "sb-none")
	h.clusterIngressRoute(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no owners status = %d, want 503", rr.Code)
	}
}

func TestClusterCreateWrap_InvalidTopologySetsRetryAfter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &createForwardCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		selectErr: cluster.ErrInvalidTopology,
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	if rr.Header().Get("Retry-After") != "300" {
		t.Fatalf("Retry-After = %q, want 300", rr.Header().Get("Retry-After"))
	}
}

func TestClusterCreateWrap_ReservationConflict(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &createForwardCluster{
		Noop:       cluster.NewNoop("node-a", "http://node-a", ""),
		target:     cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b", IsSelf: false},
		reserveErr: cluster.ErrReservationConflict,
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rr.Code)
	}
}

func TestClusterInternalSelectPlacement_ErrorResponse(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &createForwardCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		selectErr: cluster.ErrNoPlacementTarget,
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	body := `{"request":{"cpu":1,"memory_mb":256,"disk_gb":1}}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/select-placement", strings.NewReader(body))
	h.clusterInternalSelectPlacement(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 envelope", rr.Code)
	}
	var resp cluster.SelectPlacementResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error == "" {
		t.Fatal("expected error field in select-placement response")
	}
}

func TestClusterInternalPlacements_List(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&placementPageStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placements: []cluster.Placement{
			{SandboxID: "sb-1", SecretRef: "secret"},
		},
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placements", nil)
	h.clusterInternalPlacements(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestClusterReclaimOrphanLocal_MissingLocalRow(t *testing.T) {
	stub := &orphanOpsStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-orphan", OwnerState: cluster.PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "node-a",
		},
		hasPlace: true,
	}
	h, cleanup := newOrphanOpsService(t, stub, false)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/orphans/sb-orphan/reclaim-local", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	h.clusterReclaimOrphanLocal(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rr.Code)
	}
}

func TestClusterReclaimOrphanLocal_NotOrphaned(t *testing.T) {
	stub := &orphanOpsStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-live", OwnerNodeID: "node-a",
		},
		hasPlace: true,
	}
	h, cleanup := newOrphanOpsService(t, stub, true)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/orphans/sb-live/reclaim-local", nil)
	req.SetPathValue("id", "sb-live")
	rr := httptest.NewRecorder()
	h.clusterReclaimOrphanLocal(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rr.Code)
	}
}

func TestClusterDeleteOrphan_NotOrphaned(t *testing.T) {
	stub := &orphanOpsStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-live", OwnerNodeID: "node-a",
		},
		hasPlace: true,
	}
	h, cleanup := newOrphanOpsService(t, stub, false)
	defer cleanup()

	req := httptest.NewRequest(http.MethodDelete, "/v1/cluster/orphans/sb-live", nil)
	req.SetPathValue("id", "sb-live")
	rr := httptest.NewRecorder()
	h.clusterDeleteOrphan(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rr.Code)
	}
}

func TestClusterCreateWrap_SelectPlacementGenericError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &createForwardCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		selectErr: errors.New("placement scorer failed"),
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestClusterCreateWrap_CapacityExceededOnReserve(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &createForwardCluster{
		Noop:       cluster.NewNoop("node-a", "http://node-a", ""),
		target:     cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b", IsSelf: false},
		reserveErr: cluster.ErrCapacityExceeded,
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestCapacityRequestFromCreate_OverlayDisk(t *testing.T) {
	req := models.CreateSandboxRequest{
		DiskGB: 8, OverlaySizeGB: 4, Runtime: models.RuntimeFirecracker,
	}
	got := capacityRequestFromCreate(req)
	if got.DiskGB != 12 {
		t.Fatalf("DiskGB = %d, want 12", got.DiskGB)
	}
	_ = capacity.Request{}
}

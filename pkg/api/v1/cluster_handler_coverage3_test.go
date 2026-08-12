package v1

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestClusterListWrap_MergesPeerSandboxes(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Cluster-Forwarded") != "1" {
			http.Error(w, "missing forwarded header", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode([]*models.Sandbox{{ID: "sb-remote", Image: "alpine"}})
	}))
	t.Cleanup(peer.Close)

	rt := &apiRecordingRuntime{}
	stub := &membersStubCluster{
		Noop:           cluster.NewNoop("node-a", "http://node-a", ""),
		internalClient: peer.Client(),
		members: []cluster.Member{
			{NodeID: "node-b", APIURL: peer.URL, InternalURL: peer.URL, Alive: true, Role: config.NodeRoleWorker},
		},
	}
	h, st := newClusterCreateHarness(t, rt, stub)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-local", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	h.clusterListWrap(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var merged []*models.Sandbox
	if err := json.Unmarshal(rr.Body.Bytes(), &merged); err != nil {
		t.Fatalf("decode: %v", err)
	}
	ids := map[string]bool{}
	for _, sb := range merged {
		ids[sb.ID] = true
	}
	if !ids["sb-local"] || !ids["sb-remote"] {
		t.Fatalf("merged ids = %v, want local and remote", ids)
	}
}

func TestClusterListWrap_ForwardedHeaderUsesLocalList(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	req.Header.Set("X-Cluster-Forwarded", "1")
	h.clusterListWrap(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestClusterListWrap_NilClusterUsesLocalList(t *testing.T) {
	h := newHandlerWithStore(t)
	h.deps.Service.ClearClusterForTest()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	h.clusterListWrap(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestClusterReclaimOrphanLocal_NilService(t *testing.T) {
	h := &handlers{deps: Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/orphans/sb-1/reclaim-local", nil)
	req.SetPathValue("id", "sb-1")
	rr := httptest.NewRecorder()
	h.clusterReclaimOrphanLocal(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterReclaimOrphanLocal_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/orphans/sb-1/reclaim-local", nil)
	req.SetPathValue("id", "sb-1")
	rr := httptest.NewRecorder()
	h.clusterReclaimOrphanLocal(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterReclaimOrphanLocal_EmptyID(t *testing.T) {
	stub := &orphanOpsStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, cleanup := newOrphanOpsService(t, stub, false)
	defer cleanup()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/orphans//reclaim-local", nil)
	rr := httptest.NewRecorder()
	h.clusterReclaimOrphanLocal(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestClusterReclaimOrphanLocal_ClaimConflict(t *testing.T) {
	stub := &orphanOpsStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-orphan", OwnerState: cluster.PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "node-a",
		},
		hasPlace: true,
		claimErr: cluster.ErrOrphanClaimConflict,
	}
	h, cleanup := newOrphanOpsService(t, stub, true)
	defer cleanup()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/orphans/sb-orphan/reclaim-local", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	h.clusterReclaimOrphanLocal(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rr.Code)
	}
}

func TestClusterReclaimOrphanLocal_ClaimGenericError(t *testing.T) {
	stub := &orphanOpsStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-orphan", OwnerState: cluster.PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "node-a",
		},
		hasPlace: true,
		claimErr: errors.New("fsm unavailable"),
	}
	h, cleanup := newOrphanOpsService(t, stub, true)
	defer cleanup()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/orphans/sb-orphan/reclaim-local", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	h.clusterReclaimOrphanLocal(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestClusterDeleteOrphan_NilService(t *testing.T) {
	h := &handlers{deps: Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	req := httptest.NewRequest(http.MethodDelete, "/v1/cluster/orphans/sb-1", nil)
	req.SetPathValue("id", "sb-1")
	rr := httptest.NewRecorder()
	h.clusterDeleteOrphan(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterDeleteOrphan_GenericError(t *testing.T) {
	stub := &orphanOpsStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-orphan", OwnerState: cluster.PlacementOwnerStateOrphaned,
		},
		hasPlace:  true,
		deleteErr: errors.New("delete failed"),
	}
	h, cleanup := newOrphanOpsService(t, stub, false)
	defer cleanup()
	req := httptest.NewRequest(http.MethodDelete, "/v1/cluster/orphans/sb-orphan", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	h.clusterDeleteOrphan(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestClusterRemoveMember_NilService(t *testing.T) {
	h := &handlers{deps: Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	req := httptest.NewRequest(http.MethodDelete, "/v1/cluster/members/node-b", nil)
	req.SetPathValue("id", "node-b")
	rr := httptest.NewRecorder()
	h.clusterRemoveMember(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterRemoveMember_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	req := httptest.NewRequest(http.MethodDelete, "/v1/cluster/members/node-b", nil)
	req.SetPathValue("id", "node-b")
	rr := httptest.NewRecorder()
	h.clusterRemoveMember(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterRemoveMember_GenericError(t *testing.T) {
	stub := &drainStubCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		removeErr: errors.New("raft error"),
	}
	h := drainTestHandler(t, stub)
	req := httptest.NewRequest(http.MethodDelete, "/v1/cluster/members/node-b", nil)
	req.SetPathValue("id", "node-b")
	rr := httptest.NewRecorder()
	h.clusterRemoveMember(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestClusterForwardWrap_NilClusterRunsLocal(t *testing.T) {
	h := newHandlerNilCluster(t)
	called := false
	wrapped := h.clusterForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1", nil)
	req.SetPathValue("id", "sb-1")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if !called || rr.Code != http.StatusTeapot {
		t.Fatalf("called=%v status=%d, want local handler", called, rr.Code)
	}
}

func TestClusterDrainNode_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/nodes/node-b/drain", nil)
	req.SetPathValue("id", "node-b")
	rr := httptest.NewRecorder()
	h.clusterDrainNode(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterInternalSelectPlacement_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/select-placement", strings.NewReader(`{"image":"alpine"}`))
	h.clusterInternalSelectPlacement(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterPlacement_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/placements/sb-1", nil)
	req.SetPathValue("id", "sb-1")
	rr := httptest.NewRecorder()
	h.clusterPlacement(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestClusterIngressRoute_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/ingress-route/sb-1", nil)
	req.SetPathValue("id", "sb-1")
	rr := httptest.NewRecorder()
	h.clusterIngressRoute(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterInternalApply_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/apply", strings.NewReader(`{}`))
	h.clusterInternalApply(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterSandboxIndex_NilCluster(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	svc.ClearClusterForTest()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/sandbox-index", nil)
	h.writeClusterSandboxIndex(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestWriteClusterSandboxIndex_NilService(t *testing.T) {
	h := &handlers{deps: Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/sandbox-index", nil)
	h.writeClusterSandboxIndex(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterInternalPlacements_RedactsSecrets(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &placementPageStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placements: []cluster.Placement{{
			SandboxID: "sb-1", OwnerNodeID: "node-a",
			SecretRef: "cluster-secret/sb-1/v1",
		}},
	}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placements", nil)
	h.clusterInternalPlacements(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "cluster-secret") {
		t.Fatalf("expected secret ref redacted, body=%s", rr.Body.String())
	}
}

func TestClusterInternalPlacementsQuery_InvalidJSON(t *testing.T) {
	h := newHandlerNoStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/placements/query", strings.NewReader(`{`))
	h.clusterInternalPlacementsQuery(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestClusterInternalPlacementsPage_InvalidJSON(t *testing.T) {
	h := newHandlerNoStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/placements/page", strings.NewReader(`{`))
	h.clusterInternalPlacementsPage(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestClusterInternalPlacements_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placements", nil)
	h.clusterInternalPlacements(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterListWrap_PeerHTTPError(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(peer.Close)

	rt := &apiRecordingRuntime{}
	stub := &membersStubCluster{
		Noop:           cluster.NewNoop("node-a", "http://node-a", ""),
		internalClient: peer.Client(),
		members: []cluster.Member{
			{NodeID: "node-b", APIURL: peer.URL, InternalURL: peer.URL, Alive: true, Role: config.NodeRoleWorker},
		},
	}
	h, _ := newClusterCreateHarness(t, rt, stub)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	h.clusterListWrap(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterDeleteOrphan_EmptyID(t *testing.T) {
	stub := &orphanOpsStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, cleanup := newOrphanOpsService(t, stub, false)
	defer cleanup()
	req := httptest.NewRequest(http.MethodDelete, "/v1/cluster/orphans/", nil)
	rr := httptest.NewRecorder()
	h.clusterDeleteOrphan(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestClusterReclaimOrphanLocal_UnknownSandboxOnClaim(t *testing.T) {
	stub := &orphanOpsStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-orphan", OwnerState: cluster.PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "node-a",
		},
		hasPlace: true,
		claimErr: cluster.ErrUnknownSandbox,
	}
	h, cleanup := newOrphanOpsService(t, stub, true)
	defer cleanup()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/orphans/sb-orphan/reclaim-local", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	h.clusterReclaimOrphanLocal(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestSetNodeDrainState_GenericError(t *testing.T) {
	stub := &drainStubCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
		setErr: errors.New("fsm unavailable"),
	}
	h := drainTestHandler(t, stub)
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/nodes/node-b/drain", nil)
	req.SetPathValue("id", "node-b")
	rr := httptest.NewRecorder()
	h.clusterDrainNode(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestClusterForwardWrap_GenericOwnerError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &ownerOfStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		err:  errors.New("fsm read timeout"),
	}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	wrapped := h.clusterForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("local handler should not run")
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1", nil)
	req.SetPathValue("id", "sb-1")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestClusterInternalPlacementsQuery_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &placementPageStubCluster{
		Noop:       cluster.NewNoop("node-a", "http://node-a", ""),
		placements: []cluster.Placement{{SandboxID: "sb-q", OwnerNodeID: "node-a"}},
	}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/placements/query", strings.NewReader(`{"shard_count":2,"shards":[0]}`))
	h.clusterInternalPlacementsQuery(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterInternalPlacementsPage_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &placementPageStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		pageResp: cluster.PlacementPageResponse{
			Placements: []cluster.Placement{{SandboxID: "sb-page", OwnerNodeID: "node-a"}},
		},
	}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/placements/page", strings.NewReader(`{"limit":10}`))
	h.clusterInternalPlacementsPage(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterIngressRoute_NoAliveOwners(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&membersStubCluster{
		Noop:    cluster.NewNoop("node-a", "http://node-a", ""),
		members: []cluster.Member{},
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/ingress-route/sb-1", nil)
	req.SetPathValue("id", "sb-1")
	rr := httptest.NewRecorder()
	h.clusterIngressRoute(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterCreateWrap_LocalOnlyImageSelfCreate(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))

	body := `{"image":"e2b/sb-local:default","image_distribution_mode":"local_only"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(body))
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	if rt.createCalls != 1 {
		t.Fatalf("createCalls = %d, want 1", rt.createCalls)
	}
}

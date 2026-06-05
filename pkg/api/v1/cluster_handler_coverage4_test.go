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
	"github.com/aerol-ai/microvm/pkg/models"
)

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

type placementByNameStubCluster struct {
	*cluster.Noop
	ownerErr  error
	placement cluster.Placement
	hasPlace  bool
	owner     cluster.OwnerInfo
}

func (c *placementByNameStubCluster) OwnerOfName(string) (string, cluster.OwnerInfo, error) {
	if c.ownerErr != nil {
		return "sb-named", c.owner, c.ownerErr
	}
	return "sb-named", c.owner, nil
}

func (c *placementByNameStubCluster) PlacementOf(string) (cluster.Placement, bool) {
	return c.placement, c.hasPlace
}

func TestClusterForwardWrap_EmptyIDPassesThrough(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &handlers{deps: Deps{Service: service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil), Logger: logger}}

	localCalled := false
	wrapped := h.clusterForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		localCalled = true
		w.WriteHeader(http.StatusTeapot)
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	wrapped.ServeHTTP(rr, req)
	if !localCalled || rr.Code != http.StatusTeapot {
		t.Fatalf("localCalled=%v status=%d, want local handler", localCalled, rr.Code)
	}
}

func TestClusterForwardWrap_NilServicePassesThrough(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &handlers{deps: Deps{Logger: logger}}

	localCalled := false
	wrapped := h.clusterForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		localCalled = true
		w.WriteHeader(http.StatusAccepted)
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1", nil)
	req.SetPathValue("id", "sb-1")
	wrapped.ServeHTTP(rr, req)
	if !localCalled || rr.Code != http.StatusAccepted {
		t.Fatalf("localCalled=%v status=%d, want local handler", localCalled, rr.Code)
	}
}

func TestClusterCreateWrap_ReadBodyError(t *testing.T) {
	h := newHandlerNoStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", errReader{err: errors.New("read failed")})
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterCreateWrap_InvalidJSONWithBody(t *testing.T) {
	h := newHandlerNoStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{`))
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestClusterCreateWrap_MisdirectedTarget(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`))
	req.Header.Set(clusterCreateTargetHeader, "node-b")
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421; body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterCreateWrap_ForwardedMissingCreateID(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`))
	req.Header.Set(clusterCreateTargetHeader, "node-a")
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterCreateWrap_InvalidImageDistribution(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))

	body := `{"image":"alpine:3.20","image_distribution_mode":"not-a-real-mode"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(body))
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if rt.createCalls != 0 {
		t.Fatalf("createCalls = %d, want 0", rt.createCalls)
	}
}

func TestClusterCreateWrap_InvalidFailover(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))

	body := `{"image":"e2b/sb-local:default","image_distribution_mode":"local_only","failover":{"policy":"recreate"}}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(body))
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterCreateWrap_DrainedNodeLocalOnlyImage(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &drainStubCluster{
		Noop:        cluster.NewNoop("node-a", "http://node-a", ""),
		drainedView: map[string]bool{"node-a": true},
	}
	h, _ := newClusterCreateHarness(t, rt, stub)

	body := `{"image":"e2b/sb-local:default","image_distribution_mode":"local_only"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(body))
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if rt.createCalls != 0 {
		t.Fatalf("createCalls = %d, want 0 on drained node", rt.createCalls)
	}
}

func TestClusterListWrap_SkipsNonWorkerPeers(t *testing.T) {
	peerCalled := false
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		peerCalled = true
		_ = json.NewEncoder(w).Encode([]*models.Sandbox{{ID: "sb-remote"}})
	}))
	t.Cleanup(peer.Close)

	rt := &apiRecordingRuntime{}
	stub := &membersStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		members: []cluster.Member{
			{NodeID: "node-ingress", APIURL: peer.URL, Alive: true, Role: config.NodeRoleIngress},
		},
	}
	h, _ := newClusterCreateHarness(t, rt, stub)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	h.clusterListWrap(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if peerCalled {
		t.Fatal("ingress-only peer should not be queried")
	}
}

func TestClusterListWrap_LocalListFailure(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &membersStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, st := newClusterCreateHarness(t, rt, stub)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-local", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = st.Close()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	h.clusterListWrap(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 despite local list failure", rr.Code)
	}
}

func TestClusterListWrap_PeerInvalidJSON(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Cluster-Forwarded") != "1" {
			http.Error(w, "missing forwarded header", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not-json`))
	}))
	t.Cleanup(peer.Close)

	rt := &apiRecordingRuntime{}
	stub := &membersStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		members: []cluster.Member{
			{NodeID: "node-b", APIURL: peer.URL, Alive: true, Role: config.NodeRoleWorker},
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

func TestClusterListWrap_DedupePrefersLocal(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Cluster-Forwarded") != "1" {
			http.Error(w, "missing forwarded header", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode([]*models.Sandbox{
			{ID: "sb-dup", Image: "remote-image"},
			nil,
		})
	}))
	t.Cleanup(peer.Close)

	rt := &apiRecordingRuntime{}
	stub := &membersStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		members: []cluster.Member{
			{NodeID: "node-b", APIURL: peer.URL, Alive: true, Role: config.NodeRoleWorker},
		},
	}
	h, st := newClusterCreateHarness(t, rt, stub)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-dup", Image: "local-image", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	h.clusterListWrap(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var merged []*models.Sandbox
	if err := json.Unmarshal(rr.Body.Bytes(), &merged); err != nil {
		t.Fatalf("decode: %v", err)
	}
	dupCount := 0
	for _, sb := range merged {
		if sb == nil {
			continue
		}
		if sb.ID == "sb-dup" {
			dupCount++
			if sb.Image != "local-image" {
				t.Fatalf("deduped sandbox image = %q, want local-image", sb.Image)
			}
		}
	}
	if dupCount != 1 {
		t.Fatalf("sb-dup count = %d, want 1", dupCount)
	}
}

func TestClusterIngressRoute_NilService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &handlers{deps: Deps{Logger: logger}}
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/ingress-route/sb-1", nil)
	req.SetPathValue("id", "sb-1")
	rr := httptest.NewRecorder()
	h.clusterIngressRoute(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterRemoveMember_EmptyID(t *testing.T) {
	h := newHandlerNoStore(t)
	req := httptest.NewRequest(http.MethodDelete, "/v1/cluster/members/", nil)
	rr := httptest.NewRecorder()
	h.clusterRemoveMember(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestClusterInternalApply_ReadBodyError(t *testing.T) {
	h := newHandlerNoStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/apply", errReader{err: errors.New("read failed")})
	h.clusterInternalApply(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestClusterInternalPlacementByName_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	encoded := base64.RawURLEncoding.EncodeToString([]byte("known"))
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placement-by-name/"+encoded, nil)
	req.SetPathValue("name", encoded)
	rr := httptest.NewRecorder()
	h.clusterInternalPlacementByName(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterInternalPlacementByName_GenericOwnerError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&placementByNameStubCluster{
		Noop:     cluster.NewNoop("node-a", "http://node-a", ""),
		ownerErr: errors.New("fsm lookup failed"),
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	encoded := base64.RawURLEncoding.EncodeToString([]byte("known"))
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placement-by-name/"+encoded, nil)
	req.SetPathValue("name", encoded)
	rr := httptest.NewRecorder()
	h.clusterInternalPlacementByName(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestClusterInternalPlacementByName_OrphanedWithoutPlacement(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&placementByNameStubCluster{
		Noop:     cluster.NewNoop("node-a", "http://node-a", ""),
		ownerErr: cluster.ErrOrphaned,
		hasPlace: false,
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	encoded := base64.RawURLEncoding.EncodeToString([]byte("known"))
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placement-by-name/"+encoded, nil)
	req.SetPathValue("name", encoded)
	rr := httptest.NewRecorder()
	h.clusterInternalPlacementByName(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestClusterInternalPlacementByName_PlacementMissingAfterOwner(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&placementByNameStubCluster{
		Noop:     cluster.NewNoop("node-a", "http://node-a", ""),
		owner:    cluster.OwnerInfo{NodeID: "node-a", IsSelf: true},
		hasPlace: false,
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	encoded := base64.RawURLEncoding.EncodeToString([]byte("known"))
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placement-by-name/"+encoded, nil)
	req.SetPathValue("name", encoded)
	rr := httptest.NewRecorder()
	h.clusterInternalPlacementByName(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestWriteInternalPlacement_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	rr := httptest.NewRecorder()
	h.writeInternalPlacement(rr, "sb-1")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestWriteInternalPlacement_GenericOwnerError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&internalPlacementErrCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-1", OwnerNodeID: "node-a",
		},
		hasPlace: true,
		ownerErr: errors.New("owner lookup failed"),
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	h.writeInternalPlacement(rr, "sb-1")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestClusterInternalPlacementsQuery_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/placements/query", strings.NewReader(`{}`))
	h.clusterInternalPlacementsQuery(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterInternalPlacementsPage_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/placements/page", strings.NewReader(`{}`))
	h.clusterInternalPlacementsPage(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterReclaimOrphanLocal_GetSandboxStoreError(t *testing.T) {
	stub := &orphanOpsStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-orphan", OwnerState: cluster.PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "node-a",
		},
		hasPlace: true,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-orphan", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = st.Close()

	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/orphans/sb-orphan/reclaim-local", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	h.clusterReclaimOrphanLocal(rr, req)
	if rr.Code == http.StatusNoContent {
		t.Fatalf("expected store error, got 204")
	}
}

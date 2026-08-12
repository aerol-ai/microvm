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

type internalPlacementErrCluster struct {
	*cluster.Noop
	placement cluster.Placement
	hasPlace  bool
	owner     cluster.OwnerInfo
	ownerErr  error
}

func (c *internalPlacementErrCluster) PlacementOf(string) (cluster.Placement, bool) {
	return c.placement, c.hasPlace
}

func (c *internalPlacementErrCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return c.owner, c.ownerErr
}

func (c *internalPlacementErrCluster) OwnerOfName(name string) (string, cluster.OwnerInfo, error) {
	if name != "known" {
		return "", cluster.OwnerInfo{}, cluster.ErrUnknownSandbox
	}
	return "sb-named", c.owner, c.ownerErr
}

func TestWriteInternalPlacement_EmptyID(t *testing.T) {
	h := &handlers{deps: Deps{Service: service.New(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, nil, nil, nil), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	rr := httptest.NewRecorder()
	h.writeInternalPlacement(rr, "")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestWriteInternalPlacement_OrphanedOwner(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &internalPlacementErrCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-orph", OwnerState: cluster.PlacementOwnerStateOrphaned,
		},
		hasPlace: true,
		ownerErr: cluster.ErrOrphaned,
	}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	h.writeInternalPlacement(rr, "sb-orph")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var body cluster.PlacementLookupResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Orphaned {
		t.Fatal("expected orphaned=true")
	}
}

func TestClusterInternalPlacementByName_InvalidEncoding(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("node-a", "http://node-a", ""))
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placement-by-name/bad", nil)
	req.SetPathValue("name", "%%%")
	h.clusterInternalPlacementByName(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestClusterInternalPlacementByName_OrphanedLookup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &internalPlacementErrCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-named", OwnerState: cluster.PlacementOwnerStateOrphaned,
		},
		hasPlace: true,
		ownerErr: cluster.ErrOrphaned,
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

func TestClusterInternalRecoveryGet_StoreError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &recoveryBlobStubCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
		getErr: errors.New("store read failed"),
	}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/recovery/ref-1", nil)
	req.SetPathValue("ref", "ref-1")
	h.clusterInternalRecoveryGet(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestClusterInternalPlacementsQueryAndPage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&placementPageStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placements: []cluster.Placement{
			{SandboxID: "sb-q", SecretRef: "secret"},
		},
		pageResp: cluster.PlacementPageResponse{
			Placements:    []cluster.Placement{{SandboxID: "sb-page"}},
			NextPageToken: "cursor-1",
		},
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/placements/query", strings.NewReader(`{"shard":0,"shard_count":4}`))
	h.clusterInternalPlacementsQuery(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("query status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/placements/page", strings.NewReader(`{"limit":10}`))
	h.clusterInternalPlacementsPage(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("page status = %d, want 200", rr.Code)
	}
}

func TestClusterLeader_ReturnsLeaderID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&leaderStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", ""), leader: "node-b"})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	h.clusterLeader(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/leader", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["leader"] != "node-b" {
		t.Fatalf("leader = %v, want node-b", body["leader"])
	}
}

type leaderStubCluster struct {
	*cluster.Noop
	leader string
}

func (c *leaderStubCluster) Leader() string { return c.leader }

func TestClusterForwardWrap_SelfOwnerRunsLocalHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &ownerOfStubCluster{
		Noop:  cluster.NewNoop("node-a", "http://node-a", ""),
		owner: cluster.OwnerInfo{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	ran := false
	wrapped := h.clusterForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-self", nil)
	req.SetPathValue("id", "sb-self")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if !ran {
		t.Fatal("expected local handler to run for self owner")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestClusterListWrap_SkipsFailedPeerAndDedupes(t *testing.T) {
	goodPeer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Cluster-Forwarded") != "1" {
			http.Error(w, "missing forward header", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode([]*models.Sandbox{
			{ID: "sb-dup"},
			{ID: "sb-remote"},
		})
	}))
	t.Cleanup(goodPeer.Close)

	h, st := newClusterCreateHarness(t, &apiRecordingRuntime{}, &membersStubCluster{
		Noop:           cluster.NewNoop("node-a", "http://node-a", ""),
		internalClient: goodPeer.Client(),
		members: []cluster.Member{
			{NodeID: "node-b", APIURL: goodPeer.URL, InternalURL: goodPeer.URL, Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "node-c", APIURL: "http://127.0.0.1:1", InternalURL: "http://127.0.0.1:1", Alive: true, Role: config.NodeRoleWorker},
		},
	})
	now := time.Now()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-dup", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes?tag.owner=alice", nil)
	h.clusterListWrap(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got []*models.Sandbox
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	ids := map[string]int{}
	for _, sb := range got {
		ids[sb.ID]++
	}
	if ids["sb-dup"] != 1 || ids["sb-remote"] != 1 {
		t.Fatalf("ids = %v, want sb-dup once and sb-remote once", ids)
	}
}

func TestClusterReclaimOrphanLocal_ClaimNotLeader(t *testing.T) {
	stub := &orphanOpsStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-orphan", OwnerState: cluster.PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "node-a",
		},
		hasPlace: true,
		claimErr: cluster.ErrNotLeader,
	}
	h, cleanup := newOrphanOpsService(t, stub, true)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/orphans/sb-orphan/reclaim-local", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	h.clusterReclaimOrphanLocal(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterDeleteOrphan_NotLeader(t *testing.T) {
	stub := &orphanOpsStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-orphan", OwnerState: cluster.PlacementOwnerStateOrphaned,
		},
		hasPlace:  true,
		deleteErr: cluster.ErrNotLeader,
	}
	h, cleanup := newOrphanOpsService(t, stub, false)
	defer cleanup()

	req := httptest.NewRequest(http.MethodDelete, "/v1/cluster/orphans/sb-orphan", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	h.clusterDeleteOrphan(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestWriteInternalPlacement_OwnerLookupError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &internalPlacementErrCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{SandboxID: "sb-x", OwnerNodeID: "node-a"},
		hasPlace:  true,
		ownerErr:  errors.New("fsm read failed"),
	}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	h.writeInternalPlacement(rr, "sb-x")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestClusterLeader_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	rr := httptest.NewRecorder()
	h.clusterLeader(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/leader", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestClusterMembers_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	rr := httptest.NewRecorder()
	h.clusterMembers(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/members", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestClusterInternalDrainState_NilCluster(t *testing.T) {
	h := newHandlerNilCluster(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/drain-state/node-a", nil)
	req.SetPathValue("id", "node-a")
	h.clusterInternalDrainState(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterSandboxIndex_ListFailureStillReturnsPage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	_ = st.Close()
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&placementPageStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		pageResp: cluster.PlacementPageResponse{
			Placements: []cluster.Placement{{SandboxID: "sb-page"}},
		},
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/sandbox-index?limit=5", nil)
	h.writeClusterSandboxIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterInternalDrainState_ReturnsDrained(t *testing.T) {
	stub := &drainStubCluster{
		Noop:        cluster.NewNoop("node-a", "http://node-a", ""),
		drainedView: map[string]bool{"node-b": true},
	}
	h := drainTestHandler(t, stub)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/drain-state/node-b", nil)
	req.SetPathValue("id", "node-b")
	h.clusterInternalDrainState(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body cluster.DrainStateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Drained {
		t.Fatal("expected drained=true")
	}
}

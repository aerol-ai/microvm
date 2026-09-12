package daytona

import (
	"bytes"
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
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestFilterFacadeLocalToPage(t *testing.T) {
	type item struct{ ID string }
	local := []item{{ID: "sb-1"}, {ID: "sb-2"}, {ID: ""}}
	if got := filterFacadeLocalToPage(local, nil, "", func(it item) string { return it.ID }); len(got) != 3 {
		t.Fatalf("cold start = %d", len(got))
	}
	if got := filterFacadeLocalToPage(local, nil, "tok", func(it item) string { return it.ID }); got != nil {
		t.Fatalf("terminal nil placements = %+v", got)
	}
	got := filterFacadeLocalToPage(local, []cluster.Placement{{SandboxID: "sb-2"}}, "", func(it item) string { return it.ID })
	if len(got) != 1 || got[0].ID != "sb-2" {
		t.Fatalf("page filter = %+v", got)
	}
}

func TestReplaceLabelsBadJSON(t *testing.T) {
	handler, svc, _ := newDaytonaVolumesTestEnv(t)
	sb, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/daytona/sandbox/"+sb.ID+"/labels", bytes.NewReader([]byte(`{bad`)))
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("expected bad JSON rejection")
	}

	body, _ := json.Marshal(map[string]string{"env": "dev"})
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/daytona/sandbox/"+sb.ID+"/labels", bytes.NewReader(body))
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("labels status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestDestroySandboxDestroyErrorCoverage95(t *testing.T) {
	_, st, rt, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-destroy-err", Name: "destroy-err", Status: models.SandboxStatusStarted,
		ContainerID: "ctr", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	rt.destroyErr = errors.New("destroy failed")

	req := httptest.NewRequest(http.MethodDelete, "/daytona/sandbox/destroy-err", nil)
	req.SetPathValue("idOrName", "destroy-err")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("expected destroy error, got %d", rr.Code)
	}
}

func TestListSandboxesPaginatedBeyondTotalCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	if err := st.Upsert(context.Background(), &models.Sandbox{
		ID: "sb-page", Name: "only-one", Status: models.SandboxStatusStarted,
		ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated?page=99&limit=10", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var page paginatedSandboxesResponse
	if err := json.NewDecoder(rr.Body).Decode(&page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("expected empty page, got %+v", page.Items)
	}
}

func TestSetAutoArchiveIntervalNegativeCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	if err := st.Upsert(context.Background(), &models.Sandbox{
		ID: "sb-neg-archive", Name: "neg-archive", Status: models.SandboxStatusStarted,
		ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/neg-archive/autoarchive/-1", nil)
	req.SetPathValue("idOrName", "neg-archive")
	req.SetPathValue("interval", "-1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestPreviewURLExposePortErrorCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	if err := st.Upsert(context.Background(), &models.Sandbox{
		ID: "sb-preview-err", Name: "preview-err", Status: models.SandboxStatusStarted,
		ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/preview-err/ports/99999/preview-url", nil)
	req.SetPathValue("idOrName", "preview-err")
	req.SetPathValue("port", "99999")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("expected expose error, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestLoadSandboxMetaNilSandboxCoverage95(t *testing.T) {
	svc, _, _, _ := newHandlerExtraTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	meta, err := h.loadSandboxMeta(context.Background(), nil)
	if err != nil {
		t.Fatalf("loadSandboxMeta(nil): %v", err)
	}
	if meta.Labels == nil {
		t.Fatal("expected initialized labels map")
	}
}

func TestTranslateCreateSandboxRequestRejectionsCoverage95(t *testing.T) {
	h := newHandlers(Deps{})
	netAllow := "github.com"
	_, _, err := h.translateCreateSandboxRequest(context.Background(), createSandboxRequest{
		NetworkAllowList: &netAllow,
	})
	if err == nil || !strings.Contains(err.Error(), "networkAllowList") {
		t.Fatalf("networkAllowList err = %v", err)
	}

	gpu := int32(1)
	_, _, err = h.translateCreateSandboxRequest(context.Background(), createSandboxRequest{Gpu: &gpu})
	if err == nil || !strings.Contains(err.Error(), "gpu") {
		t.Fatalf("gpu err = %v", err)
	}
}

type onLogImageBuilder struct {
	fakeImageBuilder
}

func (b *onLogImageBuilder) BuildImage(ctx context.Context, req docker.BuildImageRequest) error {
	if req.OnLog != nil {
		req.OnLog("layer 1/1")
	}
	return b.fakeImageBuilder.BuildImage(ctx, req)
}

func TestResolveBuildInfoOnLogCoverage95(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := newHandlers(Deps{
		Logger:  logger,
		Builder: &onLogImageBuilder{},
	})
	_, _, err := h.resolveBuildInfo(context.Background(), &buildInfoRequest{
		DockerfileContent: stringPtr("FROM alpine\nRUN echo hi"),
	})
	if err != nil {
		t.Fatalf("resolveBuildInfo: %v", err)
	}
}

// facadeListCluster is intentionally not *cluster.Noop so listFacadeClusterItems
// takes the real placement-page merge instead of the standalone short-circuit.
// facadeListCluster is intentionally not *cluster.Noop so listFacadeClusterItems
// takes the real placement-page merge instead of the standalone short-circuit.
type facadeListCluster struct {
	*cluster.Noop
	members       []cluster.Member
	placements    []cluster.Placement
	authoritative bool
	byID          map[string]cluster.Member
}

func (c *facadeListCluster) Members() []cluster.Member { return c.members }

func (c *facadeListCluster) PlacementPage(req cluster.PlacementPageRequest) cluster.PlacementPageResponse {
	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}
	out := make([]cluster.Placement, 0, limit)
	for _, p := range c.placements {
		if req.OwnerRef != "" && p.OwnerRef != req.OwnerRef {
			continue
		}
		out = append(out, p)
		if len(out) >= limit {
			break
		}
	}
	return cluster.PlacementPageResponse{Placements: out, Authoritative: c.authoritative, NextPageToken: "next-tok"}
}

func (c *facadeListCluster) LookupMember(id string) (cluster.Member, bool) {
	if c.byID != nil {
		m, ok := c.byID[id]
		return m, ok
	}
	for _, m := range c.members {
		if m.NodeID == id {
			return m, true
		}
	}
	return cluster.Member{}, false
}

func TestListFacadeClusterItemsBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	local := []sandboxResponse{{ID: "sb-local"}, {ID: "sb-other"}}

	t.Run("forwarded_and_nil_service", func(t *testing.T) {
		h := newHandlers(Deps{Logger: logger})
		fwd := httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil)
		fwd.Header.Set("X-Cluster-Forwarded", "1")
		items, _, _, ready := h.listFacadeClusterItems(fwd, local)
		if !ready || len(items) != 2 {
			t.Fatalf("forwarded: items=%d ready=%v", len(items), ready)
		}
		items, _, _, ready = h.listFacadeClusterItems(httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil), local)
		if !ready || len(items) != 2 {
			t.Fatalf("nil service: items=%d ready=%v", len(items), ready)
		}
	})

	t.Run("nil_cluster", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.ClearClusterForTest()
		h := newHandlers(Deps{Service: svc, Logger: logger})
		items, _, _, ready := h.listFacadeClusterItems(httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil), local)
		if !ready || len(items) != 2 {
			t.Fatalf("nil cluster: items=%d ready=%v", len(items), ready)
		}
	})

	t.Run("view_not_ready", func(t *testing.T) {
		members := make([]cluster.Member, 0, 300)
		members = append(members, cluster.Member{NodeID: "self", Alive: true, Role: config.NodeRoleMixed})
		for i := 0; i < 270; i++ {
			members = append(members, cluster.Member{
				NodeID: "w-" + string(rune('a'+(i%26))) + string(rune('0'+i%10)),
				Alive:  true, Role: config.NodeRoleWorker, InternalURL: "https://w",
			})
		}
		// Distinct IDs so SelectPeersForPage counts >256 alive owners.
		members = members[:1]
		for i := 0; i < 270; i++ {
			members = append(members, cluster.Member{
				NodeID:      "owner-" + itoa(i),
				Alive:       true,
				Role:        config.NodeRoleWorker,
				InternalURL: "https://owner-" + itoa(i),
			})
		}
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(&facadeListCluster{
			Noop:    cluster.NewNoop("self", "http://self", ""),
			members: members,
		})
		h := newHandlers(Deps{Service: svc, Logger: logger})
		items, cov, _, ready := h.listFacadeClusterItems(httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil), local)
		if ready || items != nil || !cov.Partial {
			t.Fatalf("want view not ready, ready=%v items=%v partial=%v", ready, items, cov.Partial)
		}
	})

	t.Run("merge_and_missing_owners", func(t *testing.T) {
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode([]sandboxResponse{{ID: "sb-peer"}})
		}))
		t.Cleanup(peer.Close)

		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		c := &facadeListCluster{
			Noop:          cluster.NewNoop("self", "http://self", ""),
			authoritative: true,
			members: []cluster.Member{
				{NodeID: "self", Alive: true, Role: config.NodeRoleMixed},
				{NodeID: "peer-a", Alive: true, Role: config.NodeRoleWorker, InternalURL: peer.URL},
			},
			placements: []cluster.Placement{
				{SandboxID: "sb-local", OwnerNodeID: "self"},
				{SandboxID: "sb-peer", OwnerNodeID: "peer-a"},
				{SandboxID: "sb-ghost", OwnerNodeID: "missing-owner"},
			},
			byID: map[string]cluster.Member{
				"peer-a": {NodeID: "peer-a", Alive: true, Role: config.NodeRoleWorker, InternalURL: peer.URL},
			},
		}
		svc.AttachCluster(c)
		h := newHandlers(Deps{Service: svc, Logger: logger})
		req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil)
		req.Header.Set("Authorization", "Bearer t")
		items, cov, next, ready := h.listFacadeClusterItems(req, local)
		if !ready || next != "next-tok" {
			t.Fatalf("ready=%v next=%q", ready, next)
		}
		if !cov.Partial {
			t.Fatalf("missing owner should mark partial: %+v", cov)
		}
		ids := map[string]bool{}
		for _, it := range items {
			ids[it.ID] = true
		}
		if !ids["sb-local"] {
			t.Fatalf("items = %+v, want local page row", items)
		}
	})
}

func TestListSandboxesClusterViewNotReadyAndPageToken(t *testing.T) {
	handler, svc, _ := newDaytonaVolumesTestEnv(t)
	members := []cluster.Member{{NodeID: "self", Alive: true, Role: config.NodeRoleMixed}}
	for i := 0; i < 270; i++ {
		members = append(members, cluster.Member{
			NodeID: "w-" + itoa(i), Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://w",
		})
	}
	svc.AttachCluster(&facadeListCluster{
		Noop:    cluster.NewNoop("self", "http://self", ""),
		members: members,
	})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil))
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("list status=%d retry=%q body=%s", rr.Code, rr.Header().Get("Retry-After"), rr.Body.String())
	}

	pageRR := httptest.NewRecorder()
	handler.ServeHTTP(pageRR, httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated?page=2", nil))
	if pageRR.Code != http.StatusBadRequest {
		t.Fatalf("page>1 without cursor status=%d body=%s", pageRR.Code, pageRR.Body.String())
	}
}

func TestClusterListModeGuards(t *testing.T) {
	if clusterListMode(nil, httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("nil service")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fwd := httptest.NewRequest(http.MethodGet, "/", nil)
	fwd.Header.Set("X-Cluster-Forwarded", "1")
	if clusterListMode(svc, fwd) {
		t.Fatal("forwarded hop")
	}
	svc.ClearClusterForTest()
	if clusterListMode(svc, httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("nil cluster")
	}
	svc.AttachCluster(&facadeListCluster{Noop: cluster.NewNoop("self", "http://self", "")})
	if !clusterListMode(svc, httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("wrapped cluster should enable cluster list mode")
	}
}

func TestListSandboxesPaginatedClusterReady(t *testing.T) {
	handler, svc, _ := newDaytonaVolumesTestEnv(t)
	ctx := context.Background()
	sb, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	svc.AttachCluster(&facadeListCluster{
		Noop:          cluster.NewNoop("self", "http://self", ""),
		authoritative: true,
		members:       []cluster.Member{{NodeID: "self", Alive: true, Role: config.NodeRoleMixed}},
		placements:    []cluster.Placement{{SandboxID: sb.ID, OwnerNodeID: "self"}},
	})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated?page=1&limit=10", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

func TestPersistSandboxMetaAndReplaceLabelsErrors(t *testing.T) {
	handler, svc, st := newDaytonaVolumesTestEnv(t)
	sb, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	_ = st.Close()
	h := newHandlers(Deps{Service: svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := h.persistSandboxMeta(context.Background(), sb.ID, sandboxMeta{}); err == nil {
		t.Fatal("expected persist failure on closed store")
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/daytona/sandbox/"+sb.ID+"/labels", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("expected replace-labels failure after store close")
	}
}

func TestDestroySandboxSuccessCoverage95(t *testing.T) {
	svc, st, rt, handler := newHandlerExtraTestEnv(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-destroy", Name: "destroy-me", Status: models.SandboxStatusStarted,
		AuditIncarnationID: "inc-sb-destroy",
		ContainerID:        "ctr-destroy", ContainerIP: "10.0.0.9",
		ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	stateJSON, err := sandboxMetaToState(sandboxMeta{Snapshot: stringPtr("snap-1"), Target: "dev"})
	if err != nil {
		t.Fatalf("sandboxMetaToState: %v", err)
	}
	if err := st.UpsertCompatState(ctx, sb.ID, models.FacadeDaytona, stateJSON); err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}
	rt.inspectState = &models.SandboxRuntimeState{SandboxID: sb.ID, Status: models.SandboxStatusStarted}

	req := httptest.NewRequest(http.MethodDelete, "/daytona/sandbox/destroy-me", nil)
	req.SetPathValue("idOrName", "destroy-me")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := svc.GetSandbox(ctx, sb.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("sandbox still exists: %v", err)
	}
}

func TestStartStopSandboxSuccessCoverage95(t *testing.T) {
	_, st, rt, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-toggle", Name: "toggle", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-toggle", ContainerIP: "10.0.0.8",
		ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	rt.inspectState = &models.SandboxRuntimeState{SandboxID: sb.ID, Status: models.SandboxStatusStarted}
	rt.startState = &models.SandboxRuntimeState{SandboxID: sb.ID, Status: models.SandboxStatusStarted}

	stopRR := httptest.NewRecorder()
	stopReq := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/toggle/stop", nil)
	stopReq.SetPathValue("idOrName", "toggle")
	handler.ServeHTTP(stopRR, stopReq)
	if stopRR.Code != http.StatusOK {
		t.Fatalf("stop status = %d", stopRR.Code)
	}

	startRR := httptest.NewRecorder()
	startReq := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/toggle/start", nil)
	startReq.SetPathValue("idOrName", "toggle")
	handler.ServeHTTP(startRR, startReq)
	if startRR.Code != http.StatusOK {
		t.Fatalf("start status = %d", startRR.Code)
	}
}

func TestUpdateIdleLifecycleClearIntervalsCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-idle", Name: "idle-sb", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-idle", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
		Lifecycle: models.Lifecycle{
			StopIfIdleFor:    5 * time.Minute,
			DestroyIfIdleFor: 10 * time.Minute,
		},
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/idle-sb/autostop/0", nil)
	req.SetPathValue("idOrName", "idle-sb")
	req.SetPathValue("interval", "0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("autostop clear status = %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/idle-sb/autodelete/0", nil)
	req2.SetPathValue("idOrName", "idle-sb")
	req2.SetPathValue("interval", "0")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("autodelete clear status = %d", rr2.Code)
	}
}

func TestSetAutoArchiveIntervalSuccessCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-archive", Name: "archive-sb", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-archive", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/archive-sb/autoarchive/30", nil)
	req.SetPathValue("idOrName", "archive-sb")
	req.SetPathValue("interval", "30")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateSandboxNameConflictCoverage95(t *testing.T) {
	_, st, rt, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	if err := st.Upsert(context.Background(), &models.Sandbox{
		ID: "sb-existing", Name: "taken-name", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	rt.createState = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted}
	rt.createErr = store.ErrSandboxNameConflict

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/daytona/sandbox",
		strings.NewReader(`{"name":"taken-name","buildInfo":{"dockerfileContent":"FROM alpine"}}`)))
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateSandboxCreateTimeoutCoverage95(t *testing.T) {
	_, _, rt, handler := newHandlerExtraTestEnv(t)
	rt.createState = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted}
	rt.createErr = context.DeadlineExceeded

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/daytona/sandbox",
		strings.NewReader(`{"name":"timeout-sb","buildInfo":{"dockerfileContent":"FROM alpine"}}`)))
	if rr.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPreviewURLSuccessCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-preview", Name: "preview-sb", Status: models.SandboxStatusStarted,
		PublicURL: "https://preview.example.com", ToolboxEnabled: true,
		ContainerID: "ctr-preview", CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/preview-sb/ports/8080/preview-url", nil)
	req.SetPathValue("idOrName", "preview-sb")
	req.SetPathValue("port", "8080")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("preview status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestTranslateCreateSandboxRequestLifecycleCoverage95(t *testing.T) {
	h := newHandlers(Deps{})
	autoStop := int32(5)
	autoDelete := int32(10)
	req, built, err := h.translateCreateSandboxRequest(context.Background(), createSandboxRequest{
		BuildInfo:          &buildInfoRequest{DockerfileContent: stringPtr("FROM alpine")},
		AutoStopInterval:   &autoStop,
		AutoDeleteInterval: &autoDelete,
	})
	if err != nil || built != "" {
		t.Fatalf("err=%v built=%q", err, built)
	}
	if req.Lifecycle == nil || req.Lifecycle.StopIfIdleFor == 0 {
		t.Fatalf("lifecycle = %+v", req.Lifecycle)
	}
}

func TestListSandboxMetaCoverage95(t *testing.T) {
	svc, st, _, _ := newHandlerExtraTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx := context.Background()
	now := time.Now().UTC()
	sb := &models.Sandbox{ID: "sb-list-meta", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now}
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := st.UpsertCompatState(ctx, sb.ID, models.FacadeDaytona, `{"target":"dev"}`); err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}
	items, err := h.listSandboxMeta(ctx)
	if err != nil || items[sb.ID].Target != "dev" {
		t.Fatalf("items = %+v err=%v", items, err)
	}
}

func TestResolveSandboxByNameCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-by-name", Name: "lookup-name", Status: models.SandboxStatusStarted,
		ToolboxEnabled: true, ContainerID: "ctr", CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/lookup-name", nil)
	req.SetPathValue("idOrName", "lookup-name")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPersistSandboxMetaCoverage95(t *testing.T) {
	svc, st, _, _ := newHandlerExtraTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.Upsert(ctx, &models.Sandbox{
		ID: "sb-persist", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	meta := sandboxMeta{
		Snapshot: stringPtr("snap"), Target: "dev", NetworkAllowList: stringPtr("0.0.0.0/0"),
		AutoArchiveInterval: float32Ptr(10),
	}
	if err := h.persistSandboxMeta(ctx, "sb-persist", meta); err != nil {
		t.Fatalf("persistSandboxMeta: %v", err)
	}
}

func TestCreateImageFromSnapshotNameCoverage95(t *testing.T) {
	svc, st, _, _ := newHandlerExtraTestEnv(t)
	ctx := context.Background()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name: "snap-img:default", Image: "resolved:img", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	h := newHandlers(Deps{Service: svc})
	img, built, err := h.createImage(ctx, createSandboxRequest{Snapshot: stringPtr("snap-img:default")})
	if err != nil || built != "" || img != "resolved:img" {
		t.Fatalf("createImage = (%q, %q, %v)", img, built, err)
	}
}

func TestCreateImageDefaultUbuntuCoverage95(t *testing.T) {
	h := newHandlers(Deps{})
	img, built, err := h.createImage(context.Background(), createSandboxRequest{})
	if err != nil || built != "" || img != "ubuntu:22.04" {
		t.Fatalf("createImage = (%q, %q, %v)", img, built, err)
	}
}

func TestDestroySandboxLoadMetaErrorCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-bad-meta", Name: "bad-meta", Status: models.SandboxStatusStarted,
		ContainerID: "ctr", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := st.UpsertCompatState(context.Background(), sb.ID, models.FacadeDaytona, "{bad"); err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/daytona/sandbox/bad-meta", nil)
	req.SetPathValue("idOrName", "bad-meta")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("expected load meta failure")
	}
}

func TestCreateSandboxImageRollbackOnCreateFailureCoverage95(t *testing.T) {
	svc, _, rt, _ := newHandlerExtraTestEnv(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	b := &rollbackTrackingBuilder{}
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc, Logger: logger, Builder: b,
		Auth: func(next http.Handler) http.Handler { return next },
	})
	rt.createState = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted}
	rt.createErr = errors.New("create failed")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/daytona/sandbox",
		strings.NewReader(`{"name":"rollback-img","buildInfo":{"dockerfileContent":"FROM alpine\nRUN echo hi"}}`)))
	if rr.Code == http.StatusCreated {
		t.Fatal("expected create failure")
	}
	if len(b.removed) == 0 {
		t.Fatal("expected built image rollback")
	}
}

type rollbackTrackingBuilder struct {
	handlersExtraFakeImageBuilder
	removed []string
}

func (b *rollbackTrackingBuilder) RemoveImage(_ context.Context, ref string) error {
	b.removed = append(b.removed, ref)
	return nil
}

func TestResizeSandboxSuccessCoverage95(t *testing.T) {
	_, st, rt, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-resize", Name: "resize-me", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-resize", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	rt.inspectState = &models.SandboxRuntimeState{SandboxID: sb.ID, Status: models.SandboxStatusStarted}

	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/resize-me/resize", strings.NewReader(`{"cpu":2,"memory":2,"disk":2}`))
	req.SetPathValue("idOrName", "resize-me")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("resize status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSetAutoArchiveIntervalClearCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-arch-clear", Name: "arch-clear", Status: models.SandboxStatusStarted,
		ContainerID: "ctr", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/arch-clear/autoarchive/0", nil)
	req.SetPathValue("idOrName", "arch-clear")
	req.SetPathValue("interval", "0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateSnapshotOnSandboxSuccessCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-snap", Name: "snap-me", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-snap", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/snap-me/snapshot", strings.NewReader(`{"name":"my-snap"}`))
	req.SetPathValue("idOrName", "snap-me")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("snapshot status = %d body=%s", rr.Code, rr.Body.String())
	}
}

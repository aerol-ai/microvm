package e2b

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

func TestFilterE2BLocalToPage(t *testing.T) {
	local := []listedSandboxResponse{{SandboxID: "sb-1"}, {SandboxID: "sb-2"}}
	if got := filterE2BLocalToPage(local, nil, ""); len(got) != 2 {
		t.Fatalf("cold start = %d", len(got))
	}
	if got := filterE2BLocalToPage(local, nil, "tok"); got != nil {
		t.Fatalf("terminal = %+v", got)
	}
	got := filterE2BLocalToPage(local, []cluster.Placement{{SandboxID: "sb-2"}}, "")
	if len(got) != 1 || got[0].SandboxID != "sb-2" {
		t.Fatalf("page filter = %+v", got)
	}
}

// e2bFacadeListCluster is not *cluster.Noop so listFacadeClusterItems runs the
// placement-page merge instead of the standalone short-circuit.
// e2bFacadeListCluster is not *cluster.Noop so listFacadeClusterItems runs the
// placement-page merge instead of the standalone short-circuit.
type e2bFacadeListCluster struct {
	*cluster.Noop
	members       []cluster.Member
	placements    []cluster.Placement
	authoritative bool
	next          string
	byID          map[string]cluster.Member
}

func (c *e2bFacadeListCluster) Members() []cluster.Member { return c.members }

func (c *e2bFacadeListCluster) PlacementPage(req cluster.PlacementPageRequest) cluster.PlacementPageResponse {
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
	return cluster.PlacementPageResponse{Placements: out, Authoritative: c.authoritative, NextPageToken: c.next}
}

func (c *e2bFacadeListCluster) LookupMember(id string) (cluster.Member, bool) {
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

func e2bItoa(i int) string {
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

func TestListFacadeClusterItemsE2BBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	local := []listedSandboxResponse{{SandboxID: "sb-local"}, {SandboxID: "sb-other"}}

	t.Run("forwarded_and_nil_service", func(t *testing.T) {
		h := newHandlers(Deps{Logger: logger})
		fwd := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil)
		fwd.Header.Set("X-Cluster-Forwarded", "1")
		items, _, _, ready := h.listFacadeClusterItems(fwd, local)
		if !ready || len(items) != 2 {
			t.Fatalf("forwarded: items=%d ready=%v", len(items), ready)
		}
		items, _, _, ready = h.listFacadeClusterItems(httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil), local)
		if !ready || len(items) != 2 {
			t.Fatalf("nil service: items=%d ready=%v", len(items), ready)
		}
	})

	t.Run("nil_cluster", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.ClearClusterForTest()
		h := newHandlers(Deps{Service: svc, Logger: logger})
		items, _, _, ready := h.listFacadeClusterItems(httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil), local)
		if !ready || len(items) != 2 {
			t.Fatalf("nil cluster: items=%d ready=%v", len(items), ready)
		}
	})

	t.Run("view_not_ready", func(t *testing.T) {
		members := []cluster.Member{{NodeID: "self", Alive: true, Role: config.NodeRoleMixed}}
		for i := 0; i < 270; i++ {
			members = append(members, cluster.Member{
				NodeID: "w-" + e2bItoa(i), Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://w",
			})
		}
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(&e2bFacadeListCluster{Noop: cluster.NewNoop("self", "http://self", ""), members: members})
		h := newHandlers(Deps{Service: svc, Logger: logger})
		items, cov, _, ready := h.listFacadeClusterItems(httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil), local)
		if ready || items != nil || !cov.Partial {
			t.Fatalf("want view not ready, ready=%v partial=%v", ready, cov.Partial)
		}
	})

	t.Run("merge_and_missing_owners", func(t *testing.T) {
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode([]listedSandboxResponse{{SandboxID: "sb-peer"}})
		}))
		t.Cleanup(peer.Close)
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		c := &e2bFacadeListCluster{
			Noop:          cluster.NewNoop("self", "http://self", ""),
			authoritative: true,
			next:          "e2b-next",
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
		req := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil)
		req.Header.Set("Authorization", "Bearer t")
		items, cov, next, ready := h.listFacadeClusterItems(req, local)
		if !ready || next != "e2b-next" || !cov.Partial {
			t.Fatalf("ready=%v next=%q cov=%+v items=%+v", ready, next, cov, items)
		}
	})
}

func TestListSandboxesClusterModeAndFilters(t *testing.T) {
	svc, _, handler := newE2BHandlerTestEnv(t)
	ctx := context.Background()
	created, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "ubuntu:22.04"})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}

	members := []cluster.Member{{NodeID: "self", Alive: true, Role: config.NodeRoleMixed}}
	for i := 0; i < 270; i++ {
		members = append(members, cluster.Member{
			NodeID: "w-" + e2bItoa(i), Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://w",
		})
	}
	svc.AttachCluster(&e2bFacadeListCluster{Noop: cluster.NewNoop("self", "http://self", ""), members: members})

	notReady := httptest.NewRecorder()
	handler.ServeHTTP(notReady, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil))
	if notReady.Code != http.StatusServiceUnavailable {
		t.Fatalf("not ready status=%d body=%s", notReady.Code, notReady.Body.String())
	}

	numeric := httptest.NewRecorder()
	handler.ServeHTTP(numeric, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?nextToken=10", nil))
	if numeric.Code != http.StatusBadRequest {
		t.Fatalf("numeric nextToken status=%d body=%s", numeric.Code, numeric.Body.String())
	}

	svc.AttachCluster(&e2bFacadeListCluster{
		Noop:          cluster.NewNoop("self", "http://self", ""),
		authoritative: true,
		next:          "more",
		members:       []cluster.Member{{NodeID: "self", Alive: true, Role: config.NodeRoleMixed}},
		placements:    []cluster.Placement{{SandboxID: created.ID, OwnerNodeID: "self"}},
	})
	okRR := httptest.NewRecorder()
	handler.ServeHTTP(okRR, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?nextToken=opaque-cursor", nil))
	if okRR.Code != http.StatusOK {
		t.Fatalf("opaque nextToken status=%d body=%s", okRR.Code, okRR.Body.String())
	}
	if okRR.Header().Get("x-next-token") != "more" {
		t.Fatalf("x-next-token = %q", okRR.Header().Get("x-next-token"))
	}

	peerRR := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?ids="+created.ID, nil)
	req.Header.Set("X-Cluster-Forwarded", "1")
	handler.ServeHTTP(peerRR, req)
	if peerRR.Code != http.StatusOK {
		t.Fatalf("forwarded ids filter status=%d", peerRR.Code)
	}

	if clusterListMode(nil, httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("nil service")
	}
	fwd := httptest.NewRequest(http.MethodGet, "/", nil)
	fwd.Header.Set("X-Cluster-Forwarded", "1")
	if clusterListMode(svc, fwd) {
		t.Fatal("forwarded hop")
	}
}

func TestListSandboxesNilService(t *testing.T) {
	h := newHandlers(Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	rr := httptest.NewRecorder()
	h.listSandboxes(rr, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("nil service status=%d", rr.Code)
	}
}

func TestTranslateCreateSandboxRequestWasmPaths(t *testing.T) {
	svc, _, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})

	wasmReq, meta, err := h.translateCreateSandboxRequest(context.Background(), createSandboxRequest{
		TemplateID: "wasm-mod",
		Timeout:    intPtr(120),
		Metadata: map[string]any{
			"runtime":    models.RuntimeWasm,
			"module_ref": "file:///tmp/demo.wasm",
			"team":       "wasm",
		},
	})
	if err != nil {
		t.Fatalf("wasm translate: err=%v", err)
	}
	if wasmReq.Runtime != models.RuntimeWasm || wasmReq.ModuleRef != "file:///tmp/demo.wasm" {
		t.Fatalf("wasm req = %+v", wasmReq)
	}
	if meta.TemplateID != "wasm-mod" {
		t.Fatalf("meta = %+v", meta)
	}
	if wasmReq.Env == nil || wasmReq.Lifecycle == nil {
		t.Fatalf("expected env and lifecycle on wasm req")
	}
	if wasmReq.AllowPublicTraffic == nil || !*wasmReq.AllowPublicTraffic {
		t.Fatalf("expected default public traffic true")
	}

	_, _, err = h.translateCreateSandboxRequest(context.Background(), createSandboxRequest{
		TemplateID: "wasm-mod",
		Timeout:    intPtr(120),
		Metadata: map[string]any{
			"runtime":    models.RuntimeWasm,
			"module_ref": "file:///tmp/demo.wasm",
		},
		Network: &sandboxNetworkRequest{AllowOut: []string{"10.0.0.0/8"}},
	})
	if err == nil {
		t.Fatal("expected wasm egress rejection")
	}
	var reqErr requestError
	if !errors.As(err, &reqErr) || reqErr.status != http.StatusNotImplemented {
		t.Fatalf("err = %v, want 501 not implemented", err)
	}

	_, _, err = h.translateCreateSandboxRequest(context.Background(), createSandboxRequest{
		TemplateID: "wasm-mod",
		Timeout:    intPtr(120),
		Metadata: map[string]any{
			"runtime":    models.RuntimeWasm,
			"module_ref": "file:///tmp/demo.wasm",
		},
		VolumeMounts: []sandboxVolumeMountCreate{{Name: "data", Path: "/data"}},
	})
	if err == nil {
		t.Fatal("expected wasm volume mount rejection")
	}
	if !errors.As(err, &reqErr) || reqErr.status != http.StatusNotImplemented {
		t.Fatalf("err = %v, want 501 not implemented", err)
	}
}

func TestResolveTemplateSnapshotNameLookupDBError(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx := context.Background()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name:      "by-name-snap:default",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, err := h.resolveTemplate(ctx, "by-name-snap:default")
	if err == nil {
		t.Fatal("expected GetSnapshot store error")
	}
}

func TestResolveSnapshotDeleteTargetNameLookupDBError(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx := context.Background()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name:      "del-by-name:default",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, err := h.resolveSnapshotDeleteTarget(ctx, "del-by-name:default")
	if err == nil {
		t.Fatal("expected snapshot lookup store error")
	}
}

func TestLoadSandboxMetaCompatDBError(t *testing.T) {
	svc, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)
	sb, err := svc.GetSandbox(context.Background(), id)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	h := newHandlers(Deps{Service: svc})
	_, err = h.loadSandboxMeta(context.Background(), sb)
	if err == nil {
		t.Fatal("expected compat state DB error")
	}
}

func TestLoadReplayableCreateResultSandboxDBError(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx := context.Background()
	fingerprint := "fingerprint:get-sandbox-err"
	now := time.Now().UTC()
	if _, _, err := svc.ClaimIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, now, time.Minute); err != nil {
		t.Fatalf("ClaimIdempotentRequest: %v", err)
	}
	if err := svc.CompleteIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, "sb-db-err", now, time.Minute); err != nil {
		t.Fatalf("CompleteIdempotentRequest: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, replayed, err := h.loadReplayableCreateResult(ctx, &models.IdempotentRequestRecord{
		Scope:       idempotencyScopeCreate,
		Fingerprint: fingerprint,
		TargetID:    "sb-db-err",
		State:       models.RequestStateReady,
	})
	if err == nil || replayed {
		t.Fatalf("replayed=%v err=%v", replayed, err)
	}
}

func TestCreateSandboxFingerprintErrorPath(t *testing.T) {
	h := newHandlers(Deps{Service: nil})
	_, err := createRequestFingerprint("", "base", models.CreateSandboxRequest{}, sandboxMeta{})
	if err != nil {
		t.Fatalf("unexpected fingerprint error: %v", err)
	}
	// Exercise handler path where fingerprint succeeds but claim fails with closed DB.
	_, st, handler := newE2BHandlerTestEnv(t)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","timeout":120}`)))
	if rr.Code == http.StatusCreated {
		t.Fatal("expected claim failure with closed DB")
	}
	_ = h
}

func TestCreateSandboxReadyReplayLoadError(t *testing.T) {
	svc, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	ctx := context.Background()
	fingerprint, err := createRequestFingerprint("", "base", models.CreateSandboxRequest{
		Image: "ubuntu:22.04",
		Env:   map[string]string{},
	}, sandboxMeta{
		TemplateID:      "base",
		TimeoutSeconds:  120,
		OnTimeout:       "kill",
		Secure:          true,
		NetworkAllowOut: []string{},
		NetworkDenyOut:  []string{},
	})
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	now := time.Now().UTC()
	if _, _, err := svc.ClaimIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, now, time.Minute); err != nil {
		t.Fatalf("ClaimIdempotentRequest: %v", err)
	}
	if err := svc.CompleteIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, id, now, time.Minute); err != nil {
		t.Fatalf("CompleteIdempotentRequest: %v", err)
	}
	if err := st.UpsertCompatState(ctx, id, models.FacadeE2B, "{bad"); err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","timeout":120}`)))
	if rr.Code == http.StatusCreated {
		t.Fatal("expected replay load failure with corrupt compat state")
	}
}

func TestWaitForCreateReplayCoverage95(t *testing.T) {
	svc, _, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, _, err := h.waitForCreateReplay(ctx, "fingerprint:test")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context canceled", err)
	}

	_, _, replayed, err := h.waitForCreateReplay(context.Background(), "fingerprint:missing")
	if err != nil || replayed {
		t.Fatalf("missing record: replayed=%v err=%v", replayed, err)
	}
}

func TestLoadReplayableCreateResultDeleteIdempotentError(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx := context.Background()

	now := time.Now().UTC()
	fingerprint := "fingerprint:stale-target"
	if _, _, err := svc.ClaimIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, now, time.Minute); err != nil {
		t.Fatalf("ClaimIdempotentRequest: %v", err)
	}
	if err := svc.CompleteIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, "sb-missing", now, time.Minute); err != nil {
		t.Fatalf("CompleteIdempotentRequest: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, _, replayed, err := h.loadReplayableCreateResult(ctx, &models.IdempotentRequestRecord{
		Scope:       idempotencyScopeCreate,
		Fingerprint: fingerprint,
		TargetID:    "sb-missing",
		State:       models.RequestStateReady,
	})
	if err == nil || replayed {
		t.Fatalf("replayed=%v err=%v, want DB error", replayed, err)
	}
}

func TestListSandboxesStoreErrorsAndNilSkip(t *testing.T) {
	svc, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	if err := st.UpsertCompatState(context.Background(), id, models.FacadeE2B, "{bad"); err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad compat state: status=%d body=%s", rr.Code, rr.Body.String())
	}

	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil))
	if rr2.Code == http.StatusOK {
		t.Fatal("expected ListCompatState failure with closed DB")
	}
	_ = svc
}

func TestConnectSandboxPersistMetaError(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	if err := st.UpsertCompatState(context.Background(), id, models.FacadeE2B, "{bad"); err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(
		http.MethodPost,
		"/e2b/sandboxes/"+id+"/connect",
		strings.NewReader(`{"timeout":9999}`),
	))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("connect with bad compat: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUpdateTimeoutPersistMetaError(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	if err := st.UpsertCompatState(context.Background(), id, models.FacadeE2B, "{bad"); err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(
		http.MethodPost,
		"/e2b/sandboxes/"+id+"/timeout",
		strings.NewReader(`{"timeout":180}`),
	))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("update timeout with bad compat: status=%d", rr.Code)
	}
}

func TestCreateSnapshotAliasRollbackAndListErrors(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"alias-fail"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("snapshot create: %d", rr.Code)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"alias-fail-2"}`)))
	if rr2.Code == http.StatusCreated {
		t.Fatal("expected UpsertSnapshotAlias failure with closed DB")
	}

	_, st2, handler2 := newE2BHandlerTestEnv(t)
	if err := st2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr3 := httptest.NewRecorder()
	handler2.ServeHTTP(rr3, httptest.NewRequest(http.MethodGet, "/e2b/snapshots", nil))
	if rr3.Code == http.StatusOK {
		t.Fatal("expected ListSnapshots failure with closed DB")
	}
}

func TestDeleteSnapshotResolveAndAliasErrors(t *testing.T) {
	svc, st, handler := newE2BHandlerTestEnv(t)
	ctx := context.Background()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "del-snap:default", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	snapID := snapshotIDFromName("del-snap:default")
	if err := st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{
		Alias:        snapID,
		SnapshotName: "del-snap:default",
		Facade:       models.FacadeE2B,
	}); err != nil {
		t.Fatalf("UpsertSnapshotAlias: %v", err)
	}

	if err := st.DeleteSnapshot(ctx, "del-snap:default"); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/e2b/templates/"+snapID, nil))
	if rr.Code == http.StatusNoContent {
		t.Fatal("expected DeleteSnapshotAlias failure with closed DB")
	}
	_ = svc
}

func TestResolveTemplateStoreErrors(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, err := h.resolveTemplate(context.Background(), "not-in-template-map")
	if err == nil {
		t.Fatal("expected resolveTemplate store error")
	}
}

func TestResolveSnapshotDeleteTargetStoreError(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, err := h.resolveSnapshotDeleteTarget(context.Background(), "unknown-template")
	if err == nil {
		t.Fatal("expected resolve error")
	}
}

func TestLoadSandboxMetaCompatStoreError(t *testing.T) {
	svc, st, handler := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	id := createE2BSandbox(t, handler)

	sb, err := svc.GetSandbox(context.Background(), id)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err = h.loadSandboxMeta(context.Background(), sb)
	if err == nil {
		t.Fatal("expected compat state load error")
	}
	_ = handler
}

func TestParseMetadataFilterEmptyValue(t *testing.T) {
	filter, err := parseMetadataFilter("key")
	if err != nil || filter["key"] != "" {
		t.Fatalf("filter = %v err=%v", filter, err)
	}
}

func TestLoadTemplateMapInvalidJSONWithLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("SB_E2B_TEMPLATE_MAP_JSON", "{invalid")
	m := loadTemplateMap(logger)
	if _, ok := m["base"]; !ok {
		t.Fatal("expected default base template after invalid JSON")
	}
}

func intPtr(v int) *int { return &v }

func TestListSnapshotsListAliasesError(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/e2b/snapshots", nil))
	if rr.Code == http.StatusOK {
		t.Fatal("expected ListSnapshotAliases failure")
	}
}

func TestCreateSnapshotAliasRollbackOnUpsertFailure(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"rollback-snap"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("first snapshot: %d", rr.Code)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"rollback-snap-2"}`)))
	if rr2.Code == http.StatusCreated {
		t.Fatal("expected UpsertSnapshotAlias failure after dropping aliases table")
	}
}

func TestDeleteSnapshotResolveStoreErrorCoverage95(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/e2b/templates/not-a-real-snapshot-id", nil))
	if rr.Code == http.StatusNoContent {
		t.Fatal("expected resolve/delete failure")
	}
}

func TestResolveTemplateSnapshotLookupStoreError(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	encoded := snapshotIDFromName("missing-snap:default")
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, err := h.resolveTemplate(context.Background(), encoded)
	if err == nil {
		t.Fatal("expected GetSnapshot store error")
	}
}

func TestWaitForCreateReplayExpiredReadyRecord(t *testing.T) {
	svc, _, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx := context.Background()
	fingerprint := "fingerprint:expired-ready"
	now := time.Now().UTC().Add(-time.Hour)
	if _, _, err := svc.ClaimIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, now, time.Minute); err != nil {
		t.Fatalf("ClaimIdempotentRequest: %v", err)
	}
	if err := svc.CompleteIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, "sb-expired", now, time.Minute); err != nil {
		t.Fatalf("CompleteIdempotentRequest: %v", err)
	}
	_, _, replayed, err := h.waitForCreateReplay(ctx, fingerprint)
	if err != nil || replayed {
		t.Fatalf("replayed=%v err=%v, want expired ready cleanup", replayed, err)
	}
}

func TestWaitForCreateReplayLockedUntilShorterThanPoll(t *testing.T) {
	svc, _, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx := context.Background()
	fingerprint := "fingerprint:short-lock"
	now := time.Now().UTC()
	if _, _, err := svc.ClaimIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, now, 10*time.Millisecond); err != nil {
		t.Fatalf("ClaimIdempotentRequest: %v", err)
	}
	_, _, replayed, err := h.waitForCreateReplay(ctx, fingerprint)
	if err != nil || replayed {
		t.Fatalf("replayed=%v err=%v, want pending lock to expire quietly", replayed, err)
	}
}

func TestLoadTemplateMapAddsDefaultBase(t *testing.T) {
	t.Setenv("SB_E2B_TEMPLATE_MAP_JSON", `{"custom":"custom:img"}`)
	m := loadTemplateMap(nil)
	if m["base"] != "ubuntu:22.04" {
		t.Fatalf("base = %q, want default ubuntu:22.04", m["base"])
	}
	if m["custom"] != "custom:img" {
		t.Fatalf("custom = %q", m["custom"])
	}
}

func TestTranslateCreateSandboxRequestWasmGetterError(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	h := newHandlers(Deps{Service: svc})
	_, _, err := h.translateCreateSandboxRequest(context.Background(), createSandboxRequest{
		TemplateID: "catalogue-mod",
		Timeout:    intPtr(120),
	})
	if err == nil {
		t.Fatal("expected wasm catalogue lookup store error")
	}
}

func TestPersistSandboxMetaMarshalErrorNotPossible(t *testing.T) {
	// Exercise sandboxMetaToState happy path with network slices for coverage.
	stateJSON, err := sandboxMetaToState(sandboxMeta{
		OnTimeout:       "pause",
		Secure:          true,
		NetworkAllowOut: []string{"10.0.0.0/8"},
		NetworkDenyOut:  []string{"0.0.0.0/0"},
		VolumeMounts:    []sandboxVolumeMountPayload{{Name: "data", Path: "/data"}},
	})
	if err != nil || stateJSON == "" {
		t.Fatalf("stateJSON = %q err=%v", stateJSON, err)
	}
}

func TestResolveTemplateAliasLookupStoreError(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, err := h.resolveTemplate(context.Background(), "alias-db-error-template")
	if err == nil {
		t.Fatal("expected GetSnapshotAlias store error")
	}
}

func TestResolveSnapshotDeleteTargetCanonicalStoreError(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, err := h.resolveSnapshotDeleteTarget(context.Background(), "snap/with/slash")
	if err == nil {
		t.Fatal("expected canonical snapshot lookup store error")
	}
}

func TestLoadReplayableCreateResultDeleteIdempotentDBError(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx := context.Background()
	fingerprint := "fingerprint:delete-idem-err"
	now := time.Now().UTC()
	if _, _, err := svc.ClaimIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, now, time.Minute); err != nil {
		t.Fatalf("ClaimIdempotentRequest: %v", err)
	}
	if err := svc.CompleteIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, "sb-missing-target", now, time.Minute); err != nil {
		t.Fatalf("CompleteIdempotentRequest: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, replayed, err := h.loadReplayableCreateResult(ctx, &models.IdempotentRequestRecord{
		Scope:       idempotencyScopeCreate,
		Fingerprint: fingerprint,
		TargetID:    "sb-missing-target",
		State:       models.RequestStateReady,
	})
	if err == nil || replayed {
		t.Fatalf("replayed=%v err=%v, want delete idempotent DB error", replayed, err)
	}
}

func TestWaitForCreateReplayDeleteExpiredReadyDBError(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx := context.Background()
	fingerprint := "fingerprint:delete-expired-err"
	past := time.Now().UTC().Add(-2 * time.Hour)
	if _, _, err := svc.ClaimIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, past, time.Minute); err != nil {
		t.Fatalf("ClaimIdempotentRequest: %v", err)
	}
	if err := svc.CompleteIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, "sb-old", past, time.Minute); err != nil {
		t.Fatalf("CompleteIdempotentRequest: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, replayed, err := h.waitForCreateReplay(ctx, fingerprint)
	if err == nil || replayed {
		t.Fatalf("replayed=%v err=%v, want delete failure on expired ready", replayed, err)
	}
}

func TestParseMetadataFilterKeepsEmptyValue(t *testing.T) {
	filter, err := parseMetadataFilter("solo")
	if err != nil || filter["solo"] != "" {
		t.Fatalf("filter = %v err=%v", filter, err)
	}
}

func TestCreateSnapshotRollbackWarnPath(t *testing.T) {
	runtime := newFakeE2BRuntime()
	_, st, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{
		PublicHost:  "sandbox.test",
		EnableCaddy: false,
		ToolboxPort: 2280,
	})
	id := createE2BSandbox(t, handler)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"rollback-warn"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("first snapshot: %d", rr.Code)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"rollback-warn-2"}`)))
	if rr2.Code == http.StatusCreated {
		t.Fatal("expected alias upsert failure")
	}
}

func TestDeleteSnapshotAliasCleanupStoreError(t *testing.T) {
	ctx := context.Background()
	svc, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"alias-del"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("snapshot create: %d", rr.Code)
	}
	var snap snapshotInfoResponse
	if err := json.NewDecoder(rr.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := st.DeleteSnapshot(ctx, "alias-del:default"); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodDelete, "/e2b/templates/"+snap.SnapshotID, nil))
	if rr2.Code == http.StatusNoContent {
		t.Fatal("expected DeleteSnapshotAlias store error")
	}
	_ = svc
}

func TestCreateSandboxClusterReservedLocalPath(t *testing.T) {
	runtime := newFakeE2BRuntime()
	svc, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{
		PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: 2280,
	})
	fakeCluster := &e2bForwardCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
		target: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
	}
	svc.AttachCluster(fakeCluster)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes",
		strings.NewReader(`{"templateID":"base","timeout":120}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestLoadReplayableCreateResultCompatMetaLoadError(t *testing.T) {
	svc, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)
	if err := st.UpsertCompatState(context.Background(), id, models.FacadeE2B, "{bad"); err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}

	h := newHandlers(Deps{Service: svc})
	ctx := context.Background()
	fingerprint := "fingerprint:compat-meta-err"
	now := time.Now().UTC()
	if _, _, err := svc.ClaimIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, now, time.Minute); err != nil {
		t.Fatalf("ClaimIdempotentRequest: %v", err)
	}
	if err := svc.CompleteIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, id, now, time.Minute); err != nil {
		t.Fatalf("CompleteIdempotentRequest: %v", err)
	}

	_, _, replayed, err := h.loadReplayableCreateResult(ctx, &models.IdempotentRequestRecord{
		Scope:       idempotencyScopeCreate,
		Fingerprint: fingerprint,
		TargetID:    id,
		State:       models.RequestStateReady,
	})
	if err == nil || replayed {
		t.Fatalf("replayed=%v err=%v, want compat meta load error", replayed, err)
	}
	_ = handler
}

func TestCreateSandboxClaimIdempotentDBError(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes",
		strings.NewReader(`{"templateID":"base","timeout":120}`)))
	if rr.Code == http.StatusCreated {
		t.Fatal("expected ClaimIdempotentRequest failure with closed DB")
	}
}

func TestDeleteSnapshotNotFoundHTTP(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/e2b/templates/snapshot_missing-id", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestTranslateCreateSandboxWasmCatalogueDBErrorInHandler(t *testing.T) {
	t.Setenv("SB_ENABLE_WASM", "true")
	svc, st, _ := newE2BHandlerTestEnvWithRuntime(t, newFakeE2BRuntime(), config.Config{
		PublicHost:  "sandbox.test",
		EnableCaddy: false,
		ToolboxPort: 2280,
		EnableWasm:  true,
	})
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	h := newHandlers(Deps{Service: svc})
	_, _, err := h.translateCreateSandboxRequest(context.Background(), createSandboxRequest{
		TemplateID: "wasm-catalogue-id",
		Timeout:    intPtr(120),
	})
	if err == nil {
		t.Fatal("expected wasm catalogue lookup store error")
	}
}

func TestCreateSandboxPersistMetaRollbackPath(t *testing.T) {
	t.Setenv("SB_E2B_TEMPLATE_MAP_JSON", `{"base":"aerolvm-build/coverage:latest"}`)
	runtime := newFakeE2BRuntime()
	svc, st, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{
		PublicHost:  "sandbox.test",
		EnableCaddy: false,
		ToolboxPort: 2280,
	})
	fakeCluster := &e2bForwardCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
		target: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
	}
	svc.AttachCluster(fakeCluster)

	runtime.afterCreate = func() {
		_ = st.Close()
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes",
		strings.NewReader(`{"templateID":"base","timeout":120,"metadata":{"rollback":"persist"}}`)))
	if rr.Code == http.StatusCreated {
		t.Fatalf("expected create failure after runtime create, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPersistSandboxMetaNilServiceCoverage95(t *testing.T) {
	h := newHandlers(Deps{Service: nil})
	if err := h.persistSandboxMeta(context.Background(), "sb-nil", sandboxMeta{TemplateID: "base"}); err != nil {
		t.Fatalf("persistSandboxMeta: %v", err)
	}
}

func TestDeleteSnapshotCanonicalNameCoverage95(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	ctx := context.Background()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "canon-del:default", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/e2b/templates/canon-del", nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestResolveTemplateCustomMapEntryCoverage95(t *testing.T) {
	svc, _, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	h.templateMap["customtpl"] = "custom:image"
	img, _, err := h.resolveTemplate(context.Background(), "customtpl")
	if err != nil || img != "custom:image" {
		t.Fatalf("resolveTemplate = %q err=%v", img, err)
	}
}

func TestTranslateCreateSandboxRequestVolumeMountsCoverage95(t *testing.T) {
	svc, _, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	_, meta, err := h.translateCreateSandboxRequest(context.Background(), createSandboxRequest{
		TemplateID:   "base",
		Timeout:      intPtr(60),
		Network:      &sandboxNetworkRequest{MaskRequestHost: "host.example.com"},
		VolumeMounts: []sandboxVolumeMountCreate{{Name: "data", Path: "/data"}},
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if meta.MaskRequestHost != "host.example.com" || len(meta.VolumeMounts) != 1 {
		t.Fatalf("meta = %+v", meta)
	}
}

func TestConnectSandboxPersistMetaAfterLifecycleUpdate(t *testing.T) {
	runtime := newFakeE2BRuntime()
	svc, st, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{
		PublicHost:  "sandbox.test",
		EnableCaddy: false,
		ToolboxPort: 2280,
	})
	id := createE2BSandbox(t, handler)
	if _, err := svc.StopSandbox(context.Background(), id); err != nil {
		t.Fatalf("StopSandbox: %v", err)
	}
	execStoreSQL(t, st, `DROP TABLE sandbox_compat_state`)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(
		http.MethodPost,
		"/e2b/sandboxes/"+id+"/connect",
		strings.NewReader(`{"timeout":600}`),
	))
	if rr.Code == http.StatusOK {
		t.Fatal("expected connect persist failure after compat table drop")
	}
}

func TestUpdateTimeoutPersistMetaAfterLifecycleUpdate(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)
	execStoreSQL(t, st, `DROP TABLE sandbox_compat_state`)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(
		http.MethodPost,
		"/e2b/sandboxes/"+id+"/timeout",
		strings.NewReader(`{"timeout":240}`),
	))
	if rr.Code == http.StatusNoContent {
		t.Fatal("expected update timeout persist failure after compat table drop")
	}
}

func TestListSandboxesCompatStateTableMissing(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	createE2BSandbox(t, handler)
	execStoreSQL(t, st, `DROP TABLE sandbox_compat_state`)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil))
	if rr.Code == http.StatusOK {
		t.Fatal("expected ListCompatState failure with missing compat table")
	}
}

func TestListSnapshotsAliasesTableMissing(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"alias-table-miss"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("snapshot create: %d", rr.Code)
	}
	execStoreSQL(t, st, `DROP TABLE snapshot_aliases`)

	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/e2b/snapshots", nil))
	if rr2.Code == http.StatusOK {
		t.Fatal("expected ListSnapshotAliases failure with missing aliases table")
	}
}

func TestDeleteSnapshotAliasCleanupTableMissing(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"alias-del-miss"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("snapshot create: %d", rr.Code)
	}
	var snap snapshotInfoResponse
	if err := json.NewDecoder(rr.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	execStoreSQL(t, st, `DROP TABLE snapshot_aliases`)

	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodDelete, "/e2b/templates/"+snap.SnapshotID, nil))
	if rr2.Code == http.StatusNoContent {
		t.Fatal("expected DeleteSnapshotAlias failure with missing aliases table")
	}
}

func TestResolveTemplateDirectSnapshotNameCoverage95(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	ctx := context.Background()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "tpl-direct:default", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	h := newHandlers(Deps{Service: svc})
	img, _, err := h.resolveTemplate(ctx, "tpl-direct:default")
	if err != nil || img != "tpl-direct:default" {
		t.Fatalf("resolveTemplate = %q err=%v", img, err)
	}
}

func TestResolveSnapshotDeleteTargetEncodedIDCoverage95(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	ctx := context.Background()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "encoded-del:default", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	h := newHandlers(Deps{Service: svc})
	encoded := snapshotIDFromName("encoded-del:default")
	name, storedID, err := h.resolveSnapshotDeleteTarget(ctx, encoded)
	if err != nil || name != "encoded-del:default" || storedID != encoded {
		t.Fatalf("resolveSnapshotDeleteTarget = %q %q err=%v", name, storedID, err)
	}
}

func TestCreateSandboxPersistMetaFailureRollbackCoverage95(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	execStoreSQL(t, st, `DROP TABLE sandbox_compat_state`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes",
		strings.NewReader(`{"templateID":"base","timeout":120}`)))
	if rr.Code == http.StatusCreated {
		t.Fatal("expected persist meta failure after create")
	}
}

func TestListSandboxesMetadataFilterEmptyValueCoverage95(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	createE2BSandbox(t, handler)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?metadata=tag=", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateSnapshotGetSandboxStoreErrorCoverage95(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"x"}`)))
	if rr.Code == http.StatusCreated {
		t.Fatal("expected GetSandbox store error")
	}
}

func TestParseMetadataFilterEmptyKeyCoverage95(t *testing.T) {
	got, err := parseMetadataFilter("emptykey=")
	if err != nil || got["emptykey"] != "" {
		t.Fatalf("parseMetadataFilter = %+v err=%v", got, err)
	}
}

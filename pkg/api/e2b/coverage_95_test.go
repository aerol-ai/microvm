package e2b

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWriteStoreAwareErrorCoverage95(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "public_traffic_disabled", err: service.ErrPublicTrafficDisabled, wantStatus: http.StatusConflict},
		{name: "platform_volumes_disabled", err: models.ErrPlatformVolumesDisabled, wantStatus: http.StatusPreconditionFailed},
		{name: "platform_volumes_unsupported_runtime", err: models.ErrPlatformVolumesUnsupportedRuntime, wantStatus: http.StatusBadRequest},
		{name: "platform_volume_quota", err: models.ErrPlatformVolumeQuota, wantStatus: http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeStoreAwareError(nil, rr, tc.err)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tc.wantStatus)
			}
		})
	}

	rr := httptest.NewRecorder()
	longCap := fmt.Errorf("%w: %s", capacity.ErrCapacityExceeded, strings.Repeat("x", 250))
	writeStoreAwareError(slog.Default(), rr, longCap)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	body := rr.Body.String()
	if len(body) > 400 {
		t.Fatalf("expected trimmed error body, got len=%d", len(body))
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

func TestSandboxMetaFromNativeNilTagsAndNetworkDefaults(t *testing.T) {
	sb := &models.Sandbox{Tags: nil, NetworkBlockAll: false}
	meta := sandboxMetaFromNative(sb, compatBlob{NetworkAllowOut: []string{""}})
	if meta.Metadata == nil || len(meta.Metadata) != 0 {
		t.Fatalf("metadata = %v", meta.Metadata)
	}
	if len(meta.NetworkAllowOut) != 0 {
		t.Fatalf("network allow out = %v", meta.NetworkAllowOut)
	}
	if meta.AllowInternetAccess == nil || !*meta.AllowInternetAccess {
		t.Fatalf("allow internet = %v", meta.AllowInternetAccess)
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
	_, err := createRequestFingerprint("base", models.CreateSandboxRequest{}, sandboxMeta{})
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
	fingerprint, err := createRequestFingerprint("base", models.CreateSandboxRequest{
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

func TestSandboxMetaCoverage95(t *testing.T) {
	sb := &models.Sandbox{
		Image:           "img",
		Tags:            nil,
		NetworkBlockAll: true,
		CreatedAt:       time.Now().Add(-30 * time.Second),
		Lifecycle:       models.Lifecycle{StopAtAge: 60 * time.Second},
	}
	meta := sandboxMetaFromNative(sb, compatBlob{Secure: true, OnTimeout: "kill"})
	if meta.Metadata == nil || len(meta.Metadata) != 0 {
		t.Fatalf("metadata = %v, want empty map", meta.Metadata)
	}
	if meta.AllowInternetAccess == nil || *meta.AllowInternetAccess {
		t.Fatalf("AllowInternetAccess = %v, want false", meta.AllowInternetAccess)
	}

	_, err := sandboxMetaFromState(&models.SandboxCompatState{StateJSON: "{bad"}, sb)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}

	stateJSON, err := sandboxMetaToState(sandboxMeta{OnTimeout: "pause", Secure: true})
	if err != nil || stateJSON == "" {
		t.Fatalf("stateJSON = %q err=%v", stateJSON, err)
	}
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

func TestRuntimeProxyWakeErrorWithClosedDB(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/e2b/runtime/health", nil)
	req.Header.Set("E2b-Sandbox-Id", id)
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("expected wake/proxy error with closed DB")
	}
}

func TestRuntimeProxyBasicAuthHeaderBranches(t *testing.T) {
	toolboxRequests := make(chan *http.Request, 1)
	toolboxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		toolboxRequests <- r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	defer toolboxServer.Close()

	parsed, err := url.Parse(toolboxServer.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	runtime := newFakeE2BRuntime()
	runtime.containerIP = host
	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{
		PublicHost:  "sandbox.test",
		EnableCaddy: false,
		ToolboxPort: port,
	})

	createReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","secure":true}`))
	createResp := httptest.NewRecorder()
	handler.ServeHTTP(createResp, createReq)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d", createResp.Code)
	}
	var created sandboxResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	runtimeReq := httptest.NewRequest(http.MethodGet, "/e2b/runtime/health", nil)
	runtimeReq.Header.Set("E2b-Sandbox-Id", created.SandboxID)
	runtimeReq.Header.Set("X-Access-Token", created.EnvdAccessToken)
	runtimeReq.Header.Set("Authorization", "Basic dXNlcjo=")
	runtimeResp := httptest.NewRecorder()
	handler.ServeHTTP(runtimeResp, runtimeReq)
	if runtimeResp.Code != http.StatusOK {
		t.Fatalf("basic auth proxy status = %d", runtimeResp.Code)
	}

	select {
	case forwarded := <-toolboxRequests:
		if forwarded.Header.Get("X-E2B-User-Authorization") != "Basic dXNlcjo=" {
			t.Fatalf("user auth = %q", forwarded.Header.Get("X-E2B-User-Authorization"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected forwarded toolbox request")
	}

	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/e2b/runtime/health", nil)
	req2.Header.Set("E2b-Sandbox-Id", created.SandboxID)
	req2.Header.Set("X-Access-Token", created.EnvdAccessToken)
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("non-basic auth proxy status = %d", rr2.Code)
	}
}

func intPtr(v int) *int { return &v }

func TestCreateSandboxWaitForReplayServiceUnavailable(t *testing.T) {
	runtime := newFakeE2BRuntime()
	runtime.blockCreate = make(chan struct{})
	runtime.onCreateChan = make(chan struct{}, 1)

	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{
		PublicHost:  "sandbox.test",
		EnableCaddy: false,
		ToolboxPort: 2280,
	})

	body := `{"templateID":"base","timeout":120,"metadata":{"wait":"timeout"}}`
	go func() {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body)))
	}()

	select {
	case <-runtime.onCreateChan:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for blocked create")
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("wait replay timeout status = %d, body=%s", rr.Code, rr.Body.String())
	}

	close(runtime.blockCreate)
}

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

func TestSandboxMetaFromNativeDestroyAtAgeBranch(t *testing.T) {
	sb := &models.Sandbox{
		CreatedAt: time.Now().Add(-5 * time.Second),
		Lifecycle: models.Lifecycle{DestroyAtAge: 30 * time.Second},
	}
	meta := sandboxMetaFromNative(sb, compatBlob{Secure: true, OnTimeout: "kill"})
	if meta.TimeoutSeconds <= 0 {
		t.Fatalf("expected positive timeout from destroy-at-age, got %d", meta.TimeoutSeconds)
	}
}

func TestRuntimeProxyEmptyPublicPath(t *testing.T) {
	toolboxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/envd/" {
			t.Fatalf("path = %q, want /envd/", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer toolboxServer.Close()

	host, portText, err := net.SplitHostPort(strings.TrimPrefix(toolboxServer.URL, "http://"))
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	runtime := newFakeE2BRuntime()
	runtime.containerIP = host
	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{
		PublicHost:  "sandbox.test",
		EnableCaddy: false,
		ToolboxPort: port,
	})

	createReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","secure":false}`))
	createResp := httptest.NewRecorder()
	handler.ServeHTTP(createResp, createReq)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d", createResp.Code)
	}
	var created sandboxResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/e2b/runtime", nil)
	req.Header.Set("E2b-Sandbox-Id", created.SandboxID)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("runtime root status = %d", rr.Code)
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

func TestCreateRequestFingerprintAndMetadataHelpers(t *testing.T) {
	fp, err := createRequestFingerprint("base", models.CreateSandboxRequest{Image: "ubuntu:22.04"}, sandboxMeta{
		TemplateID: "base", TimeoutSeconds: 120, OnTimeout: "kill",
	})
	if err != nil || fp == "" {
		t.Fatalf("fingerprint = %q err=%v", fp, err)
	}
	if got := sandboxIDFromFingerprint(fp); got == "" {
		t.Fatal("expected deterministic sandbox id")
	}
	filter, err := parseMetadataFilter("env=prod")
	if err != nil || filter["env"] != "prod" {
		t.Fatalf("filter = %v err=%v", filter, err)
	}
}

func TestRuntimeProxyWasmRuntimeBranch(t *testing.T) {
	svc, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	sb, err := svc.GetSandbox(context.Background(), id)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	sb.Runtime = models.RuntimeWasm
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	stateBlob, _ := json.Marshal(compatBlob{Secure: false, OnTimeout: "kill"})
	if err := st.UpsertCompatState(context.Background(), id, models.FacadeE2B, string(stateBlob)); err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/e2b/runtime/health", nil)
	req.Header.Set("E2b-Sandbox-Id", id)
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("wasm proxy without driver should fail, got %d", rr.Code)
	}
}

func TestRuntimeProxyPublicPathWithoutLeadingSlash(t *testing.T) {
	toolboxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/envd/foo" {
			t.Fatalf("path = %q, want /envd/foo", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer toolboxServer.Close()

	host, portText, err := net.SplitHostPort(strings.TrimPrefix(toolboxServer.URL, "http://"))
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	runtime := newFakeE2BRuntime()
	runtime.containerIP = host
	svc, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{
		PublicHost:  "sandbox.test",
		EnableCaddy: false,
		ToolboxPort: port,
	})

	createReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","secure":false}`))
	createResp := httptest.NewRecorder()
	handler.ServeHTTP(createResp, createReq)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d", createResp.Code)
	}
	var created sandboxResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	h := newHandlers(Deps{Service: svc})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/e2b/runtimefoo", nil)
	req.URL.Path = "/e2b/runtimefoo"
	req.Header.Set("E2b-Sandbox-Id", created.SandboxID)
	h.runtimeProxy(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("runtime proxy status = %d, body=%s", rr.Code, rr.Body.String())
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

func TestSandboxMetaFromNativeNilNetworkSliceDefaults(t *testing.T) {
	meta := sandboxMetaFromNative(&models.Sandbox{Tags: map[string]string{"k": "v"}}, compatBlob{
		Secure:    true,
		OnTimeout: "kill",
	})
	if meta.NetworkAllowOut == nil || meta.NetworkDenyOut == nil {
		t.Fatalf("expected non-nil empty network slices, got allow=%v deny=%v", meta.NetworkAllowOut, meta.NetworkDenyOut)
	}
	if len(meta.NetworkAllowOut) != 0 || len(meta.NetworkDenyOut) != 0 {
		t.Fatalf("expected empty network slices")
	}
	if meta.Metadata == nil || meta.Metadata["k"] != "v" {
		t.Fatalf("metadata = %v", meta.Metadata)
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

func TestResolveTemplateCanonicalSnapshotNameCoverage95(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	ctx := context.Background()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "tpl-canonical:default", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	h := newHandlers(Deps{Service: svc})
	img, _, err := h.resolveTemplate(ctx, "tpl-canonical")
	if err != nil || img != "tpl-canonical:default" {
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

func TestSandboxMetaFromNativeStopAtAgeCoverage95(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	sb := &models.Sandbox{
		Image: "img", CreatedAt: now,
		Lifecycle: models.Lifecycle{StopAtAge: 10 * time.Minute},
	}
	meta := sandboxMetaFromNative(sb, compatBlob{OnTimeout: "kill"})
	if meta.TimeoutSeconds <= 0 || meta.OnTimeout != "pause" {
		t.Fatalf("meta = %+v", meta)
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

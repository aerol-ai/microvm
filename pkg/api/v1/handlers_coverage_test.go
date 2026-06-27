package v1

import (
	"context"
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
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestHandlers_CreateSandbox_Success(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`))
	h.createSandbox(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	if rt.createCalls != 1 {
		t.Fatalf("createCalls = %d, want 1", rt.createCalls)
	}
	// The create handler reports its server-side duration as a Server-Timing
	// metric so a client can subtract network time (used by the create benchmark).
	if st := rr.Header().Get("Server-Timing"); !strings.Contains(st, "create;dur=") {
		t.Fatalf("Server-Timing = %q, want a create;dur= metric", st)
	}
}

func TestHandlers_ListSandboxes_StoreError(t *testing.T) {
	h, st := newClusterCreateHarness(t, &apiRecordingRuntime{}, cluster.NewNoop("node-a", "http://node-a", ""))
	_ = st.Close()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	h.listSandboxes(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_ListCustomDomains_WithRows(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	seedSandboxRowV1(t, env.store, "sb-dom")
	if err := env.store.AddCustomDomain(context.Background(), "sb-dom", "app.example.com", 8080); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-dom/custom-domains", nil)
	req.SetPathValue("id", "sb-dom")
	rr := httptest.NewRecorder()
	h := &handlers{deps: Deps{Service: env.svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	h.listCustomDomains(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_GetSandbox_Success(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, st := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-get", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		ContainerID: "ctr", ContainerIP: "10.0.0.1",
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-get", nil)
	req.SetPathValue("id", "sb-get")
	h.getSandbox(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_ListMounts_EmptySuccess(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, st := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-mounts", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		ContainerID: "ctr", ContainerIP: "10.0.0.1",
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-mounts/mounts", nil)
	req.SetPathValue("id", "sb-mounts")
	h.listMounts(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_CreateSnapshot_SuccessPathDecode(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/missing/snapshot", strings.NewReader(`{"name":"snap"}`))
	req.SetPathValue("id", "missing")
	h.createSnapshot(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_Reconcile_Error(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/reconcile", nil)
	h.reconcile(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_CreateSnapshot_NotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/missing/snapshot", strings.NewReader(`{"name":"snap"}`))
	req.SetPathValue("id", "missing")
	h.createSnapshot(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_ResizeSandbox_NotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/sandboxes/missing/resize", strings.NewReader(`{"cpu":2}`))
	req.SetPathValue("id", "missing")
	h.resizeSandbox(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_UpdateLifecycle_NotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/sandboxes/missing/lifecycle", strings.NewReader(`{"lifecycle":"ephemeral"}`))
	req.SetPathValue("id", "missing")
	h.updateLifecycle(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_ExposePort_NoBody_NotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/missing/expose/8080", nil)
	req.SetPathValue("id", "missing")
	req.SetPathValue("port", "8080")
	req.ContentLength = 0
	h.exposePort(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_UnexposePort_NotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/sandboxes/missing/expose/8080", nil)
	req.SetPathValue("id", "missing")
	req.SetPathValue("port", "8080")
	h.unexposePort(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_ListCustomDomains_Empty(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	seedSandboxRowV1(t, env.store, "sb-dom")
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-dom/custom-domains", nil)
	rr := httptest.NewRecorder()
	env.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

type exposedPortWriteThroughCluster struct {
	*cluster.Noop
	addCalls    []cluster.ExposedPortRoute
	addPorts    []int
	addErr      error
	removeCalls []int
	removeErr   error
}

func (c *exposedPortWriteThroughCluster) AddExposedPort(_ context.Context, _ string, port int, route cluster.ExposedPortRoute) error {
	c.addPorts = append(c.addPorts, port)
	c.addCalls = append(c.addCalls, route)
	return c.addErr
}

func (c *exposedPortWriteThroughCluster) RemoveExposedPort(_ context.Context, _ string, port int) error {
	c.removeCalls = append(c.removeCalls, port)
	return c.removeErr
}

type exposeRuntime struct{ noopRuntime }

func (exposeRuntime) PushAllowedPorts(context.Context, string, string, []int) error { return nil }

func TestHandlers_ExposePort_ReplicatesToCluster(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID:             "sb-expose",
		Image:          "alpine:3.20",
		Status:         models.SandboxStatusStarted,
		ContainerIP:    "10.0.0.5",
		CPU:            1,
		MemoryMB:       256,
		DiskGB:         1,
		OSUser:         "root",
		ToolboxEnabled: true,
		CreatedAt:      now,
		UpdatedAt:      now,
		LastActiveAt:   now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	stub := &exposedPortWriteThroughCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	cfg := config.Config{Domain: "sandboxes.example.com"}
	caddyClient := caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
	svc := service.New(cfg, logger, st, exposeRuntime{}, nil, caddyClient, nil, nil, nil)
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-expose/expose/8080", nil)
	req.SetPathValue("id", "sb-expose")
	req.SetPathValue("port", "8080")
	req.ContentLength = 0
	h.exposePort(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if len(stub.addPorts) == 0 || stub.addPorts[len(stub.addPorts)-1] != 8080 {
		t.Fatalf("AddExposedPort ports = %+v, want at least one 8080", stub.addPorts)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/v1/sandboxes/sb-expose/expose/8080", nil)
	req.SetPathValue("id", "sb-expose")
	req.SetPathValue("port", "8080")
	h.unexposePort(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rr.Code, rr.Body.String())
	}
	if len(stub.removeCalls) != 1 || stub.removeCalls[0] != 8080 {
		t.Fatalf("RemoveExposedPort ports = %+v, want [8080]", stub.removeCalls)
	}
}

func TestReplicateAddExposedPort_BestEffortOnError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &exposedPortWriteThroughCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
		addErr: errors.New("fsm unavailable"),
	}
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	h.replicateAddExposedPort(context.Background(), "sb", 8080, cluster.ExposedPortRoute{
		Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://sb-8080.example.com",
	})
}

func TestReplicateRemoveExposedPort_BestEffortOnError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &exposedPortWriteThroughCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		removeErr: errors.New("fsm unavailable"),
	}
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	h.replicateRemoveExposedPort(context.Background(), "sb", 8080)
}

func TestReplicateExposedPort_NoClusterIsNoOp(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &handlers{deps: Deps{Service: service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil), Logger: logger}}
	h.replicateAddExposedPort(context.Background(), "sb", 8080, cluster.ExposedPortRoute{})
	h.replicateRemoveExposedPort(context.Background(), "sb", 8080)
}

func TestCapacityRequestFromCreateDefaults(t *testing.T) {
	got := capacityRequestFromCreate(models.CreateSandboxRequest{})
	if got.CPU != models.DefaultCPU || got.MemoryMB != models.DefaultMemoryMB || got.DiskGB != models.DefaultDiskGB {
		t.Fatalf("defaults = %+v, want cpu/mem/disk defaults", got)
	}
	if got.Runtime != models.RuntimeDocker {
		t.Fatalf("default runtime = %q, want docker", got.Runtime)
	}
	req := models.CreateSandboxRequest{
		TemplateID: "tpl-1",
		GPUs:       &models.GPURequest{Count: 0, Vendor: models.GPUVendorNVIDIA},
	}
	got = capacityRequestFromCreate(req)
	if got.Runtime != models.RuntimeFirecracker || got.TemplateID != "tpl-1" || got.GPUs != 1 {
		t.Fatalf("template/gpu normalize = %+v", got)
	}
	if disk := diskGBForCapacity(10, models.RuntimeFirecracker, 5); disk != 15 {
		t.Fatalf("diskGBForCapacity = %d, want 15", disk)
	}
}

func TestNormalizeCreateRuntimeForPlacement(t *testing.T) {
	req := models.CreateSandboxRequest{TemplateID: " tpl-x "}
	if err := normalizeCreateRuntimeForPlacement(&req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Runtime != models.RuntimeFirecracker || req.TemplateID != "tpl-x" {
		t.Fatalf("req = %+v, want firecracker + trimmed template", req)
	}
	bad := models.CreateSandboxRequest{Runtime: models.RuntimeDocker, TemplateID: "tpl-x"}
	if err := normalizeCreateRuntimeForPlacement(&bad); err == nil {
		t.Fatal("expected error for docker + template_id")
	}
}

func TestParseBoolQuery(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"true", true}, {"1", true}, {"yes", true}, {"false", false}, {"", false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/x?force="+tc.raw, nil)
		if got := parseBoolQuery(req, "force"); got != tc.want {
			t.Fatalf("parseBoolQuery(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func seedStartedSandboxV1(t *testing.T, st *store.Store, id string, status models.SandboxStatus) {
	t.Helper()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: id, Image: "alpine:3.20", Status: status,
		ContainerID: "ctr-" + id, ContainerIP: "10.0.0.2",
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
}

func TestHandlers_StartSandbox_Success(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, st := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
	seedStartedSandboxV1(t, st, "sb-start", models.SandboxStatusStopped)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-start/start", nil)
	req.SetPathValue("id", "sb-start")
	h.startSandbox(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_StopSandbox_Success(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, st := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
	seedStartedSandboxV1(t, st, "sb-stop", models.SandboxStatusStarted)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-stop/stop", nil)
	req.SetPathValue("id", "sb-stop")
	h.stopSandbox(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_GetNetworkUsage_Success(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, st := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
	seedStartedSandboxV1(t, st, "sb-net", models.SandboxStatusStarted)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-net/network-usage", nil)
	req.SetPathValue("id", "sb-net")
	h.getNetworkUsage(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_UpdateNetworkLimits_Success(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, st := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
	seedStartedSandboxV1(t, st, "sb-lim", models.SandboxStatusStarted)

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"network_bytes_in_limit":1000,"network_bytes_out_limit":2000}`)
	req := httptest.NewRequest(http.MethodPut, "/v1/sandboxes/sb-lim/network-limits", body)
	req.SetPathValue("id", "sb-lim")
	h.updateNetworkLimits(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlers_ListCustomDomains_StoreError(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	seedSandboxRowV1(t, env.store, "sb-dom")
	_ = env.store.Close()
	h := &handlers{deps: Deps{Service: env.svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-dom/custom-domains", nil)
	req.SetPathValue("id", "sb-dom")
	h.listCustomDomains(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

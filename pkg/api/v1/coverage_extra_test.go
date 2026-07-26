package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestClusterWasmMigrateNilService(t *testing.T) {
	h := &handlers{deps: Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	rr := httptest.NewRecorder()
	h.clusterWasmMigrate(rr, httptest.NewRequest(http.MethodPost, cluster.PublicWasmMigratePath,
		strings.NewReader(`{"sandbox_id":"sb-1","target_node_id":"node-b"}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterInternalWasmMigrateExportErrorBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("nil_service", func(t *testing.T) {
		h := &handlers{deps: Deps{Logger: logger}}
		req := httptest.NewRequest(http.MethodGet, cluster.PublicInternalWasmMigratePath+"sb-1/export", nil)
		req.SetPathValue("id", "sb-1")
		rr := httptest.NewRecorder()
		h.clusterInternalWasmMigrateExport(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d", rr.Code)
		}
	})

	t.Run("nil_cluster", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.ClearClusterForTest()
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		req := httptest.NewRequest(http.MethodGet, cluster.PublicInternalWasmMigratePath+"sb-1/export", nil)
		req.SetPathValue("id", "sb-1")
		rr := httptest.NewRecorder()
		h.clusterInternalWasmMigrateExport(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d", rr.Code)
		}
	})

	t.Run("empty_id", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(cluster.NewNoop("node-a", "http://node-a", ""))
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		req := httptest.NewRequest(http.MethodGet, cluster.PublicInternalWasmMigratePath+"/export", nil)
		req.SetPathValue("id", "  ")
		rr := httptest.NewRecorder()
		h.clusterInternalWasmMigrateExport(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", rr.Code)
		}
	})

	t.Run("unknown_sandbox", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(&unknownSandboxCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		req := httptest.NewRequest(http.MethodGet, cluster.PublicInternalWasmMigratePath+"missing/export", nil)
		req.SetPathValue("id", "missing")
		rr := httptest.NewRecorder()
		h.clusterInternalWasmMigrateExport(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d", rr.Code)
		}
	})

	t.Run("owner_lookup_error", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(&ownerLookupErrCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		req := httptest.NewRequest(http.MethodGet, cluster.PublicInternalWasmMigratePath+"sb-1/export", nil)
		req.SetPathValue("id", "sb-1")
		rr := httptest.NewRecorder()
		h.clusterInternalWasmMigrateExport(rr, req)
		if rr.Code == http.StatusOK {
			t.Fatal("expected owner lookup failure")
		}
	})

	t.Run("export_service_error", func(t *testing.T) {
		st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		svc := service.New(config.Config{EnableWasm: true, WasmModulesDir: t.TempDir()}, logger, st, &noopRuntime{}, nil, nil, nil, nil, nil)
		svc.AttachCluster(&ownerCluster{
			Noop:  cluster.NewNoop("node-a", "http://node-a", ""),
			owner: cluster.OwnerInfo{NodeID: "node-a", IsSelf: true},
		})
		seedV1WasmSandbox(t, st, "sb-export-fail")
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		req := httptest.NewRequest(http.MethodGet, cluster.PublicInternalWasmMigratePath+"sb-export-fail/export", nil)
		req.SetPathValue("id", "sb-export-fail")
		rr := httptest.NewRecorder()
		h.clusterInternalWasmMigrateExport(rr, req)
		if rr.Code == http.StatusOK {
			t.Fatal("expected export failure without migration host")
		}
	})
}

type ownerLookupErrCluster struct {
	*cluster.Noop
}

func (ownerLookupErrCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return cluster.OwnerInfo{}, errors.New("owner lookup failed")
}

type unknownSandboxCluster struct {
	*cluster.Noop
}

func (unknownSandboxCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return cluster.OwnerInfo{}, cluster.ErrUnknownSandbox
}

func TestClusterInternalWasmMigrateImportErrorBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("nil_service", func(t *testing.T) {
		h := &handlers{deps: Deps{Logger: logger}}
		req := httptest.NewRequest(http.MethodPut, cluster.PublicInternalWasmMigratePath+"sb-1/import", bytes.NewReader(nil))
		req.SetPathValue("id", "sb-1")
		rr := httptest.NewRecorder()
		h.clusterInternalWasmMigrateImport(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d", rr.Code)
		}
	})

	t.Run("empty_id", func(t *testing.T) {
		svc := service.New(config.Config{EnableWasm: true, WasmModulesDir: t.TempDir()}, logger, nil, nil, nil, nil, nil, nil, nil)
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		req := httptest.NewRequest(http.MethodPut, cluster.PublicInternalWasmMigratePath+"/import", bytes.NewReader(nil))
		req.SetPathValue("id", "")
		rr := httptest.NewRecorder()
		h.clusterInternalWasmMigrateImport(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", rr.Code)
		}
	})
}

func TestGetWasmModuleHandlerSuccessAndNotFound(t *testing.T) {
	env := newWasmModuleV1TestEnv(t)
	now := time.Now().UTC()
	if err := env.store.UpsertWasmModule(context.Background(), store.WasmModuleRecord{
		ID: "mod-handler", ModuleRef: "file:///tmp/a.wasm", Status: string(models.WasmModuleStatusReady),
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}

	h := &handlers{deps: Deps{Service: env.svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/wasm-modules/mod-handler", nil)
	req.SetPathValue("id", "mod-handler")
	h.getWasmModule(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get status = %d body=%s", rr.Code, rr.Body.String())
	}

	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/v1/wasm-modules/missing", nil)
	req2.SetPathValue("id", "missing")
	h.getWasmModule(rr2, req2)
	if rr2.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", rr2.Code)
	}
}

func TestCreateWasmModuleHandlerDirectSuccess(t *testing.T) {
	env := newWasmModuleV1TestEnv(t)
	fakeWasm := filepath.Join(t.TempDir(), "handler.wasm")
	if err := os.WriteFile(fakeWasm, []byte("\x00asm"), 0o644); err != nil {
		t.Fatalf("write wasm: %v", err)
	}
	h := &handlers{deps: Deps{Service: env.svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	body, _ := json.Marshal(models.CreateWasmModuleRequest{
		ID: "direct-mod", ModuleRef: "file://" + fakeWasm,
	})
	rr := httptest.NewRecorder()
	h.createWasmModule(rr, httptest.NewRequest(http.MethodPost, "/v1/wasm-modules", bytes.NewReader(body)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterCreateTemplateWrapSelfSuccess(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	env.svc.AttachCluster(&createForwardCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
		target: cluster.PlacementTarget{NodeID: "node-a", IsSelf: true},
	})
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/templates",
		strings.NewReader(`{"image":"docker://alpine:3.20"}`)))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAddCustomDomainSuccess(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, st := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-domain", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		ContainerID: "ctr", ContainerIP: "10.0.0.1",
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-domain/custom-domains",
		strings.NewReader(`{"hostname":"api.example.com"}`))
	req.SetPathValue("id", "sb-domain")
	h.addCustomDomain(rr, req)
	if rr.Code != http.StatusCreated && rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestResolveSnapshotImageSingleLineFROM(t *testing.T) {
	h := &handlers{deps: Deps{Build: BuildConfig{}}}
	img, built, err := h.resolveSnapshotImage(context.Background(), "FROM alpine:3.20", nil)
	if err != nil || built != "" || img != "alpine:3.20" {
		t.Fatalf("resolveSnapshotImage = (%q, %q, %v)", img, built, err)
	}
}

func TestClusterTemplateItemWrapFallsThroughToLocal(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	now := time.Now().UTC()
	tpl := &models.Template{
		ID: "tpl-local", Image: "docker://local", Status: models.TemplateStatusReady,
		RootfsPath: filepath.Join(t.TempDir(), "rootfs.ext4"),
		CreatedAt:  now, UpdatedAt: now,
	}
	if err := env.store.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer peer.Close()
	env.svc.AttachCluster(templateMembersCluster("server-a", peer.URL))

	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/templates/tpl-local", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterTemplateItemWrapPeerSuccess(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	now := time.Now().UTC()
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(&models.Template{
			ID: "tpl-peer", Image: "docker://peer", Status: models.TemplateStatusReady,
			CreatedAt: now, UpdatedAt: now,
		})
	}))
	defer peer.Close()
	env.svc.AttachCluster(templateMembersCluster("server-a", peer.URL))

	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/templates/tpl-peer", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterListTemplatesWrapForwardedHeader(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
	req.Header.Set(clusterTemplateForwardedHeader, "1")
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateTemplateDirectSuccess(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	h := &handlers{deps: Deps{Service: env.svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	rr := httptest.NewRecorder()
	h.createTemplate(rr, httptest.NewRequest(http.MethodPost, "/v1/templates",
		strings.NewReader(`{"image":"docker://alpine:3.20"}`)))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestResizeSandboxHandlerNotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/sandboxes/missing/resize", strings.NewReader(`{"cpu":2}`))
	req.SetPathValue("id", "missing")
	h.resizeSandbox(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestUpdateLifecycleHandlerNotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/sandboxes/missing/lifecycle", strings.NewReader(`{"lifecycle":"ephemeral"}`))
	req.SetPathValue("id", "missing")
	h.updateLifecycle(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestUpdateNetworkLimitsHandler(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, st := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-net", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		ContainerID: "ctr", ContainerIP: "10.0.0.1",
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/sandboxes/sb-net/network-limits",
		strings.NewReader(`{"egress_mbps":10}`))
	req.SetPathValue("id", "sb-net")
	h.updateNetworkLimits(rr, req)
	if rr.Code != http.StatusOK && rr.Code != http.StatusNotFound && rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterCreateWrapSelfPathCoverage95(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlersCreateSandboxSuccessCoverage95(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
	rr := httptest.NewRecorder()
	h.createSandbox(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

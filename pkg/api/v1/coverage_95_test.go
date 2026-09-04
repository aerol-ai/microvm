package v1

import (
	"bytes"
	"context"
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
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

type v1WasmMigrateHost struct {
	noopRuntime
	snapDir  string
	cloneGen string
}

func (h v1WasmMigrateHost) MigrateSandbox(_ context.Context, sandbox *models.Sandbox, destDir string) (string, string, error) {
	id := "sandbox"
	if sandbox != nil && sandbox.ID != "" {
		id = sandbox.ID
	}
	dst := filepath.Join(destDir, id, "mem.snap")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return "", "", err
	}
	entries, err := os.ReadDir(h.snapDir)
	if err != nil {
		return "", "", err
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(h.snapDir, ent.Name()))
		if err != nil {
			return "", "", err
		}
		if err := os.WriteFile(filepath.Join(dst, ent.Name()), data, 0o600); err != nil {
			return "", "", err
		}
	}
	return dst, h.cloneGen, nil
}

type v1WasmMigrateCluster struct {
	*cluster.Noop
	selfID       string
	targetID     string
	targetURL    string
	importClient *http.Client
	spec         *models.CreateSandboxRequest
}

func (c *v1WasmMigrateCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return cluster.OwnerInfo{NodeID: c.selfID, IsSelf: true}, nil
}

func (c *v1WasmMigrateCluster) Members() []cluster.Member {
	targetURL := c.targetURL
	if targetURL == "" {
		targetURL = "http://target"
	}
	return []cluster.Member{
		{NodeID: c.selfID, APIURL: "http://self", Alive: true, Role: config.NodeRoleWorker},
		{NodeID: c.targetID, APIURL: targetURL, InternalURL: targetURL, Alive: true, Role: config.NodeRoleWorker},
	}
}

func (c *v1WasmMigrateCluster) SpecOf(string) *models.CreateSandboxRequest {
	return c.spec
}

func (c *v1WasmMigrateCluster) PeerDialMember(m cluster.Member) (*http.Client, string, error) {
	if c.targetURL == "" || m.NodeID != c.targetID {
		return nil, "", cluster.ErrPeerInternalURLRequired
	}
	return c.importClient, c.targetURL, nil
}

func seedV1WasmSandbox(t *testing.T, st *store.Store, id string) {
	t.Helper()
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: id, Runtime: models.RuntimeWasm, ModuleRef: "file:///tmp/demo.wasm",
		Image: "file:///tmp/demo.wasm", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Create sandbox %s: %v", id, err)
	}
}

func newV1WasmMigrateHarness(t *testing.T, importServer *httptest.Server) (*handlers, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	src := filepath.Join(t.TempDir(), "mem.snap")
	cap := wasmengine.SnapshotCapture{
		Config: wasmengine.SnapshotConfig{
			SchemaVersion:   1,
			Engine:          wasmengine.EngineNameWazero(),
			BaseModule:      wasmengine.SnapshotBaseModule{Digest: "sha256:abc", Size: 1},
			Durability:      models.DurabilityPassivatable,
			CloneGeneration: "gen-handoff",
		},
		Memory:    []byte("mem"),
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}
	if err := wasmengine.WriteSnapshotDir(src, cap); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableWasm: true, WasmModulesDir: t.TempDir()}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.SetWasmRuntime(v1WasmMigrateHost{snapDir: src, cloneGen: "gen-handoff"})
	targetURL := ""
	var importClient *http.Client
	if importServer != nil {
		targetURL = importServer.URL
		importClient = importServer.Client()
	}
	svc.AttachCluster(&v1WasmMigrateCluster{
		Noop:         cluster.NewNoop("node-a", "http://self", ""),
		selfID:       "node-a",
		targetID:     "node-b",
		targetURL:    targetURL,
		importClient: importClient,
		spec: &models.CreateSandboxRequest{
			Runtime: models.RuntimeWasm, ModuleRef: "file:///tmp/demo.wasm",
		},
	})
	seedV1WasmSandbox(t, st, "sb-handoff")
	return &handlers{deps: Deps{Service: svc, Logger: logger}}, st
}

func TestClusterWasmMigrateSuccess(t *testing.T) {
	var imported bool
	importSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/import") {
			imported = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(importSrv.Close)

	h, _ := newV1WasmMigrateHarness(t, importSrv)
	body := `{"sandbox_id":"sb-handoff","target_node_id":"node-b"}`
	rr := httptest.NewRecorder()
	h.clusterWasmMigrate(rr, httptest.NewRequest(http.MethodPost, cluster.PublicWasmMigratePath, strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if !imported {
		t.Fatal("expected target import call")
	}
}

func TestClusterInternalWasmMigrateExportSuccess(t *testing.T) {
	h, _ := newV1WasmMigrateHarness(t, nil)
	req := httptest.NewRequest(http.MethodGet, cluster.PublicInternalWasmMigratePath+"sb-handoff/export", nil)
	req.SetPathValue("id", "sb-handoff")
	rr := httptest.NewRecorder()
	h.clusterInternalWasmMigrateExport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get(cluster.WasmMigrateCloneGenHeader); got != "gen-handoff" {
		t.Fatalf("clone gen = %q", got)
	}
}

func TestClusterInternalWasmMigrateExportOrphaned(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableWasm: true, WasmModulesDir: t.TempDir()}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&orphanedOwnerCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodGet, cluster.PublicInternalWasmMigratePath+"sb-1/export", nil)
	req.SetPathValue("id", "sb-1")
	rr := httptest.NewRecorder()
	h.clusterInternalWasmMigrateExport(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rr.Code)
	}
}

type orphanedOwnerCluster struct {
	*cluster.Noop
}

func (orphanedOwnerCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return cluster.OwnerInfo{}, cluster.ErrOrphaned
}

func TestClusterInternalWasmMigrateImportSuccess(t *testing.T) {
	h, st := newV1WasmMigrateHarness(t, nil)

	exportRR := httptest.NewRecorder()
	exportReq := httptest.NewRequest(http.MethodGet, cluster.PublicInternalWasmMigratePath+"sb-handoff/export", nil)
	exportReq.SetPathValue("id", "sb-handoff")
	h.clusterInternalWasmMigrateExport(exportRR, exportReq)
	if exportRR.Code != http.StatusOK {
		t.Fatalf("export status = %d, body=%s", exportRR.Code, exportRR.Body.String())
	}

	importReq := httptest.NewRequest(http.MethodPut, cluster.PublicInternalWasmMigratePath+"sb-import/import", bytes.NewReader(exportRR.Body.Bytes()))
	importReq.SetPathValue("id", "sb-import")
	importReq.Header.Set(cluster.WasmMigrateCloneGenHeader, exportRR.Header().Get(cluster.WasmMigrateCloneGenHeader))
	importRR := httptest.NewRecorder()
	h.clusterInternalWasmMigrateImport(importRR, importReq)
	if importRR.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body=%s", importRR.Code, importRR.Body.String())
	}
	if _, err := st.Get(context.Background(), "sb-import"); err != nil {
		t.Fatalf("imported sandbox missing: %v", err)
	}
}

func TestPushWasmModuleHandlerBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("wasm_disabled", func(t *testing.T) {
		h := &handlers{deps: Deps{Service: service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil), Logger: logger}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/wasm-modules/push?name=demo&tag=latest", strings.NewReader("\x00asm"))
		h.pushWasmModule(rr, req)
		if rr.Code == http.StatusCreated {
			t.Fatal("expected push failure when wasm disabled")
		}
	})

	t.Run("missing_push_host", func(t *testing.T) {
		svc := service.New(config.Config{EnableWasm: true}, logger, nil, nil, nil, nil, nil, nil, nil)
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/wasm-modules/push?name=demo&tag=latest", strings.NewReader("\x00asm"))
		h.pushWasmModule(rr, req)
		if rr.Code == http.StatusCreated {
			t.Fatal("expected push failure without registry host")
		}
	})
}

func TestListAndDeleteJSBundleStoreErrors(t *testing.T) {
	_ = newJSBundleV1TestEnv(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	_ = st.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableIsolate: true}, logger, st, &noopRuntime{}, nil, nil, nil, nil, nil)
	handler := &handlers{deps: Deps{Service: svc, Logger: logger}}

	listRR := httptest.NewRecorder()
	handler.listJSBundles(listRR, httptest.NewRequest(http.MethodGet, "/v1/js-bundles", nil))
	if listRR.Code == http.StatusOK {
		t.Fatal("expected list failure with closed store")
	}

	delRR := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/js-bundles/deadbeef", nil)
	req.SetPathValue("id", "deadbeef")
	handler.deleteJSBundle(delRR, req)
	if delRR.Code == http.StatusNoContent {
		t.Fatal("expected delete failure with closed store")
	}
}

func TestHandlers_CreateSandboxContextErrors(t *testing.T) {
	t.Run("canceled", func(t *testing.T) {
		rt := &apiRecordingRuntime{createDelay: time.Second}
		h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`)).WithContext(ctx)
		h.createSandbox(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("deadline_exceeded", func(t *testing.T) {
		rt := &apiRecordingRuntime{createDelay: 2 * time.Second}
		h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`)).WithContext(ctx)
		h.createSandbox(rr, req)
		if rr.Code != http.StatusGatewayTimeout {
			t.Fatalf("status = %d, want 504; body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestClusterCreateTemplateWrapPlacementErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&createForwardCluster{
		Noop:      cluster.NewNoop("server-a", "http://server-a", ""),
		selectErr: cluster.ErrInvalidTopology,
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	rr := httptest.NewRecorder()
	h.clusterCreateTemplateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/templates", strings.NewReader(`{"image":"docker://alpine:3.20"}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterListTemplatesWrapLocalErrorEmptyMerge(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	_ = env.store.Close()
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/templates", nil))
	if rr.Code == http.StatusOK {
		t.Fatal("expected local list error when store is closed")
	}
}

func TestListWasmModulesStoreError(t *testing.T) {
	env := newWasmModuleV1TestEnv(t)
	_ = env.store.Close()
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/wasm-modules", nil))
	if rr.Code == http.StatusOK {
		t.Fatal("expected list failure with closed store")
	}
}

func TestHandlersReconcileSuccess(t *testing.T) {
	t.Skip("reconcile needs a fully wired Service (runtime/docker); covered elsewhere")
}

func TestClusterWasmMigrateServiceNil(t *testing.T) {
	h := &handlers{deps: Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	rr := httptest.NewRecorder()
	h.clusterWasmMigrate(rr, httptest.NewRequest(http.MethodPost, cluster.PublicWasmMigratePath, strings.NewReader(`{"sandbox_id":"sb","target_node_id":"node-b"}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterInternalWasmMigrateExportMissingID(t *testing.T) {
	h, _ := newV1WasmMigrateHarness(t, nil)
	req := httptest.NewRequest(http.MethodGet, cluster.PublicInternalWasmMigratePath+"/export", nil)
	req.SetPathValue("id", "")
	rr := httptest.NewRecorder()
	h.clusterInternalWasmMigrateExport(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestClusterCreateTemplateWrapForwardedHeaderBypass(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/templates", strings.NewReader(`{"image":"docker://alpine:3.20"}`))
	req.Header.Set(clusterTemplateForwardedHeader, "1")
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted && rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestGetWasmModuleStoreError(t *testing.T) {
	env := newWasmModuleV1TestEnv(t)
	_ = env.store.Close()
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/wasm-modules/missing", nil))
	if rr.Code == http.StatusOK {
		t.Fatal("expected get failure with closed store")
	}
}

var _ wasmruntime.MigrationHost = v1WasmMigrateHost{}

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
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// quietRuntime is safe for Reconcile / CreateSnapshot handler paths that need
// ListManaged and CreateSnapshot without panicking like noopRuntime.
type quietRuntime struct {
	apiRecordingRuntime
}

func (quietRuntime) CreateSnapshot(_ context.Context, _, name string) (string, error) {
	return filepath.Join("/tmp", name+".snap"), nil
}

func (quietRuntime) Ping(context.Context) error { return nil }

type volumeErrCluster struct {
	*cluster.Noop
	byIDErr, byNameErr, listErr, sourceErr, attachErr error
}

func (c *volumeErrCluster) VolumeByID(context.Context, string, string) (models.Volume, error) {
	return models.Volume{}, c.byIDErr
}
func (c *volumeErrCluster) VolumeByName(context.Context, string, string) (models.Volume, error) {
	return models.Volume{}, c.byNameErr
}
func (c *volumeErrCluster) VolumesForTenant(context.Context, string) ([]models.Volume, error) {
	return nil, c.listErr
}
func (c *volumeErrCluster) VolumeExistsForSource(context.Context, string) (bool, error) {
	return false, c.sourceErr
}
func (c *volumeErrCluster) VolumeAttachmentCount(context.Context, string, string) (int, error) {
	return 0, c.attachErr
}

func TestHandlersReconcileSuccessPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	caddyClient := caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
	mgr, err := mounts.New(logger, mounts.Config{
		RootDir: filepath.Join(t.TempDir(), "mounts"),
		CredDir: filepath.Join(t.TempDir(), "cred"),
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)
	svc := service.New(config.Config{}, logger, st, &quietRuntime{}, nil, caddyClient, nil, mgr, nil)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	rr := httptest.NewRecorder()
	h.reconcile(rr, httptest.NewRequest(http.MethodPost, "/v1/admin/reconcile", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlersCreateSnapshotSuccessPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-snap-ok", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		ContainerID: "ctr", ContainerIP: "10.0.0.1",
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	svc := service.New(config.Config{}, logger, st, &quietRuntime{}, nil, nil, nil, nil, nil)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-snap-ok/snapshot", strings.NewReader(`{"name":"snap-ok"}`))
	req.SetPathValue("id", "sb-snap-ok")
	h.createSnapshot(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestTemplateWrapsNilServiceAndNilCluster(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("create_nil_cluster", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		env.svc.ClearClusterForTest()
		h := &handlers{deps: Deps{Service: env.svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterCreateTemplateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/templates",
			strings.NewReader(`{"image":"docker://alpine:3.20"}`)))
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("list_nil_cluster", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		env.svc.ClearClusterForTest()
		h := &handlers{deps: Deps{Service: env.svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterListTemplatesWrap(rr, httptest.NewRequest(http.MethodGet, "/v1/templates", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("item_nil_service", func(t *testing.T) {
		h := &handlers{deps: Deps{Logger: logger}}
		local := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})
		rr := httptest.NewRecorder()
		h.clusterTemplateItemWrap(local)(rr, httptest.NewRequest(http.MethodGet, "/v1/templates/x", nil))
		if rr.Code != http.StatusTeapot {
			t.Fatalf("status = %d", rr.Code)
		}
	})

	t.Run("item_nil_cluster", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		env.svc.ClearClusterForTest()
		h := &handlers{deps: Deps{Service: env.svc, Logger: logger}}
		local := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})
		rr := httptest.NewRecorder()
		h.clusterTemplateItemWrap(local)(rr, httptest.NewRequest(http.MethodGet, "/v1/templates/x", nil))
		if rr.Code != http.StatusTeapot {
			t.Fatalf("status = %d", rr.Code)
		}
	})
}

func TestClusterInternalVolumeErrorBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &volumeErrCluster{
		Noop:      cluster.NewNoop("self", "http://self", ""),
		byNameErr: cluster.ErrUnknownVolume,
		listErr:   errors.New("list failed"),
		sourceErr: errors.New("source failed"),
		attachErr: errors.New("attach failed"),
	}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	cases := []struct {
		query  string
		status int
	}{
		{"kind=name&tenant=t&name=missing", http.StatusNotFound},
		{"kind=list&tenant=t", http.StatusInternalServerError},
		{"kind=source&source=s3://x", http.StatusInternalServerError},
		{"kind=attachment_count&tenant=t&id=vol-1", http.StatusInternalServerError},
	}
	for _, tc := range cases {
		rr := httptest.NewRecorder()
		h.clusterInternalVolume(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/volume?"+tc.query, nil))
		if rr.Code != tc.status {
			t.Fatalf("%s: status = %d want %d body=%s", tc.query, rr.Code, tc.status, rr.Body.String())
		}
	}
}

func TestSetNodeDrainStateSelfEvacuate(t *testing.T) {
	stub := &drainStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h := drainTestHandler(t, stub)
	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/nodes/node-a/drain", nil)
	req.SetPathValue("id", "node-a") // self → EvacuateLocalWasmSandboxesForDrain
	rr := httptest.NewRecorder()
	h.clusterDrainNode(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if len(stub.setCalls) != 1 || stub.setCalls[0].nodeID != "node-a" || !stub.setCalls[0].drained {
		t.Fatalf("setCalls = %+v", stub.setCalls)
	}
}

func TestTemplatePeerRequestForwardsAuthAndContentType(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer t" || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "missing headers", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer peer.Close()

	parent := httptest.NewRequest(http.MethodPost, "/v1/templates/x", strings.NewReader(`{}`))
	parent.Header.Set("Authorization", "Bearer t")
	parent.Header.Set("Content-Type", "application/json")
	c := &membersStubCluster{Noop: cluster.NewNoop("self", "http://self", ""), internalClient: peer.Client()}
	status, _, body, err := templatePeerRequest(c, parent, []byte(`{}`), cluster.Member{
		NodeID: "peer", InternalURL: peer.URL, Alive: true,
	})
	if err != nil || status != http.StatusOK || !strings.Contains(string(body), "ok") {
		t.Fatalf("status=%d err=%v body=%s", status, err, body)
	}
}

func TestCreateTemplateServiceError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Closed store → CreateTemplate fails → WriteStoreAwareError branch.
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	svc := service.New(config.Config{EnableFirecracker: true, FirecrackerTemplatesDir: t.TempDir()}, logger, st, &quietRuntime{}, nil, nil, nil, nil, nil)
	_ = st.Close()
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	rr := httptest.NewRecorder()
	h.createTemplate(rr, httptest.NewRequest(http.MethodPost, "/v1/templates",
		strings.NewReader(`{"image":"docker://alpine:3.20"}`)))
	if rr.Code == http.StatusAccepted {
		t.Fatal("expected create failure with closed store")
	}
}

func TestCreateWasmModuleServiceError(t *testing.T) {
	env := newWasmModuleV1TestEnv(t)
	_ = env.store.Close()
	h := &handlers{deps: Deps{Service: env.svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	rr := httptest.NewRecorder()
	h.createWasmModule(rr, httptest.NewRequest(http.MethodPost, "/v1/wasm-modules",
		strings.NewReader(`{"ref":"oci://example/mod:1"}`)))
	if rr.Code == http.StatusCreated {
		t.Fatal("expected create failure with closed store")
	}
}

func TestClusterDeleteOrphanNilCluster(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.ClearClusterForTest()
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/cluster/orphans/sb-x", nil)
	req.SetPathValue("id", "sb-x")
	h.clusterDeleteOrphan(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestWriteInternalPlacementNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	rr := httptest.NewRecorder()
	h.writeInternalPlacement(rr, "missing-placement")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestClusterTemplateItemWrapForwardedHeader(t *testing.T) {
	h := &handlers{deps: Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	local := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/templates/x", nil)
	req.Header.Set(clusterTemplateForwardedHeader, "1")
	rr := httptest.NewRecorder()
	h.clusterTemplateItemWrap(local)(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestClusterCreateWrapNilClusterFallsThrough(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(config.Config{}, logger, st, &quietRuntime{}, nil, nil, nil, nil, nil)
	svc.ClearClusterForTest()
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes",
		strings.NewReader(`{"image":"alpine:3.20"}`)))
	if rr.Code == 0 {
		t.Fatal("expected a response")
	}
}

func TestClusterWasmMigrateServiceError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableWasm: true, WasmModulesDir: t.TempDir()}, logger, nil, nil, nil, nil, nil, nil, nil)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	rr := httptest.NewRecorder()
	h.clusterWasmMigrate(rr, httptest.NewRequest(http.MethodPost, cluster.PublicWasmMigratePath,
		strings.NewReader(`{"sandbox_id":"missing","target_node_id":"node-b"}`)))
	if rr.Code == http.StatusOK {
		t.Fatal("expected migrate failure")
	}
}

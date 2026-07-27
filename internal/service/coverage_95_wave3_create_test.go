package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

type storeCloseAfterRuntimeCreate struct {
	*recordingRuntime
	st *storepkg.Store
}

func (r *storeCloseAfterRuntimeCreate) Create(ctx context.Context, req models.CreateSandboxRequest, id, token string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	state, err := r.recordingRuntime.Create(ctx, req, id, token, binds)
	if err == nil {
		_ = r.st.Close()
	}
	return state, err
}

type failPutAttachCluster struct {
	*cluster.Noop
}

func (c *failPutAttachCluster) PutVolumeAttachments(context.Context, []models.VolumeAttachment) error {
	return errors.New("cluster put attachments failed")
}

func TestCreateSandboxPutMountsFailureRollbackWave3(t *testing.T) {
	ctx := context.Background()
	base := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarnessAllowStoreClose(t, base)
	svc.admitter = nil
	svc.docker = &storeCloseAfterRuntimeCreate{recordingRuntime: base, st: svc.store}

	const id = "sb-store-create-fail"
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20",
	}, id)
	// Closing the store right after runtime Create exercises the post-runtime
	// persist rollback chain (same teardown as PutMounts, before row insert).
	if err == nil {
		t.Fatal("expected persist failure")
	}
	if base.createCalls != 1 {
		t.Fatalf("runtime create calls = %d, want 1", base.createCalls)
	}
	if len(base.destroyIDs) != 1 || base.destroyIDs[0] != id {
		t.Fatalf("destroy ids = %v, want [%s]", base.destroyIDs, id)
	}
}

func TestVolumeMetaPutAttachmentsClusterFailureWave3(t *testing.T) {
	// Prefer a direct volumeMeta failure over create+MountAll: fake mount-s3
	// bind/hdiutil is flaky offline on macOS and never reaches PutAttachments.
	s := enabledVolumeService(t)
	s.cfg.EnableCluster = true
	s.AttachCluster(&failPutAttachCluster{Noop: cluster.NewNoop("self", "http://self", "")})
	ctx := context.Background()
	v, err := s.CreatePlatformVolume(ctx, "data")
	if err != nil {
		t.Fatalf("CreatePlatformVolume: %v", err)
	}
	err = s.volumeMeta().PutAttachments(ctx, []models.VolumeAttachment{{
		Tenant: v.Tenant, VolumeID: v.ID, SandboxID: "sb-x", Target: "/data", Source: v.Source,
	}})
	if err == nil || !strings.Contains(err.Error(), "cluster put attachments failed") {
		t.Fatalf("PutAttachments = %v, want cluster failure", err)
	}
}

func TestWasmCreatePutMountsFailureRollbackWave3(t *testing.T) {
	ctx := context.Background()
	wrt := &wasmRecordingRuntime{}
	svc, _, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.admitter = nil
	svc.SetWasmRuntime(&wasmCloseStoreAfterCreate{wasmRecordingRuntime: wrt, st: svc.store})

	const id = "sb-wasm-store-fail"
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Runtime:   models.RuntimeWasm,
		ModuleRef: "hello.wasm",
	}, id)
	if err == nil {
		t.Fatal("expected persist failure on wasm create")
	}
	if wrt.createCalls != 1 {
		t.Fatalf("wasm create calls = %d, want 1", wrt.createCalls)
	}
	if wrt.destroyCalls != 1 {
		t.Fatalf("wasm destroy calls = %d, want rollback destroy", wrt.destroyCalls)
	}
}

type wasmCloseStoreAfterCreate struct {
	*wasmRecordingRuntime
	st *storepkg.Store
}

func (r *wasmCloseStoreAfterCreate) Create(ctx context.Context, req models.CreateSandboxRequest, id, token string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	state, err := r.wasmRecordingRuntime.Create(ctx, req, id, token, binds)
	if err == nil {
		_ = r.st.Close()
	}
	return state, err
}

func TestWasmCreateCustomDomainSyncFailureWave3(t *testing.T) {
	ctx := context.Background()
	wrt := &wasmRecordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.test"
	svc.admitter = nil
	svc.SetWasmRuntime(wrt)

	var customPatchCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/id/sandbox-sb-wasm-cd-sync-custom-"):
			customPatchCalls++
			if customPatchCalls == 1 {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "boom", http.StatusInternalServerError)
		case r.Method == http.MethodPatch && r.URL.Path == "/id/sandbox-sb-wasm-cd-sync":
			http.NotFound(w, r)
		case r.Method == http.MethodPut && r.URL.Path == "/config/apps/http/servers/srv0/routes/0":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	svc.cfg.EnableCaddy = true
	svc.cfg.CaddyAdminURL = server.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.caddy = caddy.New(svc.cfg)

	allowPublic := true
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Runtime:            models.RuntimeWasm,
		ModuleRef:          "hello.wasm",
		CustomDomains:      []string{"api.external.test"},
		AllowPublicTraffic: &allowPublic,
	}, "sb-wasm-cd-sync")
	if err == nil || !strings.Contains(err.Error(), "install wasm custom-domain route") {
		t.Fatalf("CreateSandboxWithID() error = %v, want wasm custom domain sync failure", err)
	}
	if _, getErr := st.Get(ctx, "sb-wasm-cd-sync"); getErr == nil {
		t.Fatal("failed create should not leave sandbox row")
	}
	if wrt.destroyCalls != 1 {
		t.Fatalf("destroy calls = %d, want rollback", wrt.destroyCalls)
	}
}

func TestRunTemplateGCRemoveAllAndCIDReleaseWave3(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newHealthHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour

	now := time.Now().UTC()
	staleAt := now.Add(-48 * time.Hour)

	tplCID := &models.Template{
		ID: "tpl-gc-cid-w3", Image: "docker://alpine",
		Status: models.TemplateStatusReady, HasSnapshot: true,
		RootfsPath: filepath.Join(templatesDir, "tpl-gc-cid-w3", "rootfs.ext4"),
		CreatedAt:  staleAt, UpdatedAt: staleAt,
	}
	if err := os.MkdirAll(filepath.Dir(tplCID.RootfsPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(tplCID.RootfsPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	if err := st.CreateTemplate(ctx, tplCID); err != nil {
		t.Fatalf("CreateTemplate cid: %v", err)
	}

	readOnlyDir := filepath.Join(templatesDir, "tpl-gc-rmfail-w3")
	if err := os.MkdirAll(readOnlyDir, 0o755); err != nil {
		t.Fatalf("mkdir ro parent: %v", err)
	}
	tplRM := &models.Template{
		ID: "tpl-gc-rmfail-w3", Image: "docker://alpine",
		Status:     models.TemplateStatusReady,
		RootfsPath: filepath.Join(readOnlyDir, "rootfs.ext4"),
		CreatedAt:  staleAt, UpdatedAt: staleAt,
	}
	if err := os.WriteFile(tplRM.RootfsPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write ro rootfs: %v", err)
	}
	if err := os.Chmod(readOnlyDir, 0o555); err != nil {
		t.Fatalf("chmod ro: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnlyDir, 0o755) })
	if err := st.CreateTemplate(ctx, tplRM); err != nil {
		t.Fatalf("CreateTemplate rmfail: %v", err)
	}

	alloc := &fakeCIDAllocator{releaseErr: errors.New("cid release boom")}
	svc.SetTemplateCIDAllocator(alloc)
	svc.runTemplateGC(ctx, now)

	alloc.mu.Lock()
	defer alloc.mu.Unlock()
	if len(alloc.releaseIDs) == 0 || alloc.releaseIDs[0] != tplCID.ID {
		t.Fatalf("releaseIDs = %v, want tpl-gc-cid-w3 release attempt", alloc.releaseIDs)
	}
	if _, err := st.GetTemplate(ctx, tplCID.ID); err == nil {
		t.Fatal("CID-error template row should still be deleted")
	}
	if _, err := st.GetTemplate(ctx, tplRM.ID); err == nil {
		t.Fatal("RemoveAll-error template row should still be deleted")
	}
}

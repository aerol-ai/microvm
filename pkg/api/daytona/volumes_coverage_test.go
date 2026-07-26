package daytona

import (
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

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func newDaytonaVolumesTestEnv(t *testing.T) (http.Handler, *service.Service, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cipher, err := secrets.NewCipher("", filepath.Join(dir, "cipher.key"))
	if err != nil {
		t.Fatalf("secrets.NewCipher: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := mounts.New(logger, mounts.Config{
		RootDir:     filepath.Join(dir, "mounts"),
		CredDir:     filepath.Join(dir, "creds"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	cfg := config.Config{
		EnableCaddy: false,
		ToolboxPort: 2280,
		PATToken:    "operator-pat",
		EnableWasm:  true,
		PlatformVolumes: config.PlatformVolumesConfig{
			Enabled:  true,
			Backend:  config.PlatformVolumesBackendS3,
			S3Bucket: "aerol-volumes",
			S3Prefix: "volumes",
		},
	}
	svc := service.New(cfg, logger, st, newFakeDaytonaContractRuntime(), nil, caddy.New(cfg), cipher, mgr, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth:    func(h http.Handler) http.Handler { return h },
	})
	return mux, svc, st
}

func newDaytonaVolumesTestEnvWithMaxVolumes(t *testing.T, max int) (http.Handler, *service.Service, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cipher, err := secrets.NewCipher("", filepath.Join(dir, "cipher.key"))
	if err != nil {
		t.Fatalf("secrets.NewCipher: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := mounts.New(logger, mounts.Config{
		RootDir:     filepath.Join(dir, "mounts"),
		CredDir:     filepath.Join(dir, "creds"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	cfg := config.Config{
		EnableCaddy: false,
		ToolboxPort: 2280,
		PATToken:    "operator-pat",
		PlatformVolumes: config.PlatformVolumesConfig{
			Enabled:      true,
			Backend:      config.PlatformVolumesBackendS3,
			S3Bucket:     "aerol-volumes",
			S3Prefix:     "volumes",
			MaxPerTenant: max,
		},
	}
	svc := service.New(cfg, logger, st, newFakeDaytonaContractRuntime(), nil, caddy.New(cfg), cipher, mgr, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth:    func(h http.Handler) http.Handler { return h },
	})
	return mux, svc, st
}

func TestDaytonaVolumeHandlersCRUD(t *testing.T) {
	handler, _, _ := newDaytonaVolumesTestEnv(t)

	createRR := httptest.NewRecorder()
	handler.ServeHTTP(createRR, httptest.NewRequest(http.MethodPost, "/daytona/volumes",
		strings.NewReader(`{"name":"project-data"}`)))
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", createRR.Code, createRR.Body.String())
	}
	var created volumeResponse
	if err := json.NewDecoder(createRR.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == "" || created.Name != "project-data" || created.State != "ready" {
		t.Fatalf("created = %+v", created)
	}

	listRR := httptest.NewRecorder()
	handler.ServeHTTP(listRR, httptest.NewRequest(http.MethodGet, "/daytona/volumes", nil))
	if listRR.Code != http.StatusOK {
		t.Fatalf("list status = %d", listRR.Code)
	}
	var listed []volumeResponse
	if err := json.NewDecoder(listRR.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("listed = %+v", listed)
	}

	getRR := httptest.NewRecorder()
	handler.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, "/daytona/volumes/"+created.ID, nil))
	if getRR.Code != http.StatusOK {
		t.Fatalf("get status = %d", getRR.Code)
	}

	byNameRR := httptest.NewRecorder()
	handler.ServeHTTP(byNameRR, httptest.NewRequest(http.MethodGet, "/daytona/volumes/by-name/project-data", nil))
	if byNameRR.Code != http.StatusOK {
		t.Fatalf("get by name status = %d", byNameRR.Code)
	}

	delRR := httptest.NewRecorder()
	handler.ServeHTTP(delRR, httptest.NewRequest(http.MethodDelete, "/daytona/volumes/"+created.ID, nil))
	if delRR.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", delRR.Code)
	}
}

func TestDaytonaVolumeHandlerValidationAndErrors(t *testing.T) {
	handler, _, st := newDaytonaVolumesTestEnv(t)

	t.Run("invalid_json", func(t *testing.T) {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/daytona/volumes", strings.NewReader("{")))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("missing_name", func(t *testing.T) {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/daytona/volumes", strings.NewReader(`{"name":" "}`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/daytona/volumes/missing-id", nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})

	t.Run("quota_conflict", func(t *testing.T) {
		quotaHandler, quotaSvc, _ := newDaytonaVolumesTestEnvWithMaxVolumes(t, 1)
		if _, err := quotaSvc.CreatePlatformVolume(context.Background(), "first"); err != nil {
			t.Fatalf("seed volume: %v", err)
		}
		rr := httptest.NewRecorder()
		quotaHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/daytona/volumes", strings.NewReader(`{"name":"second"}`)))
		if rr.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("list_store_error", func(t *testing.T) {
		_ = st.Close()
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/daytona/volumes", nil))
		if rr.Code == http.StatusOK {
			t.Fatal("expected list failure with closed store")
		}
	})
}

func TestWriteVolumeErrorBranches(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "disabled", err: models.ErrPlatformVolumesDisabled, wantStatus: http.StatusPreconditionFailed},
		{name: "in_use", err: models.ErrPlatformVolumeInUse, wantStatus: http.StatusConflict},
		{name: "quota", err: models.ErrPlatformVolumeQuota, wantStatus: http.StatusConflict},
		{name: "not_found", err: store.ErrNotFound, wantStatus: http.StatusNotFound},
		{name: "default", err: errors.New("bad volume name"), wantStatus: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeVolumeError(rr, tc.err)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tc.wantStatus)
			}
		})
	}
}

func TestTranslateCreateSandboxRequestWasmAndVolumes(t *testing.T) {
	handler, svc, st := newDaytonaVolumesTestEnv(t)
	_ = handler

	ctx := context.Background()
	vol, err := svc.CreatePlatformVolume(ctx, "attach-me")
	if err != nil {
		t.Fatalf("CreatePlatformVolume: %v", err)
	}

	modID := "daytona-mod-" + strings.ReplaceAll(t.Name(), "/", "_")
	fakeWasm := filepath.Join(t.TempDir(), "demo.wasm")
	if err := os.WriteFile(fakeWasm, []byte("\x00asm"), 0o644); err != nil {
		t.Fatalf("write wasm: %v", err)
	}
	if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID: modID, ModuleRef: "file://" + fakeWasm,
		Status:    string(models.WasmModuleStatusReady),
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}
	gotMod, err := svc.GetWasmModule(ctx, modID)
	if err != nil || gotMod.Status != models.WasmModuleStatusReady {
		t.Fatalf("GetWasmModule = %+v err=%v", gotMod, err)
	}

	h := newHandlers(Deps{Service: svc})
	wasmLabels := map[string]string{
		"runtime":    models.RuntimeWasm,
		"module_ref": "file://" + fakeWasm,
	}
	one := int32(1)
	wasmReq, built, err := h.translateCreateSandboxRequest(ctx, createSandboxRequest{
		Snapshot: stringPtr(modID),
		Labels:   &wasmLabels,
		Cpu:      &one,
		Memory:   &one,
	})
	if err != nil {
		t.Fatalf("wasm translate: %v", err)
	}
	if built != "" || wasmReq.Runtime != models.RuntimeWasm {
		t.Fatalf("wasmReq = %+v built=%q", wasmReq, built)
	}

	_, _, err = h.translateCreateSandboxRequest(ctx, createSandboxRequest{
		Snapshot: stringPtr(modID),
		Labels:   &wasmLabels,
		Volumes:  []map[string]any{{"volumeId": vol.ID, "mountPath": "/data"}},
	})
	if err == nil || !strings.Contains(err.Error(), "not supported for wasm") {
		t.Fatalf("err = %v, want wasm volume rejection", err)
	}

	withVol, _, err := h.translateCreateSandboxRequest(ctx, createSandboxRequest{
		BuildInfo: &buildInfoRequest{DockerfileContent: stringPtr("FROM alpine")},
		Volumes:   []map[string]any{{"volumeId": vol.ID, "mountPath": "/data"}},
	})
	if err != nil {
		t.Fatalf("docker volume translate: %v", err)
	}
	if len(withVol.PlatformVolumes) != 1 || withVol.PlatformVolumes[0].Name != "attach-me" {
		t.Fatalf("platform volumes = %+v", withVol.PlatformVolumes)
	}
}

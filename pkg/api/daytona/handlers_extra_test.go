package daytona

import (
	"context"
	"crypto/tls"
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

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

type fakeHandlerRuntime struct {
	createState    *models.SandboxRuntimeState
	createErr      error
	createCallback func()
	startState     *models.SandboxRuntimeState
	startErr       error
	stopErr        error
	destroyErr     error
	resizeErr      error
	inspectState   *models.SandboxRuntimeState
	inspectErr     error
	removeImageErr error
	listManaged    map[string]*models.SandboxRuntimeState
	listManagedErr error
}

func (f *fakeHandlerRuntime) Create(ctx context.Context, req models.CreateSandboxRequest, id string, name string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	if f.createCallback != nil {
		f.createCallback()
	}
	return f.createState, f.createErr
}
func (f *fakeHandlerRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	return "sha256:fake", nil
}
func (f *fakeHandlerRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	return f.startState, f.startErr
}
func (f *fakeHandlerRuntime) Stop(context.Context, string) error {
	return f.stopErr
}
func (f *fakeHandlerRuntime) Destroy(context.Context, *models.Sandbox) error {
	return f.destroyErr
}
func (f *fakeHandlerRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return f.resizeErr
}
func (f *fakeHandlerRuntime) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	return f.inspectState, f.inspectErr
}
func (f *fakeHandlerRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	return f.listManaged, f.listManagedErr
}
func (f *fakeHandlerRuntime) Ping(context.Context) error                { return nil }
func (f *fakeHandlerRuntime) RemoveImage(context.Context, string) error { return f.removeImageErr }
func (f *fakeHandlerRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	return nil
}
func (f *fakeHandlerRuntime) ClearNetworkRules(string) error                     { return nil }
func (f *fakeHandlerRuntime) ApplyEgressPolicy(string, []string, []string) error { return nil }
func (f *fakeHandlerRuntime) ClearEgressPolicy(string, []string, []string) error { return nil }
func (f *fakeHandlerRuntime) ApplyNetworkBlockAll(string) error                  { return nil }
func (f *fakeHandlerRuntime) ApplyNetworkBlockIngress(string) error              { return nil }
func (f *fakeHandlerRuntime) ClearNetworkBlockIngress(string) error              { return nil }
func (f *fakeHandlerRuntime) ClearNetworkBlockEgress(string) error               { return nil }

func newHandlerExtraTestEnv(t *testing.T) (*service.Service, *store.Store, *fakeHandlerRuntime, http.Handler) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rt := &fakeHandlerRuntime{}

	mgr, err := mounts.New(logger, mounts.Config{
		RootDir:     filepath.Join(t.TempDir(), "mounts"),
		CredDir:     filepath.Join(t.TempDir(), "cred"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts: %v", err)
	}
	t.Cleanup(mgr.Close)

	caddyClient := caddy.New(config.Config{EnableCaddy: false})

	svc := service.New(config.Config{}, logger, st, rt, nil, caddyClient, newDaytonaTestCipher(t), mgr, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth: func(next http.Handler) http.Handler {
			return next
		},
	})
	return svc, st, rt, mux
}

func TestListSandboxesAndPagination(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)

	// Seed sandboxes
	now := time.Now().UTC()
	sb1 := &models.Sandbox{
		ID:             "sb-1",
		Name:           "alpha",
		Status:         models.SandboxStatusStarted,
		Tags:           map[string]string{"group": "a"},
		ToolboxEnabled: true,
		CreatedAt:      now.Add(-time.Hour),
		UpdatedAt:      now,
	}
	sb2 := &models.Sandbox{
		ID:             "sb-2",
		Name:           "beta",
		Status:         models.SandboxStatusStopped,
		Tags:           map[string]string{"group": "b"},
		ToolboxEnabled: true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	for _, sb := range []*models.Sandbox{sb1, sb2} {
		if err := st.Upsert(context.Background(), sb); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	t.Run("list_all", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("code = %d", rr.Code)
		}
		var list []sandboxResponse
		if err := json.NewDecoder(rr.Body).Decode(&list); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("len = %d, expected 2", len(list))
		}
	})

	t.Run("list_filtered_and_paginated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated?name=beta&states=stopped&labels=%7B%22group%22%3A%22b%22%7D&page=1&limit=1", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("code = %d, body=%s", rr.Code, rr.Body.String())
		}
		var pageResp paginatedSandboxesResponse
		if err := json.NewDecoder(rr.Body).Decode(&pageResp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if pageResp.Total != 1 || len(pageResp.Items) != 1 || pageResp.Items[0].ID != "sb-2" {
			t.Fatalf("unexpected paginated result: %+v", pageResp)
		}
	})

	t.Run("pagination_errors", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated?page=-1", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}

		req2 := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated?limit=-1", nil)
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr2.Code)
		}
	})
}

func TestSandboxLifecycleHandlers(t *testing.T) {
	_, st, rt, handler := newHandlerExtraTestEnv(t)

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:             "sb-123",
		Name:           "test-sb",
		Status:         models.SandboxStatusStopped,
		ToolboxEnabled: true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	t.Run("get_sandbox", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/test-sb", nil)
		req.SetPathValue("idOrName", "test-sb")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		var resp sandboxResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.ID != "sb-123" {
			t.Fatalf("id = %q, want sb-123", resp.ID)
		}
	})

	t.Run("start_sandbox", func(t *testing.T) {
		rt.startState = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted}
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/test-sb/start", nil)
		req.SetPathValue("idOrName", "test-sb")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("stop_sandbox", func(t *testing.T) {
		rt.stopErr = nil
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/test-sb/stop", nil)
		req.SetPathValue("idOrName", "test-sb")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("resize_sandbox", func(t *testing.T) {
		rt.resizeErr = nil
		body := `{"cpu": 4, "memory": 8, "disk": 40}`
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/test-sb/resize", strings.NewReader(body))
		req.SetPathValue("idOrName", "test-sb")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
		}

		// bad json
		req2 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/test-sb/resize", strings.NewReader("bad-json"))
		req2.SetPathValue("idOrName", "test-sb")
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr2.Code)
		}
	})

	t.Run("replace_labels", func(t *testing.T) {
		body := `{"labels": {"env": "production"}}`
		req := httptest.NewRequest(http.MethodPut, "/daytona/sandbox/test-sb/labels", strings.NewReader(body))
		req.SetPathValue("idOrName", "test-sb")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
		}

		// bad json
		req2 := httptest.NewRequest(http.MethodPut, "/daytona/sandbox/test-sb/labels", strings.NewReader("bad-json"))
		req2.SetPathValue("idOrName", "test-sb")
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr2.Code)
		}
	})

	t.Run("preview_url", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/test-sb/ports/8080/preview-url", nil)
		req.SetPathValue("idOrName", "test-sb")
		req.SetPathValue("port", "8080")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
		}

		// bad port
		req2 := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/test-sb/ports/badport/preview-url", nil)
		req2.SetPathValue("idOrName", "test-sb")
		req2.SetPathValue("port", "badport")
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr2.Code)
		}
	})

	t.Run("destroy_sandbox", func(t *testing.T) {
		rt.destroyErr = nil
		req := httptest.NewRequest(http.MethodDelete, "/daytona/sandbox/test-sb", nil)
		req.SetPathValue("idOrName", "test-sb")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestSandboxIntervalHandlers(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:             "sb-1234",
		Name:           "interval-sb",
		Status:         models.SandboxStatusStopped,
		ToolboxEnabled: true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	t.Run("setAutoStopInterval", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/interval-sb/autostop/15.5", nil)
		req.SetPathValue("idOrName", "interval-sb")
		req.SetPathValue("interval", "15.5")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
		}

		// bad interval
		req2 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/interval-sb/autostop/bad", nil)
		req2.SetPathValue("idOrName", "interval-sb")
		req2.SetPathValue("interval", "bad")
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr2.Code)
		}

		// negative interval
		req3 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/interval-sb/autostop/-5", nil)
		req3.SetPathValue("idOrName", "interval-sb")
		req3.SetPathValue("interval", "-5")
		rr3 := httptest.NewRecorder()
		handler.ServeHTTP(rr3, req3)
		if rr3.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr3.Code)
		}
	})

	t.Run("setAutoDeleteInterval", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/interval-sb/autodelete/30", nil)
		req.SetPathValue("idOrName", "interval-sb")
		req.SetPathValue("interval", "30")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("setAutoArchiveInterval", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/interval-sb/autoarchive/60", nil)
		req.SetPathValue("idOrName", "interval-sb")
		req.SetPathValue("interval", "60")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
		}

		// bad interval
		req2 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/interval-sb/autoarchive/bad", nil)
		req2.SetPathValue("idOrName", "interval-sb")
		req2.SetPathValue("interval", "bad")
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr2.Code)
		}
	})
}

func TestCreateSnapshotAndOtherHandlers(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:             "sb-999",
		Name:           "snap-sb",
		Status:         models.SandboxStatusStopped,
		ToolboxEnabled: true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	t.Run("create_snapshot", func(t *testing.T) {
		body := `{"name": "my-snapshot"}`
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/snap-sb/snapshot", strings.NewReader(body))
		req.SetPathValue("idOrName", "snap-sb")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
		}

		// bad json
		req2 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/snap-sb/snapshot", strings.NewReader("bad"))
		req2.SetPathValue("idOrName", "snap-sb")
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr2.Code)
		}
	})

	t.Run("toolbox_proxy_url", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/sb-999/toolbox-proxy-url", nil)
		req.SetPathValue("id", "sb-999")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestHandlersErrorPaths(t *testing.T) {
	_, st, rt, handler := newHandlerExtraTestEnv(t)

	// Seed one sandbox
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:             "sb-err",
		Name:           "err-sb",
		Status:         models.SandboxStatusStarted,
		ToolboxEnabled: true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	t.Run("createSandbox_errors", func(t *testing.T) {
		// 1. Bad JSON body
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader("bad-json"))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}

		// 2. NetworkAllowList unsupported
		body := `{"networkAllowList": "github.com"}`
		req2 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(body))
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr2.Code)
		}

		// 3. GPU unsupported
		gpu := int32(1)
		reqReq := createSandboxRequest{Gpu: &gpu}
		bodyBytes, _ := json.Marshal(reqReq)
		req3 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(string(bodyBytes)))
		rr3 := httptest.NewRecorder()
		handler.ServeHTTP(rr3, req3)
		if rr3.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr3.Code)
		}

		// 4. Volume entry missing mountPath → 400 validation error.
		reqReq2 := createSandboxRequest{Volumes: []map[string]any{{"volumeId": "vol-1"}}}
		bodyBytes2, _ := json.Marshal(reqReq2)
		req4 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(string(bodyBytes2)))
		rr4 := httptest.NewRecorder()
		handler.ServeHTTP(rr4, req4)
		if rr4.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr4.Code)
		}
	})

	t.Run("listSnapshots_errors", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/daytona/snapshots?limit=-1", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("createSnapshotFromImage_errors", func(t *testing.T) {
		// Bad JSON
		req := httptest.NewRequest(http.MethodPost, "/daytona/snapshots", strings.NewReader("bad"))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}

		// Missing name
		req2 := httptest.NewRequest(http.MethodPost, "/daytona/snapshots", strings.NewReader(`{}`))
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr2.Code)
		}

		// Missing imageName and buildInfo
		req3 := httptest.NewRequest(http.MethodPost, "/daytona/snapshots", strings.NewReader(`{"name": "snap"}`))
		rr3 := httptest.NewRecorder()
		handler.ServeHTTP(rr3, req3)
		if rr3.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr3.Code)
		}

		// Both imageName and buildInfo
		req4 := httptest.NewRequest(http.MethodPost, "/daytona/snapshots", strings.NewReader(`{"name": "snap", "imageName": "img", "buildInfo": {"dockerfileContent": "FROM alpine"}}`))
		rr4 := httptest.NewRecorder()
		handler.ServeHTTP(rr4, req4)
		if rr4.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr4.Code)
		}
	})

	t.Run("get_destroy_missing_sandbox_errors", func(t *testing.T) {
		// resolveSandbox fails (sandbox missing)
		req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/non-existent", nil)
		req.SetPathValue("idOrName", "non-existent")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rr.Code)
		}

		req2 := httptest.NewRequest(http.MethodDelete, "/daytona/sandbox/non-existent", nil)
		req2.SetPathValue("idOrName", "non-existent")
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rr2.Code)
		}
	})

	t.Run("start_stop_resize_lifecycle_errors", func(t *testing.T) {
		// 1. Start error
		rt.startErr = errors.New("cannot start sandbox")
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/err-sb/start", nil)
		req.SetPathValue("idOrName", "err-sb")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}

		// 2. Stop error
		rt.stopErr = errors.New("cannot stop sandbox")
		req2 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/err-sb/stop", nil)
		req2.SetPathValue("idOrName", "err-sb")
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr2.Code)
		}

		// 3. Resize error
		rt.resizeErr = errors.New("cannot resize sandbox")
		req3 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/err-sb/resize", strings.NewReader(`{"cpu": 2}`))
		req3.SetPathValue("idOrName", "err-sb")
		rr3 := httptest.NewRecorder()
		handler.ServeHTTP(rr3, req3)
		if rr3.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr3.Code)
		}
	})

	t.Run("intervals_errors", func(t *testing.T) {
		// 1. setAutoStopInterval bad interval (must be float)
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/err-sb/autostop/abc", nil)
		req.SetPathValue("idOrName", "err-sb")
		req.SetPathValue("interval", "abc")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}

		// 2. setAutoStopInterval negative
		req2 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/err-sb/autostop/-1.5", nil)
		req2.SetPathValue("idOrName", "err-sb")
		req2.SetPathValue("interval", "-1.5")
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr2.Code)
		}

		// 3. setAutoArchiveInterval bad interval
		req3 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/err-sb/autoarchive/abc", nil)
		req3.SetPathValue("idOrName", "err-sb")
		req3.SetPathValue("interval", "abc")
		rr3 := httptest.NewRecorder()
		handler.ServeHTTP(rr3, req3)
		if rr3.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr3.Code)
		}
	})

	t.Run("toolboxProxyURL_errors", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/missing-sandbox/toolbox-proxy-url", nil)
		req.SetPathValue("id", "missing-sandbox")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rr.Code)
		}
	})

	t.Run("previewURL_errors", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/missing-sandbox/ports/80/preview-url", nil)
		req.SetPathValue("idOrName", "missing-sandbox")
		req.SetPathValue("port", "80")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rr.Code)
		}
	})

	t.Run("replaceLabels_errors", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/daytona/sandbox/err-sb/labels", strings.NewReader("bad"))
		req.SetPathValue("idOrName", "err-sb")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})
}

func TestDaytonaHelperFunctions(t *testing.T) {
	t.Run("singleLineFromImage", func(t *testing.T) {
		img, ok := singleLineFromImage("FROM alpine")
		if !ok || img != "alpine" {
			t.Fatalf("FROM alpine failed: ok=%v, img=%s", ok, img)
		}
		img2, ok2 := singleLineFromImage("# comment\nFROM alpine")
		if !ok2 || img2 != "alpine" {
			t.Fatalf("FROM alpine with comment failed: ok=%v, img=%s", ok2, img2)
		}
		_, ok3 := singleLineFromImage("FROM alpine\nRUN echo")
		if ok3 {
			t.Fatal("expected false for multiline")
		}
		_, ok4 := singleLineFromImage("FROM")
		if ok4 {
			t.Fatal("expected false for bare FROM")
		}
		_, ok5 := singleLineFromImage("FROM ")
		if ok5 {
			t.Fatal("expected false for empty FROM")
		}
		_, ok6 := singleLineFromImage("RUN echo")
		if ok6 {
			t.Fatal("expected false for no FROM")
		}
	})

	t.Run("mapSandboxState", func(t *testing.T) {
		states := []struct {
			status models.SandboxStatus
			want   string
		}{
			{models.SandboxStatusCreating, "creating"},
			{models.SandboxStatusStarted, "started"},
			{models.SandboxStatusStopped, "stopped"},
			{models.SandboxStatusDestroyed, "destroyed"},
			{models.SandboxStatusError, "error"},
			{models.SandboxStatus("nonexistent"), "unknown"},
		}
		for _, tc := range states {
			if got := mapSandboxState(tc.status); got != tc.want {
				t.Fatalf("mapSandboxState(%q) = %q, want %q", tc.status, got, tc.want)
			}
		}
	})

	t.Run("snapshotSortKey", func(t *testing.T) {
		item := snapshotResponse{
			Name:      "snap",
			State:     "active",
			CreatedAt: "2026-06-06",
		}
		if got := snapshotSortKey(item, "name"); got != "snap" {
			t.Fatalf("name: got %q", got)
		}
		if got := snapshotSortKey(item, "state"); got != "active" {
			t.Fatalf("state: got %q", got)
		}
		if got := snapshotSortKey(item, "createdAt"); got != "2026-06-06" {
			t.Fatalf("createdAt: got %q", got)
		}

		// default without LastUsedAt
		if got := snapshotSortKey(item, "other"); got != "2026-06-06" {
			t.Fatalf("default no lastUsedAt: got %q", got)
		}

		// default with LastUsedAt
		lastUsed := "2026-06-07"
		item.LastUsedAt = &lastUsed
		if got := snapshotSortKey(item, "other"); got != "2026-06-07" {
			t.Fatalf("default with lastUsedAt: got %q", got)
		}
	})

	t.Run("requestBaseURL", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/foo", nil)
		req.Header.Set("X-Forwarded-Proto", "https,http")
		req.Header.Set("X-Forwarded-Host", "forwarded.test")
		if got := requestBaseURL(req); got != "https://forwarded.test" {
			t.Fatalf("got %q, want https://forwarded.test", got)
		}

		req2 := httptest.NewRequest(http.MethodGet, "/foo", nil)
		req2.TLS = &tls.ConnectionState{}
		if got := requestBaseURL(req2); got != "https://example.com" {
			t.Fatalf("got %q, want https://example.com", got)
		}
	})

	t.Run("durationMinutesPtr", func(t *testing.T) {
		if got := durationMinutesPtr(0); got != nil {
			t.Fatal("expected nil")
		}
		val := time.Minute
		if got := durationMinutesPtr(val); got == nil || *got != 1.0 {
			t.Fatalf("expected 1.0, got %v", got)
		}
	})

	t.Run("timePtr", func(t *testing.T) {
		if got := timePtr(time.Time{}); got != nil {
			t.Fatal("expected nil")
		}
		now := time.Now()
		if got := timePtr(now); got == nil {
			t.Fatal("expected non-nil time string")
		}
	})

	t.Run("nonEmptyStringPtr", func(t *testing.T) {
		if got := nonEmptyStringPtr(nil); got != nil {
			t.Fatal("expected nil")
		}
		str := "   "
		if got := nonEmptyStringPtr(&str); got != nil {
			t.Fatal("expected nil")
		}
	})

	t.Run("firstFloat32Ptr", func(t *testing.T) {
		f1 := float32(1.5)
		f2 := float32(2.5)
		if got := firstFloat32Ptr(&f1, &f2); got == nil || *got != 1.5 {
			t.Fatalf("expected 1.5, got %v", got)
		}
		if got := firstFloat32Ptr(nil, &f2); got == nil || *got != 2.5 {
			t.Fatalf("expected 2.5, got %v", got)
		}
	})

	t.Run("parseFloat32Path_NaN_Inf", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.SetPathValue("nan", "NaN")
		_, err := parseFloat32Path(req, "nan")
		if err == nil {
			t.Fatal("expected error for NaN")
		}

		req2 := httptest.NewRequest(http.MethodPost, "/test", nil)
		req2.SetPathValue("inf", "Infinity")
		_, err2 := parseFloat32Path(req2, "inf")
		if err2 == nil {
			t.Fatal("expected error for Infinity")
		}
	})

	t.Run("parsePositiveFloatQuery_errors", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?val=", nil)
		got, err := parsePositiveFloatQuery(req, "val", 1.5)
		if err != nil || got != 1.5 {
			t.Fatalf("expected 1.5, got %f / %v", got, err)
		}

		req2 := httptest.NewRequest(http.MethodGet, "/test?val=abc", nil)
		_, err2 := parsePositiveFloatQuery(req2, "val", 1.5)
		if err2 == nil {
			t.Fatal("expected error for abc")
		}

		req3 := httptest.NewRequest(http.MethodGet, "/test?val=-1.5", nil)
		_, err3 := parsePositiveFloatQuery(req3, "val", 1.5)
		if err3 == nil {
			t.Fatal("expected error for negative float")
		}
	})
}

func TestHandlersDBAndTranslationErrors(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)

	// Seed a sandbox first
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:             "sb-db-err",
		Name:           "db-err-sb",
		Status:         models.SandboxStatusStarted,
		ToolboxEnabled: true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	t.Run("translate_sandbox_error", func(t *testing.T) {
		// Multi-line dockerfile without builder triggers translateCreateSandboxRequest error
		body := `{"name": "test-build-err", "buildInfo": {"dockerfileContent": "FROM alpine\nRUN echo"}}`
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(body))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("resolve_build_info_snapshot_error", func(t *testing.T) {
		// Multi-line dockerfile without builder inside createSnapshotFromImage
		body := `{"name": "test-snap-err", "buildInfo": {"dockerfileContent": "FROM alpine\nRUN echo"}}`
		req := httptest.NewRequest(http.MethodPost, "/daytona/snapshots", strings.NewReader(body))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("closed_db_operations", func(t *testing.T) {
		// Close the database to force SQL errors
		_ = st.Close()

		endpoints := []struct {
			method string
			path   string
			body   string
		}{
			{http.MethodGet, "/daytona/sandbox", ""},
			{http.MethodGet, "/daytona/sandbox/paginated", ""},
			{http.MethodGet, "/daytona/sandbox/db-err-sb", ""},
			{http.MethodDelete, "/daytona/sandbox/db-err-sb", ""},
			{http.MethodPost, "/daytona/sandbox/db-err-sb/start", ""},
			{http.MethodPost, "/daytona/sandbox/db-err-sb/stop", ""},
			{http.MethodPost, "/daytona/sandbox/db-err-sb/snapshot", `{"name":"snap"}`},
			{http.MethodPost, "/daytona/sandbox/db-err-sb/resize", `{"cpu":2}`},
			{http.MethodPut, "/daytona/sandbox/db-err-sb/labels", `{"labels":{"x":"y"}}`},
			{http.MethodPost, "/daytona/sandbox/db-err-sb/autoarchive/15", ""},
			{http.MethodGet, "/daytona/snapshots", ""},
			{http.MethodGet, "/daytona/snapshots/sha256:fake", ""},
			{http.MethodDelete, "/daytona/snapshots/sha256:fake", ""},
			{http.MethodPost, "/daytona/snapshots", `{"name":"snap","imageName":"alpine"}`},
		}

		for _, ep := range endpoints {
			req := httptest.NewRequest(ep.method, ep.path, strings.NewReader(ep.body))
			if ep.method == http.MethodGet || ep.method == http.MethodDelete {
				if strings.Contains(ep.path, "db-err-sb") {
					req.SetPathValue("idOrName", "db-err-sb")
				}
				if strings.Contains(ep.path, "sha256:fake") {
					req.SetPathValue("id", "sha256:fake")
				}
			} else {
				if strings.Contains(ep.path, "db-err-sb") {
					req.SetPathValue("idOrName", "db-err-sb")
				}
			}
			if strings.Contains(ep.path, "autoarchive") {
				req.SetPathValue("interval", "15")
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			// Closed DB should cause internal DB error, mapped to 400 Bad Request
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("%s %s: expected 400, got %d", ep.method, ep.path, rr.Code)
			}
		}
	})
}

type handlersExtraFakeImageBuilder struct {
	existsVal    bool
	existsErr    error
	buildErr     error
	removeErr    error
	refreshErr   error
	buildsCalled bool
}

func (f *handlersExtraFakeImageBuilder) RefreshTag(_ context.Context, ref string) error {
	return f.refreshErr
}

func (f *handlersExtraFakeImageBuilder) ImageExists(_ context.Context, ref string) (bool, error) {
	return f.existsVal, f.existsErr
}

func (f *handlersExtraFakeImageBuilder) BuildImage(_ context.Context, req docker.BuildImageRequest) error {
	f.buildsCalled = true
	return f.buildErr
}

func (f *handlersExtraFakeImageBuilder) RemoveImage(_ context.Context, ref string) error {
	return f.removeErr
}

func TestHandlersBuildAndImageEdgeCases(t *testing.T) {
	t.Run("default_image_env", func(t *testing.T) {
		t.Setenv("SB_DAYTONA_DEFAULT_IMAGE", "default-env-image")
		h := newHandlers(Deps{})
		req := createSandboxRequest{}
		img, built, err := h.createImage(context.Background(), req)
		if err != nil {
			t.Fatalf("createImage: %v", err)
		}
		if img != "default-env-image" || built != "" {
			t.Fatalf("expected default-env-image, got %q, built %q", img, built)
		}
	})

	t.Run("image_default_fallback", func(t *testing.T) {
		t.Setenv("SB_DAYTONA_DEFAULT_IMAGE", "")
		h := newHandlers(Deps{})
		req := createSandboxRequest{}
		img, built, err := h.createImage(context.Background(), req)
		if err != nil {
			t.Fatalf("createImage: %v", err)
		}
		if img != "ubuntu:22.04" || built != "" {
			t.Fatalf("expected ubuntu:22.04, got %q, built %q", img, built)
		}
	})

	t.Run("snapshot_empty_image_fallback", func(t *testing.T) {
		svc, st, _, _ := newHandlerExtraTestEnv(t)
		now := time.Now()
		snap := &models.SandboxSnapshot{
			Name:            "empty-img-snap",
			ImageID:         "sha256:some-image-id",
			SourceSandboxID: "sb-1",
			CreatedAt:       now,
		}
		if err := st.CreateSnapshot(context.Background(), snap); err != nil {
			t.Fatalf("CreateSnapshot: %v", err)
		}
		h := newHandlers(Deps{Service: svc})
		req := createSandboxRequest{
			Snapshot: stringPtr("empty-img-snap"),
		}
		img, built, err := h.createImage(context.Background(), req)
		if err != nil {
			t.Fatalf("createImage: %v", err)
		}
		if img != "sha256:some-image-id" || built != "" {
			t.Fatalf("expected sha256:some-image-id, got %q", img)
		}
	})

	t.Run("resolve_build_info_errors", func(t *testing.T) {
		h := newHandlers(Deps{})
		// dockerfile empty error
		_, _, err := h.resolveBuildInfo(context.Background(), &buildInfoRequest{})
		if err == nil {
			t.Fatal("expected error for empty dockerfile")
		}

		// buildInfo.contextHashes requires operator-side support error
		h2 := newHandlers(Deps{Build: BuildConfig{ContextEnabled: false}})
		_, _, err2 := h2.resolveBuildInfo(context.Background(), &buildInfoRequest{
			DockerfileContent: stringPtr("FROM alpine"),
			ContextHashes:     []string{"123"},
		})
		if err2 == nil || !strings.Contains(err2.Error(), "context upload support") {
			t.Fatalf("expected context upload support error, got %v", err2)
		}

		// buildInfo.contextHashes is enabled but no context resolver is configured
		h3 := newHandlers(Deps{Build: BuildConfig{ContextEnabled: true}})
		_, _, err3 := h3.resolveBuildInfo(context.Background(), &buildInfoRequest{
			DockerfileContent: stringPtr("FROM alpine"),
			ContextHashes:     []string{"123"},
		})
		if err3 == nil || !strings.Contains(err3.Error(), "no context resolver") {
			t.Fatalf("expected no context resolver error, got %v", err3)
		}
	})

	t.Run("resolve_build_info_builder_errors", func(t *testing.T) {
		// 1. ImageExists error
		b1 := &handlersExtraFakeImageBuilder{existsErr: errors.New("exists error")}
		h1 := newHandlers(Deps{Builder: b1})
		_, _, err := h1.resolveBuildInfo(context.Background(), &buildInfoRequest{DockerfileContent: stringPtr("FROM alpine\nRUN echo")})
		if err == nil || !errors.Is(err, errBuildOperational) {
			t.Fatalf("expected errBuildOperational, got %v", err)
		}

		// 2. RefreshTag error
		b2 := &handlersExtraFakeImageBuilder{existsVal: true, refreshErr: errors.New("refresh error")}
		h2 := newHandlers(Deps{Builder: b2, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
		_, _, err = h2.resolveBuildInfo(context.Background(), &buildInfoRequest{DockerfileContent: stringPtr("FROM alpine\nRUN echo")})
		if err != nil {
			t.Fatalf("expected success on refresh failure, got %v", err)
		}

		// 3. BuildImage error
		b3 := &handlersExtraFakeImageBuilder{buildErr: errors.New("build error")}
		h3 := newHandlers(Deps{Builder: b3})
		_, _, err = h3.resolveBuildInfo(context.Background(), &buildInfoRequest{DockerfileContent: stringPtr("FROM alpine\nRUN echo")})
		if err == nil || !errors.Is(err, errBuildOperational) {
			t.Fatalf("expected errBuildOperational, got %v", err)
		}

		// 4. BuildImage timeout error
		b4 := &handlersExtraFakeImageBuilder{buildErr: context.DeadlineExceeded}
		h4 := newHandlers(Deps{Builder: b4})
		_, _, err = h4.resolveBuildInfo(context.Background(), &buildInfoRequest{DockerfileContent: stringPtr("FROM alpine\nRUN echo")})
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected DeadlineExceeded, got %v", err)
		}

		// 5. buildContextWithTimeout timeout > 0
		b5 := &handlersExtraFakeImageBuilder{}
		h5 := newHandlers(Deps{Builder: b5, Build: BuildConfig{Timeout: 10 * time.Second}})
		_, _, err = h5.resolveBuildInfo(context.Background(), &buildInfoRequest{DockerfileContent: stringPtr("FROM alpine\nRUN echo")})
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
	})

	t.Run("durationFromMinutes_negative", func(t *testing.T) {
		got := durationFromMinutes(-5)
		if got != 0 {
			t.Fatalf("expected 0, got %v", got)
		}
	})
}

func TestCreateSandbox_HTTP_Errors(t *testing.T) {
	t.Run("gateway_timeout", func(t *testing.T) {
		svc, _, _, _ := newHandlerExtraTestEnv(t)
		b := &handlersExtraFakeImageBuilder{buildErr: context.DeadlineExceeded}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		mux := http.NewServeMux()
		RegisterRoutes(mux, Deps{
			Service: svc,
			Logger:  logger,
			Auth:    func(next http.Handler) http.Handler { return next },
			Builder: b,
		})

		body := `{"name": "sb-timeout", "buildInfo": {"dockerfileContent": "FROM alpine\nRUN echo"}}`
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusGatewayTimeout {
			t.Fatalf("expected 504, got %d", rr.Code)
		}
	})

	t.Run("bad_gateway", func(t *testing.T) {
		svc, _, _, _ := newHandlerExtraTestEnv(t)
		b := &handlersExtraFakeImageBuilder{buildErr: errors.New("docker crash")}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		mux := http.NewServeMux()
		RegisterRoutes(mux, Deps{
			Service: svc,
			Logger:  logger,
			Auth:    func(next http.Handler) http.Handler { return next },
			Builder: b,
		})

		body := `{"name": "sb-bad-gateway", "buildInfo": {"dockerfileContent": "FROM alpine\nRUN echo"}}`
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadGateway {
			t.Fatalf("expected 502, got %d", rr.Code)
		}
	})

	t.Run("volumes_disabled", func(t *testing.T) {
		// Platform volumes are disabled in the test env, so a create that
		// attaches a (well-formed) volume is rejected with 412 — replacing the
		// old blanket 405.
		_, _, _, handler := newHandlerExtraTestEnv(t)
		body := `{"name": "sb-volumes", "volumes": [{"volumeId": "vol-1", "mountPath": "/data"}]}`
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(body))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusPreconditionFailed {
			t.Fatalf("expected 412, got %d", rr.Code)
		}
	})

	t.Run("image_rollback_failure", func(t *testing.T) {
		svc, _, rt, _ := newHandlerExtraTestEnv(t)
		b := &handlersExtraFakeImageBuilder{removeErr: errors.New("remove failed")}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		mux := http.NewServeMux()
		RegisterRoutes(mux, Deps{
			Service: svc,
			Logger:  logger,
			Auth:    func(next http.Handler) http.Handler { return next },
			Builder: b,
		})

		rt.createErr = errors.New("runtime create failed")

		body := `{"name": "sb-rollback", "buildInfo": {"dockerfileContent": "FROM alpine\nRUN echo"}}`
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("metadata_persistence_failure_cleanup", func(t *testing.T) {
		svc, st, rt, _ := newHandlerExtraTestEnv(t)
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		mux := http.NewServeMux()
		RegisterRoutes(mux, Deps{
			Service: svc,
			Logger:  logger,
			Auth:    func(next http.Handler) http.Handler { return next },
		})

		rt.createState = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted}
		rt.createCallback = func() {
			_ = st.Close()
		}
		rt.destroyErr = errors.New("destroy failed")

		body := `{"name": "sb-persist-fail-a", "buildInfo": {"dockerfileContent": "FROM alpine"}}`
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("metadata_persistence_failure_cleanup_success", func(t *testing.T) {
		svc, st, rt, _ := newHandlerExtraTestEnv(t)
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		mux := http.NewServeMux()
		RegisterRoutes(mux, Deps{
			Service: svc,
			Logger:  logger,
			Auth:    func(next http.Handler) http.Handler { return next },
		})

		rt.createState = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted}
		rt.createCallback = func() {
			_ = st.Close()
		}
		rt.destroyErr = nil

		body := `{"name": "sb-persist-fail-b", "buildInfo": {"dockerfileContent": "FROM alpine"}}`
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})
}

func TestCreateSnapshotFromImage_HTTP_Errors(t *testing.T) {
	t.Run("gateway_timeout", func(t *testing.T) {
		svc, _, _, _ := newHandlerExtraTestEnv(t)
		b := &handlersExtraFakeImageBuilder{buildErr: context.DeadlineExceeded}
		mux := http.NewServeMux()
		RegisterRoutes(mux, Deps{
			Service: svc,
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
			Auth:    func(next http.Handler) http.Handler { return next },
			Builder: b,
		})

		body := `{"name": "snap-timeout", "buildInfo": {"dockerfileContent": "FROM alpine\nRUN echo"}}`
		req := httptest.NewRequest(http.MethodPost, "/daytona/snapshots", strings.NewReader(body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusGatewayTimeout {
			t.Fatalf("expected 504, got %d", rr.Code)
		}
	})

	t.Run("bad_gateway", func(t *testing.T) {
		svc, _, _, _ := newHandlerExtraTestEnv(t)
		b := &handlersExtraFakeImageBuilder{buildErr: errors.New("build error")}
		mux := http.NewServeMux()
		RegisterRoutes(mux, Deps{
			Service: svc,
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
			Auth:    func(next http.Handler) http.Handler { return next },
			Builder: b,
		})

		body := `{"name": "snap-bad-gateway", "buildInfo": {"dockerfileContent": "FROM alpine\nRUN echo"}}`
		req := httptest.NewRequest(http.MethodPost, "/daytona/snapshots", strings.NewReader(body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadGateway {
			t.Fatalf("expected 502, got %d", rr.Code)
		}
	})

	t.Run("rollback_failure", func(t *testing.T) {
		svc, st, _, _ := newHandlerExtraTestEnv(t)
		b := &handlersExtraFakeImageBuilder{removeErr: errors.New("remove error")}
		mux := http.NewServeMux()
		RegisterRoutes(mux, Deps{
			Service: svc,
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
			Auth:    func(next http.Handler) http.Handler { return next },
			Builder: b,
		})

		_ = st.Close()

		body := `{"name": "snap-rollback-fail", "buildInfo": {"dockerfileContent": "FROM alpine\nRUN echo"}}`
		req := httptest.NewRequest(http.MethodPost, "/daytona/snapshots", strings.NewReader(body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})
}

func TestFiltersAndSorting(t *testing.T) {
	h := newHandlers(Deps{})
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	t.Run("filteredSandboxes", func(t *testing.T) {
		sb := &models.Sandbox{
			ID:     "sb-match",
			Name:   "matching-sb",
			Status: models.SandboxStatusStarted,
		}
		sandboxes := []*models.Sandbox{nil, sb}
		metadata := map[string]compatBlob{
			"sb-match": {Snapshot: "matching-sb-snap"},
		}

		// 1. Filter by ID mismatch
		f1 := listFilters{ID: "mismatch"}
		res1 := h.filteredSandboxes(req, sandboxes, metadata, f1)
		if len(res1) != 0 {
			t.Fatalf("expected 0, got %d", len(res1))
		}

		// 2. Filter by labels mismatch
		f2 := listFilters{Labels: map[string]string{"env": "prod"}}
		res2 := h.filteredSandboxes(req, sandboxes, metadata, f2)
		if len(res2) != 0 {
			t.Fatalf("expected 0, got %d", len(res2))
		}

		// 3. Filter by state mismatch
		f3 := listFilters{States: map[string]struct{}{"stopped": {}}}
		res3 := h.filteredSandboxes(req, sandboxes, metadata, f3)
		if len(res3) != 0 {
			t.Fatalf("expected 0, got %d", len(res3))
		}

		// 4. Match
		f4 := listFilters{ID: "match"}
		res4 := h.filteredSandboxes(req, sandboxes, metadata, f4)
		if len(res4) != 1 || res4[0].ID != "sb-match" {
			t.Fatalf("expected 1 matching sandbox, got %+v", res4)
		}
	})

	t.Run("filteredSnapshots", func(t *testing.T) {
		snap1 := &models.SandboxSnapshot{
			Name:      "snap-a",
			CreatedAt: time.Now(),
		}
		snap2 := &models.SandboxSnapshot{
			Name:      "snap-b",
			CreatedAt: time.Now(),
		}
		snapshots := []*models.SandboxSnapshot{nil, snap1, snap2}

		// 1. Filter by name mismatch
		f1 := snapshotListFilters{Name: "mismatch"}
		res1 := h.filteredSnapshots(req, snapshots, f1)
		if len(res1) != 0 {
			t.Fatalf("expected 0, got %d", len(res1))
		}

		// 2. Equal sort keys sorting
		f2 := snapshotListFilters{Sort: "state", Order: "asc"}
		res2 := h.filteredSnapshots(req, []*models.SandboxSnapshot{snap2, snap1}, f2)
		if len(res2) != 2 || res2[0].Name != "snap-a" {
			t.Fatalf("expected snap-a first in asc order, got %+v", res2)
		}

		f3 := snapshotListFilters{Sort: "state", Order: "desc"}
		res3 := h.filteredSnapshots(req, []*models.SandboxSnapshot{snap1, snap2}, f3)
		if len(res3) != 2 || res3[0].Name != "snap-b" {
			t.Fatalf("expected snap-b first in desc order, got %+v", res3)
		}
	})
}

func TestToSandboxResponse_Extra(t *testing.T) {
	h := newHandlers(Deps{})
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	sb := &models.Sandbox{
		ID:        "sb-extra",
		LastError: "some error occurred",
		GPUs:      &models.GPURequest{Count: 2},
	}
	resp := h.toSandboxResponse(req, sb, sandboxMeta{})
	if resp.ErrorReason == nil || *resp.ErrorReason != "some error occurred" {
		t.Fatalf("expected ErrorReason 'some error occurred', got %v", resp.ErrorReason)
	}
	if resp.GPU != 2 {
		t.Fatalf("expected GPU count 2, got %f", resp.GPU)
	}
}

func TestParseSnapshotListFilters_Errors(t *testing.T) {
	// 1. limit > 200
	req1 := httptest.NewRequest(http.MethodGet, "/snapshots?limit=250", nil)
	_, _, _, err1 := parseSnapshotListFilters(req1)
	if err1 == nil || !strings.Contains(err1.Error(), "limit must be less than") {
		t.Fatalf("expected limit error, got %v", err1)
	}

	// 2. invalid sort
	req2 := httptest.NewRequest(http.MethodGet, "/snapshots?sort=invalid", nil)
	_, _, _, err2 := parseSnapshotListFilters(req2)
	if err2 == nil || !strings.Contains(err2.Error(), "sort must be one of") {
		t.Fatalf("expected sort error, got %v", err2)
	}

	// 3. invalid order
	req3 := httptest.NewRequest(http.MethodGet, "/snapshots?order=invalid", nil)
	_, _, _, err3 := parseSnapshotListFilters(req3)
	if err3 == nil || !strings.Contains(err3.Error(), "order must be one of") {
		t.Fatalf("expected order error, got %v", err3)
	}

	// 4. invalid page
	req4 := httptest.NewRequest(http.MethodGet, "/snapshots?page=-1", nil)
	_, _, _, err4 := parseSnapshotListFilters(req4)
	if err4 == nil {
		t.Fatal("expected page error")
	}
}

func TestDirectHelperMethodErrors(t *testing.T) {
	svc, st, _, _ := newHandlerExtraTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	sb := &models.Sandbox{ID: "sb-direct"}

	// 1. loadSandboxMeta database error (closed connection)
	_ = st.Close()
	_, err := h.loadSandboxMeta(context.Background(), sb)
	if err == nil {
		t.Fatal("expected error from loadSandboxMeta with closed database")
	}

	// 2. persistSandboxMeta database error (closed connection)
	err = h.persistSandboxMeta(context.Background(), "sb-direct", sandboxMeta{})
	if err == nil {
		t.Fatal("expected error from persistSandboxMeta with closed database")
	}

	// 3. listSandboxMeta database error (closed connection)
	_, err = h.listSandboxMeta(context.Background())
	if err == nil {
		t.Fatal("expected error from listSandboxMeta with closed database")
	}
}

func TestForwardedListAppliesExactPlacementIDsBeforeSerialization(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox?ids=sb-keep", nil)
	req.Header.Set("X-Cluster-Forwarded", "1")
	filters, err := parseListFilters(req)
	if err != nil {
		t.Fatalf("parseListFilters() error = %v", err)
	}
	now := time.Now().UTC()
	sandboxes := []*models.Sandbox{
		{ID: "sb-keep", Name: "keep", Status: models.SandboxStatusStarted, CreatedAt: now},
		{ID: "sb-drop", Name: "drop", Status: models.SandboxStatusStarted, CreatedAt: now.Add(time.Second)},
	}
	items := newHandlers(Deps{}).filteredSandboxes(req, sandboxes, nil, filters)
	if len(items) != 1 || items[0].ID != "sb-keep" {
		t.Fatalf("filtered items = %+v, want only sb-keep", items)
	}

	public := httptest.NewRequest(http.MethodGet, "/daytona/sandbox?ids=sb-keep", nil)
	publicFilters, err := parseListFilters(public)
	if err != nil {
		t.Fatalf("public parseListFilters() error = %v", err)
	}
	items = newHandlers(Deps{}).filteredSandboxes(public, sandboxes, nil, publicFilters)
	if len(items) != 2 {
		t.Fatalf("public ids query unexpectedly changed API behavior: %+v", items)
	}
}

func TestHTTPListHandlers_ExtraErrorsAndPagination(t *testing.T) {
	svc, st, _, handler := newHandlerExtraTestEnv(t)

	// Seed a dummy sandbox
	sb := &models.Sandbox{
		ID:        "sb-bad-json",
		Name:      "bad-json-sb",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Seed invalid JSON inside compat state
	err := svc.UpsertCompatState(context.Background(), "sb-bad-json", models.FacadeDaytona, "{invalid-json")
	if err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}

	// 1. listSandboxes labels parse error
	req1 := httptest.NewRequest(http.MethodGet, "/daytona/sandbox?labels=invalid", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr1.Code)
	}

	// 2. listSandboxes paginated labels parse error
	req2 := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated?labels=invalid", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr2.Code)
	}

	// 3. listSandboxes metadata load (JSON unmarshal) error
	req3 := httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil)
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr3.Code)
	}

	// 4. listSandboxesPaginated metadata load (JSON unmarshal) error
	req4 := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated", nil)
	rr4 := httptest.NewRecorder()
	handler.ServeHTTP(rr4, req4)
	if rr4.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr4.Code)
	}

	// 5. getSandbox metadata load (JSON unmarshal) error
	req5 := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/bad-json-sb", nil)
	req5.SetPathValue("idOrName", "bad-json-sb")
	rr5 := httptest.NewRecorder()
	handler.ServeHTTP(rr5, req5)
	if rr5.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr5.Code)
	}

	// 6. listSnapshots pagination start > total
	req6 := httptest.NewRequest(http.MethodGet, "/daytona/snapshots?page=10&limit=5", nil)
	rr6 := httptest.NewRecorder()
	handler.ServeHTTP(rr6, req6)
	if rr6.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr6.Code)
	}

	// 7. clusterPlacementRequest non-zero snapshot image distribution mode
	snap := &models.SandboxSnapshot{
		Name:      "snap-dist",
		Image:     "alpine",
		CreatedAt: time.Now(),
	}
	snap.ApplyImageDistribution(models.ImageDistributionMetadata{
		Mode:        models.ImageDistributionLocalOnly,
		Digest:      "sha256:abc",
		RegistryRef: "ref",
	})
	// Re-open DB for this step (new env)
	_, st2, rt2, handler2 := newHandlerExtraTestEnv(t)
	rt2.createState = &models.SandboxRuntimeState{
		SandboxID: "sb-dist",
		Status:    models.SandboxStatusStarted,
	}
	if err := st2.CreateSnapshot(context.Background(), snap); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	body := `{"name": "sb-dist", "snapshot": "snap-dist"}`
	req7 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(body))
	rr7 := httptest.NewRecorder()
	handler2.ServeHTTP(rr7, req7)
	if rr7.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (body: %s)", rr7.Code, rr7.Body.String())
	}
}

package v1

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeTemplateBuilderV1 is the v1 handler-test stub for
// service.TemplateBuilder. Touches the requested OutPath so the
// success path's os.Stat round-trip produces a non-zero size.
type fakeTemplateBuilderV1 struct {
	mu    sync.Mutex
	calls int
	done  chan struct{}
}

func (f *fakeTemplateBuilderV1) Build(_ context.Context, req service.TemplateBuildRequest) (*service.TemplateBuildResult, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	defer func() {
		if f.done != nil {
			f.done <- struct{}{}
		}
	}()
	if err := os.WriteFile(req.OutPath, []byte("FAKE"), 0o600); err != nil {
		return nil, err
	}
	return &service.TemplateBuildResult{
		RootfsPath: req.OutPath,
		StagingDir: filepath.Join(filepath.Dir(req.OutPath), "staging"),
		SizeBytes:  4,
	}, nil
}

type templateV1Env struct {
	svc     *service.Service
	store   *store.Store
	builder *fakeTemplateBuilderV1
	handler http.Handler
}

func newTemplateV1TestEnv(t *testing.T) *templateV1Env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	templatesDir := filepath.Join(dir, "templates")
	if err := os.MkdirAll(templatesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Config{
		EnableFirecracker:       true,
		FirecrackerTemplatesDir: templatesDir,
	}
	svc := service.New(cfg, logger, st, &noopRuntime{}, nil, nil, nil, nil, nil)
	builder := &fakeTemplateBuilderV1{done: make(chan struct{}, 1)}
	svc.SetTemplateBuilder(builder)

	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth:    func(h http.Handler) http.Handler { return h },
	})
	return &templateV1Env{svc: svc, store: st, builder: builder, handler: mux}
}

// TestV1CreateTemplate_Returns202 is the canonical happy path: POST
// returns 202 + a PENDING row, and the background goroutine fires the
// builder. This is the API-shape contract Phase 2 promises clients.
func TestV1CreateTemplate_Returns202(t *testing.T) {
	env := newTemplateV1TestEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/templates",
		strings.NewReader(`{"id":"tpl-api","image":"docker://alpine:3.19"}`))
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", rr.Code, rr.Body.String())
	}
	var resp models.Template
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ID != "tpl-api" || resp.Status != models.TemplateStatusPending {
		t.Fatalf("resp = %+v, want id=tpl-api status=pending", resp)
	}

	select {
	case <-env.builder.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("builder.Build did not run")
	}
}

// TestV1GetTemplate_MissingReturns404 confirms the well-known
// not-found mapping carries the right HTTP status — store.ErrNotFound
// already routes through WriteStoreAwareError, but a regression in
// that wiring would silently turn 404s into 400s.
func TestV1GetTemplate_MissingReturns404(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/templates/tpl-nope", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

// TestV1ListTemplates_ReturnsRows confirms LIST is wired and returns
// JSON in the obvious shape.
func TestV1ListTemplates_ReturnsRows(t *testing.T) {
	env := newTemplateV1TestEnv(t)

	if _, err := env.svc.CreateTemplate(context.Background(), models.CreateTemplateRequest{
		ID: "tpl-list", Image: "docker://alpine:3.19",
	}); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var rows []models.Template
	if err := json.NewDecoder(rr.Body).Decode(&rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "tpl-list" {
		t.Fatalf("rows = %+v, want exactly [tpl-list]", rows)
	}
}

// TestV1DeleteTemplate_InUseReturns409 pins the API contract for the
// ErrTemplateInUse sentinel (added in apihttp.WriteStoreAwareError):
// an active sandbox holding template_id forces the operator to
// destroy the sandbox first instead of yanking rootfs out from under
// a live Firecracker guest. We seed the store directly to avoid
// pulling in the runtime.
func TestV1DeleteTemplate_InUseReturns409(t *testing.T) {
	env := newTemplateV1TestEnv(t)

	tpl := &models.Template{
		ID: "tpl-busy-api", Image: "docker://alpine:3.19",
		Status: models.TemplateStatusReady, RootfsPath: "/var/lib/aerolvm/templates/tpl-busy-api/rootfs.ext4",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := env.store.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	sb := &models.Sandbox{
		ID: "sb-busy-api", Image: "docker://alpine:3.19",
		Status: models.SandboxStatusStarted, ContainerID: "ctr", ContainerIP: "10.0.0.10",
		CPU: 1, MemoryMB: 1024, DiskGB: 10, OSUser: "root",
		Env: map[string]string{}, ToolboxEnabled: true,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), LastActiveAt: time.Now().UTC(),
		Runtime: models.RuntimeFirecracker, TemplateID: tpl.ID,
	}
	if err := env.store.Create(context.Background(), sb); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/v1/templates/"+tpl.ID, nil)
	delRR := httptest.NewRecorder()
	env.handler.ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusConflict {
		t.Fatalf("delete status = %d, want 409; body=%s", delRR.Code, delRR.Body.String())
	}
}

package daytona

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

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestDestroySandboxSuccessCoverage95(t *testing.T) {
	svc, st, rt, handler := newHandlerExtraTestEnv(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-destroy", Name: "destroy-me", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-destroy", ContainerIP: "10.0.0.9",
		ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	stateJSON, err := sandboxMetaToState(sandboxMeta{Snapshot: stringPtr("snap-1"), Target: "dev"})
	if err != nil {
		t.Fatalf("sandboxMetaToState: %v", err)
	}
	if err := st.UpsertCompatState(ctx, sb.ID, models.FacadeDaytona, stateJSON); err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}
	rt.inspectState = &models.SandboxRuntimeState{SandboxID: sb.ID, Status: models.SandboxStatusStarted}

	req := httptest.NewRequest(http.MethodDelete, "/daytona/sandbox/destroy-me", nil)
	req.SetPathValue("idOrName", "destroy-me")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := svc.GetSandbox(ctx, sb.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("sandbox still exists: %v", err)
	}
}

func TestStartStopSandboxSuccessCoverage95(t *testing.T) {
	_, st, rt, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-toggle", Name: "toggle", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-toggle", ContainerIP: "10.0.0.8",
		ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	rt.inspectState = &models.SandboxRuntimeState{SandboxID: sb.ID, Status: models.SandboxStatusStarted}
	rt.startState = &models.SandboxRuntimeState{SandboxID: sb.ID, Status: models.SandboxStatusStarted}

	stopRR := httptest.NewRecorder()
	stopReq := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/toggle/stop", nil)
	stopReq.SetPathValue("idOrName", "toggle")
	handler.ServeHTTP(stopRR, stopReq)
	if stopRR.Code != http.StatusOK {
		t.Fatalf("stop status = %d", stopRR.Code)
	}

	startRR := httptest.NewRecorder()
	startReq := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/toggle/start", nil)
	startReq.SetPathValue("idOrName", "toggle")
	handler.ServeHTTP(startRR, startReq)
	if startRR.Code != http.StatusOK {
		t.Fatalf("start status = %d", startRR.Code)
	}
}

func TestUpdateIdleLifecycleClearIntervalsCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-idle", Name: "idle-sb", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-idle", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
		Lifecycle: models.Lifecycle{
			StopIfIdleFor:    5 * time.Minute,
			DestroyIfIdleFor: 10 * time.Minute,
		},
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/idle-sb/autostop/0", nil)
	req.SetPathValue("idOrName", "idle-sb")
	req.SetPathValue("interval", "0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("autostop clear status = %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/idle-sb/autodelete/0", nil)
	req2.SetPathValue("idOrName", "idle-sb")
	req2.SetPathValue("interval", "0")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("autodelete clear status = %d", rr2.Code)
	}
}

func TestSetAutoArchiveIntervalSuccessCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-archive", Name: "archive-sb", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-archive", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/archive-sb/autoarchive/30", nil)
	req.SetPathValue("idOrName", "archive-sb")
	req.SetPathValue("interval", "30")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSandboxMetaFromStateRoundTripCoverage95(t *testing.T) {
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-meta", Name: "", OSUser: "dev",
		CreatedAt: now, UpdatedAt: now,
		Lifecycle: models.Lifecycle{StopIfIdleFor: 2 * time.Minute, DestroyIfIdleFor: 3 * time.Minute},
	}
	meta := sandboxMetaFromNative(sb, compatBlob{
		Snapshot: "snap", Target: "target", NetworkAllowList: "10.0.0.0/8", AutoArchiveInterval: 15,
	})
	stateJSON, err := sandboxMetaToState(meta)
	if err != nil {
		t.Fatalf("sandboxMetaToState: %v", err)
	}
	got, err := sandboxMetaFromState(&models.SandboxCompatState{StateJSON: stateJSON}, sb)
	if err != nil || got.Target != "target" {
		t.Fatalf("got = %+v err=%v", got, err)
	}
	_, err = sandboxMetaFromState(&models.SandboxCompatState{StateJSON: "{bad"}, sb)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
}

func TestCreateSandboxNameConflictCoverage95(t *testing.T) {
	_, st, rt, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	if err := st.Upsert(context.Background(), &models.Sandbox{
		ID: "sb-existing", Name: "taken-name", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	rt.createState = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted}
	rt.createErr = store.ErrSandboxNameConflict

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/daytona/sandbox",
		strings.NewReader(`{"name":"taken-name","buildInfo":{"dockerfileContent":"FROM alpine"}}`)))
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateSandboxCreateTimeoutCoverage95(t *testing.T) {
	_, _, rt, handler := newHandlerExtraTestEnv(t)
	rt.createState = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted}
	rt.createErr = context.DeadlineExceeded

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/daytona/sandbox",
		strings.NewReader(`{"name":"timeout-sb","buildInfo":{"dockerfileContent":"FROM alpine"}}`)))
	if rr.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPreviewURLSuccessCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-preview", Name: "preview-sb", Status: models.SandboxStatusStarted,
		PublicURL: "https://preview.example.com", ToolboxEnabled: true,
		ContainerID: "ctr-preview", CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/preview-sb/ports/8080/preview-url", nil)
	req.SetPathValue("idOrName", "preview-sb")
	req.SetPathValue("port", "8080")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("preview status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestTranslateCreateSandboxRequestLifecycleCoverage95(t *testing.T) {
	h := newHandlers(Deps{})
	autoStop := int32(5)
	autoDelete := int32(10)
	req, built, err := h.translateCreateSandboxRequest(context.Background(), createSandboxRequest{
		BuildInfo:          &buildInfoRequest{DockerfileContent: stringPtr("FROM alpine")},
		AutoStopInterval:   &autoStop,
		AutoDeleteInterval: &autoDelete,
	})
	if err != nil || built != "" {
		t.Fatalf("err=%v built=%q", err, built)
	}
	if req.Lifecycle == nil || req.Lifecycle.StopIfIdleFor == 0 {
		t.Fatalf("lifecycle = %+v", req.Lifecycle)
	}
}

func TestListSandboxMetaCoverage95(t *testing.T) {
	svc, st, _, _ := newHandlerExtraTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx := context.Background()
	now := time.Now().UTC()
	sb := &models.Sandbox{ID: "sb-list-meta", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now}
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := st.UpsertCompatState(ctx, sb.ID, models.FacadeDaytona, `{"target":"dev"}`); err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}
	items, err := h.listSandboxMeta(ctx)
	if err != nil || items[sb.ID].Target != "dev" {
		t.Fatalf("items = %+v err=%v", items, err)
	}
}

func TestResolveSandboxByNameCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-by-name", Name: "lookup-name", Status: models.SandboxStatusStarted,
		ToolboxEnabled: true, ContainerID: "ctr", CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/lookup-name", nil)
	req.SetPathValue("idOrName", "lookup-name")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPersistSandboxMetaCoverage95(t *testing.T) {
	svc, st, _, _ := newHandlerExtraTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.Upsert(ctx, &models.Sandbox{
		ID: "sb-persist", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	meta := sandboxMeta{
		Snapshot: stringPtr("snap"), Target: "dev", NetworkAllowList: stringPtr("0.0.0.0/0"),
		AutoArchiveInterval: float32Ptr(10),
	}
	if err := h.persistSandboxMeta(ctx, "sb-persist", meta); err != nil {
		t.Fatalf("persistSandboxMeta: %v", err)
	}
}

func TestDaytonaPaginatedListEmptyCoverage95(t *testing.T) {
	_, _, _, handler := newHandlerExtraTestEnv(t)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated?page=1&limit=10", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var page paginatedSandboxesResponse
	if err := json.NewDecoder(rr.Body).Decode(&page); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestCreateImageFromSnapshotNameCoverage95(t *testing.T) {
	svc, st, _, _ := newHandlerExtraTestEnv(t)
	ctx := context.Background()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name: "snap-img:default", Image: "resolved:img", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	h := newHandlers(Deps{Service: svc})
	img, built, err := h.createImage(ctx, createSandboxRequest{Snapshot: stringPtr("snap-img:default")})
	if err != nil || built != "" || img != "resolved:img" {
		t.Fatalf("createImage = (%q, %q, %v)", img, built, err)
	}
}

func TestCreateImageDefaultUbuntuCoverage95(t *testing.T) {
	h := newHandlers(Deps{})
	img, built, err := h.createImage(context.Background(), createSandboxRequest{})
	if err != nil || built != "" || img != "ubuntu:22.04" {
		t.Fatalf("createImage = (%q, %q, %v)", img, built, err)
	}
}

func TestDestroySandboxLoadMetaErrorCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-bad-meta", Name: "bad-meta", Status: models.SandboxStatusStarted,
		ContainerID: "ctr", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := st.UpsertCompatState(context.Background(), sb.ID, models.FacadeDaytona, "{bad"); err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/daytona/sandbox/bad-meta", nil)
	req.SetPathValue("idOrName", "bad-meta")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("expected load meta failure")
	}
}

func TestCreateSandboxImageRollbackOnCreateFailureCoverage95(t *testing.T) {
	svc, _, rt, _ := newHandlerExtraTestEnv(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	b := &rollbackTrackingBuilder{}
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc, Logger: logger, Builder: b,
		Auth: func(next http.Handler) http.Handler { return next },
	})
	rt.createState = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted}
	rt.createErr = errors.New("create failed")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/daytona/sandbox",
		strings.NewReader(`{"name":"rollback-img","buildInfo":{"dockerfileContent":"FROM alpine\nRUN echo hi"}}`)))
	if rr.Code == http.StatusCreated {
		t.Fatal("expected create failure")
	}
	if len(b.removed) == 0 {
		t.Fatal("expected built image rollback")
	}
}

type rollbackTrackingBuilder struct {
	handlersExtraFakeImageBuilder
	removed []string
}

func (b *rollbackTrackingBuilder) RemoveImage(_ context.Context, ref string) error {
	b.removed = append(b.removed, ref)
	return nil
}

func TestResizeSandboxSuccessCoverage95(t *testing.T) {
	_, st, rt, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-resize", Name: "resize-me", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-resize", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	rt.inspectState = &models.SandboxRuntimeState{SandboxID: sb.ID, Status: models.SandboxStatusStarted}

	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/resize-me/resize", strings.NewReader(`{"cpu":2,"memory":2,"disk":2}`))
	req.SetPathValue("idOrName", "resize-me")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("resize status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSetAutoArchiveIntervalClearCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-arch-clear", Name: "arch-clear", Status: models.SandboxStatusStarted,
		ContainerID: "ctr", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/arch-clear/autoarchive/0", nil)
	req.SetPathValue("idOrName", "arch-clear")
	req.SetPathValue("interval", "0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateSnapshotOnSandboxSuccessCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-snap", Name: "snap-me", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-snap", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/snap-me/snapshot", strings.NewReader(`{"name":"my-snap"}`))
	req.SetPathValue("idOrName", "snap-me")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("snapshot status = %d body=%s", rr.Code, rr.Body.String())
	}
}

package daytona

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

func TestTranslateCreateSandboxRequestAcceptsDaytonaGoImageFixture(t *testing.T) {
	fixture := []byte(`{
		"public": false,
		"buildInfo": {
			"dockerfileContent": "FROM alpine"
		}
	}`)

	var req createSandboxRequest
	if err := json.Unmarshal(fixture, &req); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	h := newHandlers(Deps{})
	translated, err := h.translateCreateSandboxRequest(req)
	if err != nil {
		t.Fatalf("translateCreateSandboxRequest() error = %v", err)
	}
	if translated.Image != "alpine" {
		t.Fatalf("translated.Image = %q, want %q", translated.Image, "alpine")
	}
	if translated.NetworkBlockAll {
		t.Fatal("translated.NetworkBlockAll unexpectedly true")
	}
	if translated.Lifecycle != nil {
		t.Fatalf("translated.Lifecycle = %+v, want nil", translated.Lifecycle)
	}
	if translated.CPU != 0 || translated.MemoryMB != 0 || translated.DiskGB != 0 {
		t.Fatalf("unexpected translated resource values: %+v", translated)
	}
	if len(translated.Env) != 0 {
		t.Fatalf("translated.Env = %+v, want empty", translated.Env)
	}
}

func TestTranslateCreateSandboxRequestRejectsComplexBuildInfo(t *testing.T) {
	fixture := []byte(`{
		"buildInfo": {
			"dockerfileContent": "FROM alpine\nRUN echo hello"
		}
	}`)

	var req createSandboxRequest
	if err := json.Unmarshal(fixture, &req); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	h := newHandlers(Deps{})
	_, err := h.translateCreateSandboxRequest(req)
	if err == nil {
		t.Fatal("expected translateCreateSandboxRequest() error for complex buildInfo")
	}
	if got := err.Error(); got != "buildInfo is only supported for simple single-line Dockerfiles of the form `FROM <image>`" {
		t.Fatalf("error = %q", got)
	}
}

func TestTranslateCreateSandboxRequestPreservesIdleLifecycleFields(t *testing.T) {
	autoStop := int32(5)
	autoDelete := int32(15)
	req := createSandboxRequest{
		Public:             boolPtr(false),
		BuildInfo:          &buildInfoRequest{DockerfileContent: stringPtr("FROM alpine")},
		AutoStopInterval:   &autoStop,
		AutoDeleteInterval: &autoDelete,
		NetworkBlockAll:    boolPtr(true),
	}

	h := newHandlers(Deps{})
	translated, err := h.translateCreateSandboxRequest(req)
	if err != nil {
		t.Fatalf("translateCreateSandboxRequest() error = %v", err)
	}
	if translated.Image != "alpine" {
		t.Fatalf("translated.Image = %q, want alpine", translated.Image)
	}
	if !translated.NetworkBlockAll {
		t.Fatal("translated.NetworkBlockAll = false, want true")
	}
	if translated.Lifecycle == nil {
		t.Fatal("translated.Lifecycle = nil, want non-nil")
	}
	if translated.Lifecycle.StopIfIdleFor != 5*time.Minute {
		t.Fatalf("StopIfIdleFor = %v, want 5m", translated.Lifecycle.StopIfIdleFor)
	}
	if translated.Lifecycle.DestroyIfIdleFor != 15*time.Minute {
		t.Fatalf("DestroyIfIdleFor = %v, want 15m", translated.Lifecycle.DestroyIfIdleFor)
	}
}

func TestIntervalMetadataPtrRejectsNegativeAndClearsZero(t *testing.T) {
	if _, err := intervalMetadataPtr(-1); err == nil {
		t.Fatal("expected negative interval error")
	}
	if got, err := intervalMetadataPtr(0); err != nil || got != nil {
		t.Fatalf("intervalMetadataPtr(0) = (%+v, %v), want nil, nil", got, err)
	}
	got, err := intervalMetadataPtr(2.5)
	if err != nil {
		t.Fatalf("intervalMetadataPtr(2.5) error = %v", err)
	}
	if got == nil || *got != 2.5 {
		t.Fatalf("intervalMetadataPtr(2.5) = %+v, want 2.5", got)
	}
}

func TestInt32MinutesPtrOmitsDisabledIntervals(t *testing.T) {
	zero := int32(0)
	negative := int32(-1)
	positive := int32(7)
	if got := int32MinutesPtr(nil); got != nil {
		t.Fatalf("int32MinutesPtr(nil) = %+v, want nil", got)
	}
	if got := int32MinutesPtr(&zero); got != nil {
		t.Fatalf("int32MinutesPtr(0) = %+v, want nil", got)
	}
	if got := int32MinutesPtr(&negative); got != nil {
		t.Fatalf("int32MinutesPtr(-1) = %+v, want nil", got)
	}
	got := int32MinutesPtr(&positive)
	if got == nil || *got != 7 {
		t.Fatalf("int32MinutesPtr(7) = %+v, want 7", got)
	}
}

func TestListSnapshotsReturnsPaginatedDaytonaShape(t *testing.T) {
	ctx := context.Background()
	_, st, rt, handler := newSnapshotHandlerTestEnv(t)

	older := &models.SandboxSnapshot{
		Name:            "alpha",
		Image:           "snapshots/alpha:v1",
		ImageID:         "sha256:alpha",
		SourceSandboxID: "sb-alpha",
		CreatedAt:       time.Now().UTC().Add(-time.Hour).Round(0),
	}
	newer := &models.SandboxSnapshot{
		Name:            "beta",
		Image:           "snapshots/beta:v1",
		ImageID:         "sha256:beta",
		SourceSandboxID: "sb-beta",
		CreatedAt:       time.Now().UTC().Round(0),
	}
	for _, snapshot := range []*models.SandboxSnapshot{older, newer} {
		if err := st.CreateSnapshot(ctx, snapshot); err != nil {
			t.Fatalf("CreateSnapshot(%s) error = %v", snapshot.Name, err)
		}
	}
	if rt.removeHits != 0 {
		t.Fatalf("unexpected RemoveImage calls before request: %d", rt.removeHits)
	}

	req := httptest.NewRequest(http.MethodGet, "/daytona/snapshots?sort=name&order=asc&limit=1&page=2", nil)
	req.Header.Set("X-Daytona-Organization-ID", "org-123")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp paginatedSnapshotsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response error = %v", err)
	}
	if resp.Total != 2 || resp.Page != 2 || resp.TotalPages != 2 {
		t.Fatalf("unexpected pagination: %+v", resp)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(resp.Items))
	}
	if resp.Items[0].Name != "beta" {
		t.Fatalf("item name = %q, want beta", resp.Items[0].Name)
	}
	if resp.Items[0].ID != newer.ImageID {
		t.Fatalf("item id = %q, want %q", resp.Items[0].ID, newer.ImageID)
	}
	if resp.Items[0].OrganizationID == nil || *resp.Items[0].OrganizationID != "org-123" {
		t.Fatalf("organizationId = %+v, want org-123", resp.Items[0].OrganizationID)
	}
}

func TestGetSnapshotSupportsImageIDLookup(t *testing.T) {
	ctx := context.Background()
	_, st, _, handler := newSnapshotHandlerTestEnv(t)

	snapshot := &models.SandboxSnapshot{
		Name:            "lookup-by-id",
		Image:           "snapshots/lookup:v1",
		ImageID:         "sha256:lookup",
		SourceSandboxID: "sb-lookup",
		CreatedAt:       time.Now().UTC().Round(0),
	}
	if err := st.CreateSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("CreateSnapshot() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/daytona/snapshots/sha256:lookup", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp snapshotResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response error = %v", err)
	}
	if resp.ID != snapshot.ImageID || resp.Name != snapshot.Name {
		t.Fatalf("unexpected snapshot payload: %+v", resp)
	}
	if resp.ImageName == nil || *resp.ImageName != snapshot.Image {
		t.Fatalf("imageName = %+v, want %q", resp.ImageName, snapshot.Image)
	}
}

func TestDeleteSnapshotRemovesStoredSnapshot(t *testing.T) {
	ctx := context.Background()
	_, st, rt, handler := newSnapshotHandlerTestEnv(t)

	snapshot := &models.SandboxSnapshot{
		Name:            "delete-me",
		Image:           "snapshots/delete:v1",
		ImageID:         "sha256:delete-me",
		SourceSandboxID: "sb-delete",
		CreatedAt:       time.Now().UTC().Round(0),
	}
	if err := st.CreateSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("CreateSnapshot() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/daytona/snapshots/sha256:delete-me", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if rt.removeHits != 1 || rt.lastRemoved != snapshot.Image {
		t.Fatalf("unexpected remove image calls: hits=%d last=%q", rt.removeHits, rt.lastRemoved)
	}
	if _, err := st.GetSnapshot(ctx, snapshot.Name); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

type fakeDaytonaSnapshotRuntime struct {
	removeHits  int
	lastRemoved string
	removeErr   error
}

func (f *fakeDaytonaSnapshotRuntime) Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	panic("unexpected Create")
}

func (f *fakeDaytonaSnapshotRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	panic("unexpected CreateSnapshot")
}

func (f *fakeDaytonaSnapshotRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	panic("unexpected Start")
}

func (f *fakeDaytonaSnapshotRuntime) Stop(context.Context, string) error { panic("unexpected Stop") }

func (f *fakeDaytonaSnapshotRuntime) Destroy(context.Context, *models.Sandbox) error {
	panic("unexpected Destroy")
}

func (f *fakeDaytonaSnapshotRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	panic("unexpected Resize")
}

func (f *fakeDaytonaSnapshotRuntime) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	panic("unexpected Inspect")
}

func (f *fakeDaytonaSnapshotRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	panic("unexpected ListManaged")
}

func (f *fakeDaytonaSnapshotRuntime) Ping(context.Context) error { panic("unexpected Ping") }

func (f *fakeDaytonaSnapshotRuntime) RemoveImage(_ context.Context, imageRef string) error {
	f.removeHits++
	f.lastRemoved = imageRef
	return f.removeErr
}

func (f *fakeDaytonaSnapshotRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	panic("unexpected PushAllowedPorts")
}

func (f *fakeDaytonaSnapshotRuntime) ClearNetworkRules(string) error    { return nil }
func (f *fakeDaytonaSnapshotRuntime) ApplyNetworkBlockAll(string) error { return nil }

func newSnapshotHandlerTestEnv(t *testing.T) (*service.Service, *store.Store, *fakeDaytonaSnapshotRuntime, http.Handler) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rt := &fakeDaytonaSnapshotRuntime{}
	svc := service.New(config.Config{}, logger, st, rt, nil, nil, nil, nil, nil)
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

func boolPtr(value bool) *bool {
	return &value
}

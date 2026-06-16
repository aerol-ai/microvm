package v1

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

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// snapshotV1TestEnv bundles the moving parts a v1 snapshot test needs.
// We stand up a real store + service so RegisterSnapshot persists through
// the same path production uses, and inject a fake builder for the
// dockerfile_content branch.
type snapshotV1TestEnv struct {
	svc     *service.Service
	store   *store.Store
	builder *fakeImageBuilder
	handler http.Handler
}

func newSnapshotV1TestEnv(t *testing.T, builder *fakeImageBuilder, build BuildConfig) *snapshotV1TestEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, st, &noopRuntime{}, nil, nil, nil, nil, nil)
	if builder == nil {
		builder = &fakeImageBuilder{}
	}
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Builder: builder,
		Build:   build,
		Auth:    func(h http.Handler) http.Handler { return h },
	})
	return &snapshotV1TestEnv{svc: svc, store: st, builder: builder, handler: mux}
}

// TestRegisterSnapshotFromImage covers the simple path: caller hands us a
// pre-built registry image. We persist a snapshot row with the supplied
// resources/region and respond 201 with the stored row.
func TestRegisterSnapshotFromImage(t *testing.T) {
	env := newSnapshotV1TestEnv(t, nil, BuildConfig{})

	body := `{
		"name": "py-base",
		"image": "python:3.12-slim",
		"entrypoint": ["python", "-V"],
		"cpu": 2,
		"memory_mb": 4096,
		"disk_gb": 10,
		"region_id": "us"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/snapshots", strings.NewReader(body))
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	var resp models.SandboxSnapshot
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "py-base" || resp.Image != "python:3.12-slim" {
		t.Errorf("resp = %+v, want name=py-base image=python:3.12-slim", resp)
	}
	if resp.RegionID != "us" || resp.MemoryMB != 4096 || resp.DiskGB != 10 || resp.CPU != 2 {
		t.Errorf("resp resources = %+v, want region=us cpu=2 mem=4096 disk=10", resp)
	}

	stored, err := env.svc.GetSnapshot(context.Background(), "py-base")
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if stored.Image != "python:3.12-slim" {
		t.Errorf("stored.Image = %q, want python:3.12-slim", stored.Image)
	}
	if len(env.builder.builds) != 0 {
		t.Errorf("image path must not invoke builder, got %d builds", len(env.builder.builds))
	}
	// External registry refs need no AOCR push — the response must surface
	// push_state="active" immediately so a polling client doesn't wait.
	if resp.PushState != models.SnapshotPushStateActive {
		t.Errorf("resp.PushState = %q, want %q (external image needs no push)",
			resp.PushState, models.SnapshotPushStateActive)
	}
}

// TestRegisterSnapshotWithPusherMarksPending exercises the wiring that flips
// new rows to push_state="pending" when the pusher is attached. Reading the
// row back from the store (rather than relying on the response body) keeps
// this test isolated from the goroutine the service kicks after CreateSnapshot
// — we just want to prove the persisted state is what the reconciler will
// pick up on its next tick.
func TestRegisterSnapshotWithPusherMarksPending(t *testing.T) {
	env := newSnapshotV1TestEnv(t, nil, BuildConfig{})

	patPath := filepath.Join(t.TempDir(), "pat")
	if err := writeTestFile(patPath, "token"); err != nil {
		t.Fatalf("write pat: %v", err)
	}
	pusher, err := service.NewSnapshotPusher(service.SnapshotPushConfig{
		Enabled:   true,
		Host:      "aocr.test",
		ClusterID: "cluster-v1",
		PATPath:   patPath,
	}, &v1NoopPushDocker{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewSnapshotPusher: %v", err)
	}
	// Attach only the pusher, not the reconciler. The test asserts on the
	// initial persisted state (local_only + pending). Attaching a reconciler
	// would cause kickSnapshotPushReconciler to fire a goroutine that races
	// with GetSnapshot below — the noop docker returns immediately and the
	// reconciler would flip ImageDistributionMode to "aocr" before we read.
	env.svc.AttachSnapshotPusher(pusher, nil)

	body := `{"name":"locally-built","dockerfile_content":"FROM debian:bookworm-slim\nRUN true"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/snapshots", strings.NewReader(body))
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
	}

	stored, err := env.svc.GetSnapshot(context.Background(), "locally-built")
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	// Built dockerfile snapshots start as local_only with push_state=pending
	// so the reconciler picks them up. We check the persisted row (not the
	// response body) to prove the store has the correct initial state.
	if stored.ImageDistributionMode != models.ImageDistributionLocalOnly {
		t.Fatalf("ImageDistributionMode = %q, want %q", stored.ImageDistributionMode, models.ImageDistributionLocalOnly)
	}
	if stored.PushState != models.SnapshotPushStatePending {
		t.Fatalf("PushState = %q, want %q", stored.PushState, models.SnapshotPushStatePending)
	}
}

// v1NoopPushDocker is a stand-in for the snapshot pusher's docker dep that
// never gets invoked in this test (we assert on the queued state, not on
// the reconciler outcome). Declaring it here keeps the test self-contained.
type v1NoopPushDocker struct{}

func (v1NoopPushDocker) PushImage(_ context.Context, req docker.PushImageRequest) (string, error) {
	return req.DestRef, nil
}

func writeTestFile(path, contents string) error {
	return os.WriteFile(path, []byte(contents), 0o600)
}

// TestRegisterSnapshotFromDockerfile covers the multi-line dockerfile path:
// the daemon runs the build through Builder.BuildImage and registers the
// resulting content-addressed tag as the snapshot's image.
func TestRegisterSnapshotFromDockerfile(t *testing.T) {
	env := newSnapshotV1TestEnv(t, &fakeImageBuilder{}, BuildConfig{})

	dockerfile := "FROM debian:bookworm-slim\nRUN apt-get update"
	wantTag := docker.BuildTagFor(dockerfile, nil)
	body, _ := json.Marshal(map[string]any{
		"name":               "debian-built",
		"dockerfile_content": dockerfile,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/snapshots", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	var resp models.SandboxSnapshot
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Image != wantTag {
		t.Errorf("resp.Image = %q, want %q (resolved build tag)", resp.Image, wantTag)
	}
	if len(env.builder.builds) != 1 || env.builder.builds[0].Tag != wantTag {
		t.Fatalf("unexpected builder.builds: %+v", env.builder.builds)
	}
}

// TestRegisterSnapshotSingleLineFROM is the fast-path: a one-liner FROM
// dockerfile with no context returns the bare image without a build.
func TestRegisterSnapshotSingleLineFROM(t *testing.T) {
	env := newSnapshotV1TestEnv(t, nil, BuildConfig{})

	body := `{"name":"alpine","dockerfile_content":"FROM alpine:3.20"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/snapshots", strings.NewReader(body))
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
	}
	var resp models.SandboxSnapshot
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Image != "alpine:3.20" {
		t.Errorf("resp.Image = %q, want alpine:3.20 (single-line FROM is pass-through)", resp.Image)
	}
	if len(env.builder.builds) != 0 {
		t.Errorf("single-line FROM must not invoke builder, got %d builds", len(env.builder.builds))
	}
}

// TestRegisterSnapshotCacheHitRefreshes verifies the dockerfile_content path
// short-circuits when the build cache already has the tag, and that we bump
// LastTagTime via RefreshTag so the janitor doesn't GC the row we just
// pointed a snapshot at.
func TestRegisterSnapshotCacheHitRefreshes(t *testing.T) {
	dockerfile := "FROM alpine:3.20\nRUN echo cached"
	wantTag := docker.BuildTagFor(dockerfile, nil)
	builder := &fakeImageBuilder{exists: map[string]bool{wantTag: true}}
	env := newSnapshotV1TestEnv(t, builder, BuildConfig{})

	body, _ := json.Marshal(map[string]any{
		"name":               "cached",
		"dockerfile_content": dockerfile,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/snapshots", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
	}
	if len(builder.builds) != 0 {
		t.Errorf("cache hit should skip BuildImage, got %d builds", len(builder.builds))
	}
	if len(builder.refreshes) != 1 || builder.refreshes[0] != wantTag {
		t.Errorf("expected RefreshTag(%q), got %+v", wantTag, builder.refreshes)
	}
}

// TestRegisterSnapshotValidationErrors pins the input shapes the handler
// rejects up front.
func TestRegisterSnapshotValidationErrors(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		build    BuildConfig
		wantCode int
		wantHint string
	}{
		{
			name:     "missing name",
			body:     `{"image":"python:3.12"}`,
			wantCode: http.StatusBadRequest,
			wantHint: "name is required",
		},
		{
			name:     "neither image nor dockerfile",
			body:     `{"name":"x"}`,
			wantCode: http.StatusBadRequest,
			wantHint: "image or dockerfile_content",
		},
		{
			name:     "both image and dockerfile",
			body:     `{"name":"x","image":"a","dockerfile_content":"FROM b"}`,
			wantCode: http.StatusBadRequest,
			wantHint: "mutually exclusive",
		},
		{
			name:     "context_hashes without operator flag",
			body:     `{"name":"x","dockerfile_content":"FROM a\nCOPY . /app","context_hashes":["deadbeef"]}`,
			wantCode: http.StatusBadRequest,
			wantHint: "SB_IMAGE_BUILD_CONTEXT_ENABLED",
		},
		{
			name:     "context_hashes with flag returns not implemented",
			body:     `{"name":"x","dockerfile_content":"FROM a\nCOPY . /app","context_hashes":["deadbeef"]}`,
			build:    BuildConfig{ContextEnabled: true},
			wantCode: http.StatusNotImplemented,
			wantHint: "context_hashes",
		},
		{
			name:     "invalid json",
			body:     `{not-json`,
			wantCode: http.StatusBadRequest,
			wantHint: "invalid JSON",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newSnapshotV1TestEnv(t, nil, tc.build)
			req := httptest.NewRequest(http.MethodPost, "/v1/snapshots", strings.NewReader(tc.body))
			rr := httptest.NewRecorder()
			env.handler.ServeHTTP(rr, req)

			if rr.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tc.wantCode, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tc.wantHint) {
				t.Errorf("body does not contain %q; got %s", tc.wantHint, rr.Body.String())
			}
		})
	}
}

// TestRegisterSnapshotMissingBuilderFor multilineDockerfile checks the
// graceful 400 when the daemon was started without an image builder but a
// caller asked for a multi-line dockerfile build. Single-line FROM still
// works without a builder (pass-through).
func TestRegisterSnapshotMissingBuilder(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, st, &noopRuntime{}, nil, nil, nil, nil, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Builder: nil, // no builder configured
		Auth:    func(h http.Handler) http.Handler { return h },
	})

	body := `{"name":"x","dockerfile_content":"FROM alpine\nRUN true"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/snapshots", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "image builder") {
		t.Errorf("body should explain missing builder; got %s", rr.Body.String())
	}
}

// TestRegisterSnapshotBuildErrorRollsBack covers the registration-failure
// path: if RegisterSnapshot fails after a successful build, we must call
// RemoveImage on the freshly built tag, otherwise the layer leaks (no
// snapshot row points at it for the built-image janitor).
//
// We trigger that path by registering "boom" once successfully, then asking
// to register the same name with a *different* image — the second call
// surfaces a conflict from the service layer, and the rollback should fire.
func TestRegisterSnapshotBuildErrorRollsBack(t *testing.T) {
	env := newSnapshotV1TestEnv(t, &fakeImageBuilder{}, BuildConfig{})

	// First call: pin name "boom" to a single-line FROM (no build, no
	// builder.removes invocation).
	first := httptest.NewRecorder()
	env.handler.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/v1/snapshots",
		strings.NewReader(`{"name":"boom","image":"alpine:3.20"}`)))
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d; body=%s", first.Code, first.Body.String())
	}

	// Second call: same name but a different (built) image. The service
	// layer rejects on conflict, and the freshly built tag must be removed.
	dockerfile := "FROM debian:bookworm-slim\nRUN apt-get update"
	wantTag := docker.BuildTagFor(dockerfile, nil)
	body, _ := json.Marshal(map[string]any{
		"name":               "boom",
		"dockerfile_content": dockerfile,
	})
	second := httptest.NewRecorder()
	env.handler.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/v1/snapshots",
		strings.NewReader(string(body))))
	if second.Code == http.StatusCreated {
		t.Fatalf("expected conflict, got 201; body=%s", second.Body.String())
	}
	if len(env.builder.removes) != 1 || env.builder.removes[0] != wantTag {
		t.Errorf("expected rollback RemoveImage(%q), got %+v", wantTag, env.builder.removes)
	}
}

// TestRegisterSnapshotBuildTimeout maps a deadline-exceeded build error to
// 504 via the writeBuildError sentinel mapping.
func TestRegisterSnapshotBuildTimeout(t *testing.T) {
	builder := &fakeImageBuilder{buildErr: context.DeadlineExceeded}
	env := newSnapshotV1TestEnv(t, builder, BuildConfig{})

	body := `{"name":"slow","dockerfile_content":"FROM debian:bookworm\nRUN sleep 9999"}`
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/snapshots",
		strings.NewReader(body)))

	if rr.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504; body=%s", rr.Code, rr.Body.String())
	}
}

// TestRegisterSnapshotBuildOperationalError maps a generic build failure to
// 502.
func TestRegisterSnapshotBuildOperationalError(t *testing.T) {
	builder := &fakeImageBuilder{buildErr: errors.New("docker daemon refused")}
	env := newSnapshotV1TestEnv(t, builder, BuildConfig{})

	body := `{"name":"broken","dockerfile_content":"FROM debian:bookworm\nRUN false"}`
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/snapshots",
		strings.NewReader(body)))

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", rr.Code, rr.Body.String())
	}
}

// noopRuntime is the minimal runtime stub the v1 snapshot tests need —
// snapshot registration never touches the runtime, so every method panics
// to surface accidental coupling at test time.
type noopRuntime struct{}

func (noopRuntime) Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	panic("unexpected Create")
}
func (noopRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	panic("unexpected CreateSnapshot")
}
func (noopRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	panic("unexpected Start")
}
func (noopRuntime) Stop(context.Context, string) error             { panic("unexpected Stop") }
func (noopRuntime) Destroy(context.Context, *models.Sandbox) error { panic("unexpected Destroy") }
func (noopRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	panic("unexpected Resize")
}
func (noopRuntime) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	panic("unexpected Inspect")
}
func (noopRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	panic("unexpected ListManaged")
}
func (noopRuntime) Ping(context.Context) error                { panic("unexpected Ping") }
func (noopRuntime) RemoveImage(context.Context, string) error { return nil }
func (noopRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	panic("unexpected PushAllowedPorts")
}
func (noopRuntime) ClearNetworkRules(string) error                     { return nil }
func (noopRuntime) ApplyEgressPolicy(string, []string, []string) error { return nil }
func (noopRuntime) ClearEgressPolicy(string, []string, []string) error { return nil }
func (noopRuntime) ApplyNetworkBlockAll(string) error                  { return nil }
func (noopRuntime) ApplyNetworkBlockIngress(string) error              { return nil }
func (noopRuntime) ClearNetworkBlockIngress(string) error              { return nil }
func (noopRuntime) ClearNetworkBlockEgress(string) error               { return nil }

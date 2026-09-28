package daytona

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestDaytonaSnapshotStateMapping pins the Daytona-facing state translation
// for every push-lifecycle value the snapshot row can hold. The SDK's poll
// loop exits only on "active" or "error" — getting any of these wrong
// either hangs the client or fails it early, so we lock in the table.
func TestDaytonaSnapshotStateMapping(t *testing.T) {
	cases := []struct {
		name       string
		pushState  string
		pushError  string
		wantState  string
		wantReason string
		reasonNil  bool
	}{
		{"empty (legacy row) is active", "", "", "active", "", true},
		{"active", models.SnapshotPushStateActive, "", "active", "", true},
		{"pending → pulling_image", models.SnapshotPushStatePending, "", "pulling_image", "", true},
		{"pushing → pulling_image", models.SnapshotPushStatePushing, "", "pulling_image", "", true},
		{"error surfaces push error", models.SnapshotPushStateError, "registry 500", "error", "registry 500", false},
		{"error without message gets fallback reason", models.SnapshotPushStateError, "", "error", "snapshot push failed", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := &models.SandboxSnapshot{PushState: tc.pushState, PushError: tc.pushError}
			state, reason := daytonaSnapshotState(snap)
			if state != tc.wantState {
				t.Fatalf("state = %q, want %q", state, tc.wantState)
			}
			if tc.reasonNil {
				if reason != nil {
					t.Fatalf("reason = %q, want nil", *reason)
				}
				return
			}
			if reason == nil {
				t.Fatalf("reason = nil, want %q", tc.wantReason)
			}
			if *reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", *reason, tc.wantReason)
			}
		})
	}
}

// snapshotCreateTestEnv bundles the moving parts a snapshot-create test
// needs. Tests that only drive HTTP use .handler; tests that want to call
// internal helpers (e.g. translateCreateSandboxRequest) use .h.
type snapshotCreateTestEnv struct {
	svc     *service.Service
	store   *store.Store
	builder *fakeImageBuilder
	h       *handlers
	handler http.Handler
}

// newSnapshotCreateTestEnv mirrors newSnapshotHandlerTestEnv but lets a test
// inject a fake builder so the buildInfo branch can be exercised without a
// real Docker daemon.
func newSnapshotCreateTestEnv(t *testing.T, builder *fakeImageBuilder) *snapshotCreateTestEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rt := &fakeDaytonaSnapshotRuntime{}
	svc := service.New(config.Config{}, logger, st, rt, nil, nil, newDaytonaTestCipher(t), nil, nil)
	if builder == nil {
		builder = &fakeImageBuilder{}
	}
	deps := Deps{
		Service: svc,
		Logger:  logger,
		Builder: builder,
		Auth: func(next http.Handler) http.Handler {
			return next
		},
	}
	h := newHandlers(deps)
	mux := http.NewServeMux()
	RegisterRoutes(mux, deps)
	return &snapshotCreateTestEnv{
		svc:     svc,
		store:   st,
		builder: builder,
		h:       h,
		handler: mux,
	}
}

// TestCreateSnapshotFromImageName covers the simple path: the caller hands
// us a pre-built registry image. We persist a snapshot row pointing at that
// image, return state="active" so the SDK's poll loop exits immediately,
// and surface the resources / regionId the caller asked for.
func TestCreateSnapshotFromImageName(t *testing.T) {
	env := newSnapshotCreateTestEnv(t, nil)
	svc, builder, handler := env.svc, env.builder, env.handler

	body := `{
		"name": "py-base",
		"imageName": "python:3.12-slim",
		"entrypoint": ["python", "-V"],
		"cpu": 2,
		"memory": 4,
		"disk": 10,
		"regionId": "us"
	}`
	req := httptest.NewRequest(http.MethodPost, "/daytona/snapshots", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var resp snapshotResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Name != "py-base" {
		t.Errorf("name = %q, want py-base", resp.Name)
	}
	if resp.ImageName == nil || *resp.ImageName != "python:3.12-slim" {
		t.Errorf("imageName = %+v, want python:3.12-slim", resp.ImageName)
	}
	if resp.State != "active" {
		t.Errorf("state = %q, want active (SDK polls until terminal)", resp.State)
	}
	if len(resp.Entrypoint) != 2 || resp.Entrypoint[0] != "python" {
		t.Errorf("entrypoint = %+v, want [python -V]", resp.Entrypoint)
	}
	if resp.CPU != 2 || resp.Mem != 4 || resp.Disk != 10 {
		t.Errorf("resources = (cpu=%v mem=%v disk=%v), want (2,4,10)", resp.CPU, resp.Mem, resp.Disk)
	}
	if len(resp.RegionIDs) != 1 || resp.RegionIDs[0] != "us" {
		t.Errorf("regionIds = %+v, want [us]", resp.RegionIDs)
	}

	// Persisted via the service — verify GetSnapshot returns it.
	stored, err := svc.GetSnapshot(context.Background(), "py-base")
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if stored.Image != "python:3.12-slim" {
		t.Errorf("stored.Image = %q, want python:3.12-slim", stored.Image)
	}
	if stored.RegionID != "us" {
		t.Errorf("stored.RegionID = %q, want us", stored.RegionID)
	}

	// imageName path must NOT touch the builder.
	if len(builder.builds) != 0 {
		t.Errorf("builder.builds = %d, want 0 (imageName path)", len(builder.builds))
	}
}

// TestCreateSnapshotFromBuildInfo covers the SDK's Image.debianSlim(...)
// flow — the Image builder serializes to a multi-line Dockerfile and we
// run it through resolveBuildInfo, which calls the image builder. The
// resulting tag is then registered as the snapshot's image.
func TestCreateSnapshotFromBuildInfo(t *testing.T) {
	env := newSnapshotCreateTestEnv(t, &fakeImageBuilder{})
	builder, handler := env.builder, env.handler

	dockerfile := "FROM debian:bookworm-slim\nRUN apt-get update"
	wantTag := docker.BuildTagFor(dockerfile, nil)
	payload := map[string]any{
		"name": "debian-built",
		"buildInfo": map[string]any{
			"dockerfileContent": dockerfile,
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/daytona/snapshots", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}

	var resp snapshotResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ImageName == nil || *resp.ImageName != wantTag {
		t.Errorf("imageName = %+v, want %q (resolved build tag)", resp.ImageName, wantTag)
	}
	if len(builder.builds) != 1 {
		t.Fatalf("builder.builds = %d, want 1 (build path)", len(builder.builds))
	}
	if got := builder.builds[0].Tag; got != wantTag {
		t.Errorf("build tag = %q, want %q", got, wantTag)
	}
}

// TestCreateSnapshotFromSingleLineFROM is the fast-path: a one-liner FROM
// dockerfile with no context. The facade returns the bare image string
// without invoking the builder (mirrors resolveBuildInfo's case 1).
func TestCreateSnapshotFromSingleLineFROM(t *testing.T) {
	env := newSnapshotCreateTestEnv(t, nil)
	builder, handler := env.builder, env.handler

	body := `{"name":"alpine","buildInfo":{"dockerfileContent":"FROM alpine:3.20"}}`
	req := httptest.NewRequest(http.MethodPost, "/daytona/snapshots", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
	}
	var resp snapshotResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.ImageName == nil || *resp.ImageName != "alpine:3.20" {
		t.Errorf("imageName = %+v, want alpine:3.20 (single-line FROM is pass-through)", resp.ImageName)
	}
	if len(builder.builds) != 0 {
		t.Errorf("builder.builds = %d, want 0 (single-line FROM should not build)", len(builder.builds))
	}
}

// TestCreateSnapshotValidationErrors pins the input shapes the handler
// rejects up front. Each row is a payload + expected error fragment so a
// future refactor that loosens validation flips a specific case red.
func TestCreateSnapshotValidationErrors(t *testing.T) {
	handler := newSnapshotCreateTestEnv(t, nil).handler

	cases := []struct {
		name     string
		body     string
		wantCode int
		wantHint string
	}{
		{
			name:     "missing name",
			body:     `{"imageName":"python:3.12"}`,
			wantCode: http.StatusBadRequest,
			wantHint: "name is required",
		},
		{
			name:     "neither imageName nor buildInfo",
			body:     `{"name":"x"}`,
			wantCode: http.StatusBadRequest,
			wantHint: "imageName or buildInfo",
		},
		{
			name:     "both imageName and buildInfo set",
			body:     `{"name":"x","imageName":"a","buildInfo":{"dockerfileContent":"FROM b"}}`,
			wantCode: http.StatusBadRequest,
			wantHint: "mutually exclusive",
		},
		{
			name:     "contextHashes without operator flag",
			body:     `{"name":"x","buildInfo":{"dockerfileContent":"FROM a\nCOPY . /app","contextHashes":["deadbeef"]}}`,
			wantCode: http.StatusBadRequest,
			wantHint: "SB_IMAGE_BUILD_CONTEXT_ENABLED",
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
			req := httptest.NewRequest(http.MethodPost, "/daytona/snapshots", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tc.wantCode, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tc.wantHint) {
				t.Errorf("body does not contain %q; got %s", tc.wantHint, rr.Body.String())
			}
		})
	}
}

// TestCreateSnapshotIdempotentOnSameImage covers the SDK-retry case: if a
// caller re-issues the same create request after a transient network
// failure, we return the existing row instead of erroring with a conflict.
// A retry with a *different* image is still a conflict — that's a different
// payload claiming the same name.
func TestCreateSnapshotIdempotentOnSameImage(t *testing.T) {
	handler := newSnapshotCreateTestEnv(t, nil).handler

	body := `{"name":"py","imageName":"python:3.12"}`
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/daytona/snapshots",
		strings.NewReader(body)))
	if first.Code != http.StatusCreated {
		t.Fatalf("first call status = %d; body=%s", first.Code, first.Body.String())
	}

	// Same payload twice — should succeed, not 409.
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/daytona/snapshots",
		strings.NewReader(body)))
	if second.Code != http.StatusCreated {
		t.Fatalf("retry status = %d, want 201 (idempotent); body=%s", second.Code, second.Body.String())
	}

	// Same name with a *different* image must conflict.
	conflict := httptest.NewRecorder()
	handler.ServeHTTP(conflict, httptest.NewRequest(http.MethodPost, "/daytona/snapshots",
		strings.NewReader(`{"name":"py","imageName":"python:3.13"}`)))
	if conflict.Code == http.StatusCreated {
		t.Fatalf("conflicting image under same name accepted: body=%s", conflict.Body.String())
	}
}

// TestCreateSnapshotThenCreateSandboxResolvesImage is the end-to-end glue
// the declarative-image example needs: after registering a snapshot named
// "py-base" → "python:3.12-slim", a follow-up sandbox create that passes
// snapshot: "py-base" must resolve to image "python:3.12-slim", not pass
// the literal string "py-base" downstream as a docker image ref.
func TestCreateSnapshotThenCreateSandboxResolvesImage(t *testing.T) {
	env := newSnapshotCreateTestEnv(t, nil)

	// 1. Register the snapshot via HTTP — same path the SDK takes.
	mkSnap := httptest.NewRecorder()
	env.handler.ServeHTTP(mkSnap, httptest.NewRequest(http.MethodPost, "/daytona/snapshots",
		strings.NewReader(`{"name":"py-base","imageName":"python:3.12-slim"}`)))
	if mkSnap.Code != http.StatusCreated {
		t.Fatalf("create snapshot status = %d; body=%s", mkSnap.Code, mkSnap.Body.String())
	}

	// 2. Translate a sandbox-create payload that references that snapshot.
	// The lookup happens inside translateCreateSandboxRequest → createImage
	// → service.GetSnapshot, so we don't need to drive the full Docker
	// create path to verify resolution.
	snapshotName := "py-base"
	req := createSandboxRequest{Snapshot: &snapshotName}
	translated, _, err := env.h.translateCreateSandboxRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if translated.Image != "python:3.12-slim" {
		t.Fatalf("translated.Image = %q, want python:3.12-slim (resolved from snapshot row)", translated.Image)
	}
}

// TestCreateSandboxWithUnknownSnapshotFallsThrough preserves the legacy
// behavior used by the create-vm example: if the snapshot string isn't a
// registered snapshot name, the facade passes it through as a docker image
// reference instead of erroring. That way callers can keep referencing
// registry-style strings (e.g. "ghcr.io/me/img:tag") without first having
// to register them.
func TestCreateSandboxWithUnknownSnapshotFallsThrough(t *testing.T) {
	env := newSnapshotCreateTestEnv(t, nil)

	directRef := "ghcr.io/sumanrocs/penify-agent:v1"
	req := createSandboxRequest{Snapshot: &directRef}
	translated, _, err := env.h.translateCreateSandboxRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if translated.Image != directRef {
		t.Fatalf("translated.Image = %q, want %q (fallback pass-through)", translated.Image, directRef)
	}
}

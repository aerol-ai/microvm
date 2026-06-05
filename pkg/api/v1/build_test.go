package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
)

type fakeImageBuilder struct {
	exists     map[string]bool
	existsErr  error
	builds     []docker.BuildImageRequest
	buildErr   error
	pushes     []docker.PushImageRequest
	pushErr    error
	refreshes  []string
	refreshErr error
	removes    []string
	removeErr  error
}

func (f *fakeImageBuilder) RefreshTag(_ context.Context, ref string) error {
	f.refreshes = append(f.refreshes, ref)
	return f.refreshErr
}

func (f *fakeImageBuilder) RemoveImage(_ context.Context, ref string) error {
	f.removes = append(f.removes, ref)
	if f.removeErr != nil {
		return f.removeErr
	}
	if f.exists != nil {
		delete(f.exists, ref)
	}
	return nil
}

func (f *fakeImageBuilder) ImageExists(_ context.Context, ref string) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}
	return f.exists[ref], nil
}

func (f *fakeImageBuilder) BuildImage(_ context.Context, req docker.BuildImageRequest) error {
	f.builds = append(f.builds, req)
	if f.buildErr != nil {
		return f.buildErr
	}
	if f.exists == nil {
		f.exists = map[string]bool{}
	}
	f.exists[req.Tag] = true
	return nil
}

func (f *fakeImageBuilder) PushImage(_ context.Context, req docker.PushImageRequest) (string, error) {
	f.pushes = append(f.pushes, req)
	if f.pushErr != nil {
		return "", f.pushErr
	}
	return req.DestRef, nil
}

func newTestMux(builder ImageBuilder, build BuildConfig) http.Handler {
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Builder: builder,
		Build:   build,
		Auth:    func(h http.Handler) http.Handler { return h },
	})
	return mux
}

func TestBuildImageReturnsContentAddressedTag(t *testing.T) {
	dockerfile := "FROM alpine\nRUN echo hi"
	builder := &fakeImageBuilder{}
	mux := newTestMux(builder, BuildConfig{})

	body, _ := json.Marshal(buildImageRequest{DockerfileContent: dockerfile})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
	}
	var resp buildImageResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantTag := docker.BuildTagFor(dockerfile, nil)
	if resp.Image != wantTag {
		t.Fatalf("Image = %q, want %q", resp.Image, wantTag)
	}
	if len(builder.builds) != 1 || builder.builds[0].Tag != wantTag {
		t.Fatalf("unexpected build calls: %+v", builder.builds)
	}
}

func TestBuildImageCacheHitSkipsBuild(t *testing.T) {
	dockerfile := "FROM alpine\nRUN echo hi"
	wantTag := docker.BuildTagFor(dockerfile, nil)
	builder := &fakeImageBuilder{exists: map[string]bool{wantTag: true}}
	mux := newTestMux(builder, BuildConfig{})

	body, _ := json.Marshal(buildImageRequest{DockerfileContent: dockerfile})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if len(builder.builds) != 0 {
		t.Fatalf("expected zero builds on cache hit, got %d", len(builder.builds))
	}
}

func TestBuildImageRejectsEmptyDockerfile(t *testing.T) {
	mux := newTestMux(&fakeImageBuilder{}, BuildConfig{})
	body, _ := json.Marshal(buildImageRequest{DockerfileContent: "   "})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestBuildImageRejectsContextHashesWithoutFlag(t *testing.T) {
	mux := newTestMux(&fakeImageBuilder{}, BuildConfig{})
	body, _ := json.Marshal(buildImageRequest{
		DockerfileContent: "FROM alpine\nCOPY x x",
		ContextHashes:     []string{"deadbeef"},
	})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "SB_IMAGE_BUILD_CONTEXT_ENABLED") {
		t.Fatalf("body should point at flag: %s", rr.Body.String())
	}
}

func TestBuildImageRejectsMissingBuilder(t *testing.T) {
	mux := newTestMux(nil, BuildConfig{})
	body, _ := json.Marshal(buildImageRequest{DockerfileContent: "FROM alpine"})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestBuildImagePushesAfterBuild(t *testing.T) {
	dockerfile := "FROM alpine\nRUN echo hi"
	builder := &fakeImageBuilder{}
	mux := newTestMux(builder, BuildConfig{})

	body, _ := json.Marshal(buildImageRequest{
		DockerfileContent: dockerfile,
		Push: &buildImagePushSpec{
			Registry: "ghcr.io/my-org/my-image",
			Tag:      "v1.2.3",
			Server:   "ghcr.io",
			Username: "ci-bot",
			Password: "secret",
		},
	})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
	}
	var resp buildImageResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantTag := docker.BuildTagFor(dockerfile, nil)
	if resp.Image != wantTag {
		t.Fatalf("Image = %q, want %q", resp.Image, wantTag)
	}
	if resp.Pushed != "ghcr.io/my-org/my-image:v1.2.3" {
		t.Fatalf("Pushed = %q, want ghcr.io/my-org/my-image:v1.2.3", resp.Pushed)
	}
	if len(builder.builds) != 1 {
		t.Fatalf("expected 1 build call, got %d", len(builder.builds))
	}
	if len(builder.pushes) != 1 {
		t.Fatalf("expected 1 push call, got %d", len(builder.pushes))
	}
	got := builder.pushes[0]
	if got.SourceTag != wantTag {
		t.Fatalf("push SourceTag = %q, want %q", got.SourceTag, wantTag)
	}
	if got.DestRef != "ghcr.io/my-org/my-image:v1.2.3" {
		t.Fatalf("push DestRef = %q, want ghcr.io/my-org/my-image:v1.2.3", got.DestRef)
	}
	if got.Auth.Username != "ci-bot" || got.Auth.Password != "secret" || got.Auth.Server != "ghcr.io" {
		t.Fatalf("unexpected auth: %+v", got.Auth)
	}
}

func TestBuildImagePushesOnCacheHit(t *testing.T) {
	dockerfile := "FROM alpine\nRUN echo hi"
	wantTag := docker.BuildTagFor(dockerfile, nil)
	builder := &fakeImageBuilder{exists: map[string]bool{wantTag: true}}
	mux := newTestMux(builder, BuildConfig{})

	body, _ := json.Marshal(buildImageRequest{
		DockerfileContent: dockerfile,
		Push: &buildImagePushSpec{
			Registry: "ghcr.io/my-org/my-image",
			Username: "u",
			Password: "p",
		},
	})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
	}
	if len(builder.builds) != 0 {
		t.Fatalf("cache hit should skip build, got %d", len(builder.builds))
	}
	if len(builder.pushes) != 1 {
		t.Fatalf("expected push on cache hit, got %d", len(builder.pushes))
	}
}

func TestBuildImagePushRejectsMissingCredentials(t *testing.T) {
	cases := []struct {
		name string
		push *buildImagePushSpec
	}{
		{"empty registry", &buildImagePushSpec{Username: "u", Password: "p"}},
		{"missing username", &buildImagePushSpec{Registry: "ghcr.io/x/y", Password: "p"}},
		{"missing password", &buildImagePushSpec{Registry: "ghcr.io/x/y", Username: "u"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := newTestMux(&fakeImageBuilder{}, BuildConfig{})
			body, _ := json.Marshal(buildImageRequest{
				DockerfileContent: "FROM alpine",
				Push:              tc.push,
			})
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestBuildImagePushFailureSurfaces(t *testing.T) {
	dockerfile := "FROM alpine"
	builder := &fakeImageBuilder{pushErr: errPushBoom}
	mux := newTestMux(builder, BuildConfig{})

	body, _ := json.Marshal(buildImageRequest{
		DockerfileContent: dockerfile,
		Push: &buildImagePushSpec{
			Registry: "ghcr.io/x/y",
			Username: "u",
			Password: "p",
		},
	})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", rr.Code, rr.Body.String())
	}
}

func TestBuildImageInvalidJSON(t *testing.T) {
	h := &handlers{deps: Deps{}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader("{bad"))
	h.buildImage(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestBuildImageContextHashesEnabledReturns501(t *testing.T) {
	mux := newTestMux(&fakeImageBuilder{}, BuildConfig{ContextEnabled: true})
	body, _ := json.Marshal(buildImageRequest{
		DockerfileContent: "FROM alpine\nCOPY . /app",
		ContextHashes:     []string{"deadbeef"},
	})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501; body=%s", rr.Code, rr.Body.String())
	}
}

func TestBuildImageCacheRefreshFailureStillOK(t *testing.T) {
	dockerfile := "FROM alpine\nRUN echo hi"
	wantTag := docker.BuildTagFor(dockerfile, nil)
	builder := &fakeImageBuilder{
		exists:     map[string]bool{wantTag: true},
		refreshErr: errors.New("refresh failed"),
	}
	mux := newTestMux(builder, BuildConfig{})

	body, _ := json.Marshal(buildImageRequest{DockerfileContent: dockerfile})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestBuildImageBuildFailure(t *testing.T) {
	builder := &fakeImageBuilder{buildErr: errors.New("build failed")}
	mux := newTestMux(builder, BuildConfig{})
	body, _ := json.Marshal(buildImageRequest{DockerfileContent: "FROM alpine\nRUN false"})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
}

func TestBuildImageBuildTimeout(t *testing.T) {
	builder := &fakeImageBuilder{buildErr: context.DeadlineExceeded}
	mux := newTestMux(builder, BuildConfig{Timeout: time.Second})
	body, _ := json.Marshal(buildImageRequest{DockerfileContent: "FROM alpine\nRUN sleep 999"})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
	if rr.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504; body=%s", rr.Code, rr.Body.String())
	}
}

func TestBuildImagePushTimeout(t *testing.T) {
	builder := &fakeImageBuilder{pushErr: context.DeadlineExceeded}
	mux := newTestMux(builder, BuildConfig{Timeout: time.Second})
	body, _ := json.Marshal(buildImageRequest{
		DockerfileContent: "FROM alpine",
		Push: &buildImagePushSpec{
			Registry: "ghcr.io/x/y", Username: "u", Password: "p",
		},
	})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
	if rr.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504; body=%s", rr.Code, rr.Body.String())
	}
}

func TestBuildImageExistsCheckError(t *testing.T) {
	builder := &fakeImageBuilder{existsErr: errors.New("daemon down")}
	mux := newTestMux(builder, BuildConfig{})
	body := `{"dockerfile_content":"FROM alpine\nRUN echo hi"}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(body)))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
}

func TestBuildContextWithTimeoutZeroUsesCancelOnly(t *testing.T) {
	ctx, cancel := buildContextWithTimeout(context.Background(), 0)
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("zero timeout should not set deadline")
	}
}

var errPushBoom = pushBoomErr{}

type pushBoomErr struct{}

func (pushBoomErr) Error() string { return "boom" }

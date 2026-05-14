package v2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/docker"
)

type fakeImageBuilder struct {
	exists   map[string]bool
	builds   []docker.BuildImageRequest
	buildErr error
}

func (f *fakeImageBuilder) ImageExists(_ context.Context, ref string) (bool, error) {
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
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v2/images/build", strings.NewReader(string(body))))

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
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v2/images/build", strings.NewReader(string(body))))

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
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v2/images/build", strings.NewReader(string(body))))
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
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v2/images/build", strings.NewReader(string(body))))
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
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v2/images/build", strings.NewReader(string(body))))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

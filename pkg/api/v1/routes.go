package v1

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/docker"
)

// ImageBuilder is the slice of pkg/docker.Client v1 needs to compile an
// Image-builder graph into a content-addressed local image tag, and
// optionally push the result to a remote registry. Declared as an
// interface so the test harness can stub it without standing up a real
// Docker daemon. PushImage is v1-only — the Daytona facade interface
// deliberately omits it to keep its surface aligned with upstream Daytona.
type ImageBuilder interface {
	BuildImage(ctx context.Context, req docker.BuildImageRequest) error
	ImageExists(ctx context.Context, imageRef string) (bool, error)
	PushImage(ctx context.Context, req docker.PushImageRequest) (string, error)
	// RefreshTag bumps Docker's Metadata.LastTagTime so the built-image
	// janitor doesn't GC a tag that was just handed out from the build
	// cache. Called on the ImageExists==true short-circuit path.
	RefreshTag(ctx context.Context, fullRef string) error
}

// BuildConfig mirrors the operator-configured image-build knobs.
type BuildConfig struct {
	ContextEnabled bool
	Timeout        time.Duration
}

// Deps holds the shared dependencies a version package needs from the
// top-level pkg/api router. Keeping these explicit (rather than reaching into
// pkg/api globals) lets future version packages coexist without coupling.
type Deps struct {
	Service *service.Service
	Logger  *slog.Logger
	// Auth wraps each handler with bearer-token auth. The middleware lives in
	// pkg/api so all versions share one auth contract; the version package
	// only decides which routes need it.
	Auth func(http.Handler) http.Handler
	// Builder is optional. When nil, POST /v1/images/build responds 503.
	Builder ImageBuilder
	Build   BuildConfig
}

// RegisterRoutes mounts every v1 route onto mux. Paths are written with the
// PathPrefix already baked in so this file is the single grep target for
// "what does v1 expose?".
func RegisterRoutes(mux *http.ServeMux, d Deps) {
	h := &handlers{deps: d}

	mux.Handle("GET "+PathPrefix+"/capacity", d.Auth(http.HandlerFunc(h.capacity)))
	mux.Handle("POST "+PathPrefix+"/admin/reconcile", d.Auth(http.HandlerFunc(h.reconcile)))
	mux.Handle("POST "+PathPrefix+"/images/build", d.Auth(http.HandlerFunc(h.buildImage)))

	mux.Handle("POST "+PathPrefix+"/sandboxes", d.Auth(http.HandlerFunc(h.createSandbox)))
	mux.Handle("GET "+PathPrefix+"/sandboxes", d.Auth(http.HandlerFunc(h.listSandboxes)))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}", d.Auth(http.HandlerFunc(h.getSandbox)))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/start", d.Auth(http.HandlerFunc(h.startSandbox)))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/stop", d.Auth(http.HandlerFunc(h.stopSandbox)))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/snapshot", d.Auth(http.HandlerFunc(h.createSnapshot)))
	mux.Handle("DELETE "+PathPrefix+"/sandboxes/{id}", d.Auth(http.HandlerFunc(h.destroySandbox)))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/resize", d.Auth(http.HandlerFunc(h.resizeSandbox)))
	mux.Handle("PUT "+PathPrefix+"/sandboxes/{id}/lifecycle", d.Auth(http.HandlerFunc(h.updateLifecycle)))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/ports/{port}", d.Auth(http.HandlerFunc(h.exposePort)))
	mux.Handle("DELETE "+PathPrefix+"/sandboxes/{id}/ports/{port}", d.Auth(http.HandlerFunc(h.unexposePort)))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/mounts", d.Auth(http.HandlerFunc(h.listMounts)))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/network/usage", d.Auth(http.HandlerFunc(h.getNetworkUsage)))
	mux.Handle("PATCH "+PathPrefix+"/sandboxes/{id}/network/limits", d.Auth(http.HandlerFunc(h.updateNetworkLimits)))

	// Explicit session routes are syntactic sugar for the toolbox proxy:
	// /v1/sandboxes/{id}/sessions/... → toolbox /sessions/...
	mux.Handle(PathPrefix+"/sandboxes/{id}/sessions", d.Auth(http.HandlerFunc(h.sessionsProxy)))
	mux.Handle(PathPrefix+"/sandboxes/{id}/sessions/{path...}", d.Auth(http.HandlerFunc(h.sessionsProxy)))
	mux.Handle(PathPrefix+"/sandboxes/{id}/toolbox", d.Auth(http.HandlerFunc(h.toolboxProxy)))
	mux.Handle(PathPrefix+"/sandboxes/{id}/toolbox/{path...}", d.Auth(http.HandlerFunc(h.toolboxProxy)))
}

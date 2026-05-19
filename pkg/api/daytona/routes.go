package daytona

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/docker"
)

const (
	PathPrefix    = "/daytona"
	ToolboxPrefix = PathPrefix + "/toolbox"
)

// ImageBuilder is the slice of pkg/docker.Client the facade needs to turn a
// Dockerfile into a runnable image. Declared as an interface so the test
// harness can stub it without standing up a real Docker daemon.
type ImageBuilder interface {
	BuildImage(ctx context.Context, req docker.BuildImageRequest) error
	ImageExists(ctx context.Context, imageRef string) (bool, error)
	RemoveImage(ctx context.Context, imageRef string) error
	// RefreshTag bumps Docker's Metadata.LastTagTime so the built-image
	// janitor doesn't GC a tag we just handed back from the cache. Called
	// on the ImageExists==true short-circuit in resolveBuildInfo.
	RefreshTag(ctx context.Context, fullRef string) error
}

// BuildConfig surfaces the operator-configured image-build knobs through to
// the facade. Mirrors the corresponding fields on internal/config.Config —
// kept narrow so the package doesn't take a dep on internal/config.
type BuildConfig struct {
	ContextEnabled bool
	Timeout        time.Duration
}

// Deps are the shared dependencies the Daytona facade needs from the
// top-level API package.
type Deps struct {
	Service *service.Service
	Logger  *slog.Logger
	Auth    func(http.Handler) http.Handler
	// Builder is optional. When nil, multi-line Dockerfile builds are
	// rejected at the handler with a 400 — the legacy single-line `FROM`
	// fast-path still works (it doesn't need a builder).
	Builder ImageBuilder
	Build   BuildConfig
}

// RegisterRoutes mounts the supported Daytona compatibility surface.
func RegisterRoutes(mux *http.ServeMux, d Deps) {
	h := newHandlers(d)

	mux.Handle("POST "+PathPrefix+"/sandbox", d.Auth(http.HandlerFunc(h.createSandbox)))
	mux.Handle("POST "+PathPrefix+"/snapshots", d.Auth(http.HandlerFunc(h.createSnapshotFromImage)))
	mux.Handle("GET "+PathPrefix+"/snapshots", d.Auth(http.HandlerFunc(h.listSnapshots)))
	mux.Handle("GET "+PathPrefix+"/snapshots/{id}", d.Auth(http.HandlerFunc(h.getSnapshot)))
	mux.Handle("DELETE "+PathPrefix+"/snapshots/{id}", d.Auth(http.HandlerFunc(h.deleteSnapshot)))
	mux.Handle("GET "+PathPrefix+"/sandbox", d.Auth(http.HandlerFunc(h.listSandboxes)))
	mux.Handle("GET "+PathPrefix+"/sandbox/paginated", d.Auth(http.HandlerFunc(h.listSandboxesPaginated)))
	mux.Handle("GET "+PathPrefix+"/sandbox/{idOrName}", d.Auth(h.clusterForwardWrap("idOrName", http.HandlerFunc(h.getSandbox))))
	mux.Handle("DELETE "+PathPrefix+"/sandbox/{idOrName}", d.Auth(h.clusterForwardWrap("idOrName", http.HandlerFunc(h.destroySandbox))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/start", d.Auth(h.clusterForwardWrap("idOrName", http.HandlerFunc(h.startSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/stop", d.Auth(h.clusterForwardWrap("idOrName", http.HandlerFunc(h.stopSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/snapshot", d.Auth(h.clusterForwardWrap("idOrName", http.HandlerFunc(h.createSnapshot))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/resize", d.Auth(h.clusterForwardWrap("idOrName", http.HandlerFunc(h.resizeSandbox))))
	mux.Handle("GET "+PathPrefix+"/sandbox/{id}/toolbox-proxy-url", d.Auth(h.clusterForwardWrap("id", http.HandlerFunc(h.toolboxProxyURL))))
	mux.Handle("GET "+PathPrefix+"/sandbox/{idOrName}/ports/{port}/preview-url", d.Auth(h.clusterForwardWrap("idOrName", http.HandlerFunc(h.previewURL))))
	mux.Handle("PUT "+PathPrefix+"/sandbox/{idOrName}/labels", d.Auth(h.clusterForwardWrap("idOrName", http.HandlerFunc(h.replaceLabels))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/autostop/{interval}", d.Auth(h.clusterForwardWrap("idOrName", http.HandlerFunc(h.setAutoStopInterval))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/autodelete/{interval}", d.Auth(h.clusterForwardWrap("idOrName", http.HandlerFunc(h.setAutoDeleteInterval))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/autoarchive/{interval}", d.Auth(h.clusterForwardWrap("idOrName", http.HandlerFunc(h.setAutoArchiveInterval))))

	mux.Handle(ToolboxPrefix+"/{id}", d.Auth(h.clusterForwardWrap("id", http.HandlerFunc(h.toolbox))))
	mux.Handle(ToolboxPrefix+"/{id}/{path...}", d.Auth(h.clusterForwardWrap("id", http.HandlerFunc(h.toolbox))))

	// Volumes — the Daytona SDK probes these five routes when callers use
	// daytona.volume.{list,get,create,delete}. The facade has no volume
	// backend yet; respond with 405 so clients see a clear "recognized but
	// not implemented" signal rather than a 404 they'd retry through.
	mux.Handle("GET "+PathPrefix+"/volumes", d.Auth(http.HandlerFunc(volumesNotSupported)))
	mux.Handle("POST "+PathPrefix+"/volumes", d.Auth(http.HandlerFunc(volumesNotSupported)))
	mux.Handle("GET "+PathPrefix+"/volumes/{volumeId}", d.Auth(http.HandlerFunc(volumesNotSupported)))
	mux.Handle("DELETE "+PathPrefix+"/volumes/{volumeId}", d.Auth(http.HandlerFunc(volumesNotSupported)))
	mux.Handle("GET "+PathPrefix+"/volumes/by-name/{name}", d.Auth(http.HandlerFunc(volumesNotSupported)))
}

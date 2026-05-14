package daytona

import (
	"log/slog"
	"net/http"

	"github.com/aerol-ai/microvm/internal/service"
)

const (
	PathPrefix    = "/daytona"
	ToolboxPrefix = PathPrefix + "/toolbox"
)

// Deps are the shared dependencies the Daytona facade needs from the
// top-level API package.
type Deps struct {
	Service *service.Service
	Logger  *slog.Logger
	Auth    func(http.Handler) http.Handler
}

// RegisterRoutes mounts the supported Daytona compatibility surface.
func RegisterRoutes(mux *http.ServeMux, d Deps) {
	h := newHandlers(d)

	mux.Handle("POST "+PathPrefix+"/sandbox", d.Auth(http.HandlerFunc(h.createSandbox)))
	mux.Handle("GET "+PathPrefix+"/sandbox", d.Auth(http.HandlerFunc(h.listSandboxes)))
	mux.Handle("GET "+PathPrefix+"/sandbox/paginated", d.Auth(http.HandlerFunc(h.listSandboxesPaginated)))
	mux.Handle("GET "+PathPrefix+"/sandbox/{idOrName}", d.Auth(http.HandlerFunc(h.getSandbox)))
	mux.Handle("DELETE "+PathPrefix+"/sandbox/{idOrName}", d.Auth(http.HandlerFunc(h.destroySandbox)))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/start", d.Auth(http.HandlerFunc(h.startSandbox)))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/stop", d.Auth(http.HandlerFunc(h.stopSandbox)))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/snapshot", d.Auth(http.HandlerFunc(h.createSnapshot)))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/resize", d.Auth(http.HandlerFunc(h.resizeSandbox)))
	mux.Handle("GET "+PathPrefix+"/sandbox/{id}/toolbox-proxy-url", d.Auth(http.HandlerFunc(h.toolboxProxyURL)))
	mux.Handle("GET "+PathPrefix+"/sandbox/{idOrName}/ports/{port}/preview-url", d.Auth(http.HandlerFunc(h.previewURL)))
	mux.Handle("PUT "+PathPrefix+"/sandbox/{idOrName}/labels", d.Auth(http.HandlerFunc(h.replaceLabels)))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/autostop/{interval}", d.Auth(http.HandlerFunc(h.setAutoStopInterval)))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/autodelete/{interval}", d.Auth(http.HandlerFunc(h.setAutoDeleteInterval)))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/autoarchive/{interval}", d.Auth(http.HandlerFunc(h.setAutoArchiveInterval)))

	mux.Handle(ToolboxPrefix+"/{id}", d.Auth(http.HandlerFunc(h.toolbox)))
	mux.Handle(ToolboxPrefix+"/{id}/{path...}", d.Auth(http.HandlerFunc(h.toolbox)))
}

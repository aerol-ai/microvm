package v1

import (
	"log/slog"
	"net/http"

	"github.com/aerol-ai/microvm/internal/service"
)

// Deps holds the shared dependencies a version package needs from the
// top-level pkg/api router. Keeping these explicit (rather than reaching into
// pkg/api globals) is what lets pkg/api/v2 coexist later without coupling.
type Deps struct {
	Service *service.Service
	Logger  *slog.Logger
	// Auth wraps each handler with bearer-token auth. The middleware lives in
	// pkg/api so all versions share one auth contract; the version package
	// only decides which routes need it.
	Auth func(http.Handler) http.Handler
}

// RegisterRoutes mounts every v1 route onto mux. Paths are written with the
// PathPrefix already baked in so this file is the single grep target for
// "what does v1 expose?".
func RegisterRoutes(mux *http.ServeMux, d Deps) {
	h := &handlers{deps: d}

	mux.Handle("GET "+PathPrefix+"/capacity", d.Auth(http.HandlerFunc(h.capacity)))
	mux.Handle("POST "+PathPrefix+"/admin/reconcile", d.Auth(http.HandlerFunc(h.reconcile)))

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

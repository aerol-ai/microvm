package e2b

import (
	"github.com/aerol-ai/microvm/pkg/api/clusterroute"
	"log/slog"
	"net/http"

	"github.com/aerol-ai/microvm/internal/service"
)

const PathPrefix = "/e2b"

// Deps are the shared dependencies the E2B facade needs from the top-level
// API package.
type Deps struct {
	Service *service.Service
	Logger  *slog.Logger
	Auth    func(http.Handler) http.Handler
}

// RegisterRoutes mounts the supported E2B control-plane compatibility surface.
func RegisterRoutes(mux *http.ServeMux, d Deps) {
	h := newHandlers(d)

	mux.Handle("POST "+PathPrefix+"/sandboxes", d.Auth(http.HandlerFunc(h.createSandbox)))
	mux.Handle("GET "+PathPrefix+"/sandboxes", d.Auth(http.HandlerFunc(h.listSandboxes)))
	mux.Handle("GET "+PathPrefix+"/v2/sandboxes", d.Auth(http.HandlerFunc(h.listSandboxes)))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}", d.Auth(h.clusterForwardWrap(http.HandlerFunc(h.getSandbox))))
	mux.Handle("DELETE "+PathPrefix+"/sandboxes/{id}", d.Auth(h.clusterForwardWrap(http.HandlerFunc(h.deleteSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/connect", d.Auth(h.clusterForwardWrap(http.HandlerFunc(h.connectSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/pause", d.Auth(h.clusterForwardWrap(http.HandlerFunc(h.pauseSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/timeout", d.Auth(h.clusterForwardWrap(http.HandlerFunc(h.updateTimeout))))
	mux.Handle("PUT "+PathPrefix+"/sandboxes/{id}/network", d.Auth(h.clusterForwardWrap(http.HandlerFunc(h.updateNetwork))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/snapshots", d.Auth(h.clusterForwardWrap(http.HandlerFunc(h.createSnapshot))))
	mux.Handle("GET "+PathPrefix+"/snapshots", d.Auth(http.HandlerFunc(h.listSnapshots)))
	mux.Handle("DELETE "+PathPrefix+"/templates/{id}", d.Auth(http.HandlerFunc(h.deleteSnapshot)))
	// /runtime carries its sandbox id in the E2b-Sandbox-Id header, not a
	// path value, so it forwards to the owner node by that header (plan B5).
	// Unauthenticated like the rest of /runtime: the envd token guards it.
	runtimeForward := clusterroute.Wrap(h.deps.Service, clusterroute.Options{
		ID:         func(r *http.Request) string { return r.Header.Get("E2b-Sandbox-Id") },
		WriteError: WriteError,
	}, http.HandlerFunc(h.runtimeProxy))
	mux.Handle(PathPrefix+"/runtime", runtimeForward)
	mux.Handle(PathPrefix+"/runtime/", runtimeForward)
}

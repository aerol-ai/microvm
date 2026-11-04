package e2b

import (
	"log/slog"
	"net/http"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clusterroute"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

const PathPrefix = "/e2b"

// RuntimePath is the envd runtime proxy. It is the one /e2b route with no
// API principal: the sandbox's own envd token guards it (and nothing does
// when the caller created the sandbox with secure:false), so it sits on the
// registry test's public allowlist.
const RuntimePath = PathPrefix + "/runtime"

// Deps are the shared dependencies the E2B facade needs from the top-level
// API package.
type Deps struct {
	Service *service.Service
	Logger  *slog.Logger
	// Auth authenticates a request with the E2B credential headers
	// (pkg/api). Routes never call it directly: Route composes it with the
	// permission check.
	Auth func(http.Handler) http.Handler
	// Audit is the seam task T5 fills with kind "api" records
	// (apihttp.AuditHook). nil records nothing.
	Audit apihttp.AuditHook
	// TemplateMapJSON maps template ids → images (SB_E2B_TEMPLATE_MAP_JSON),
	// ClientID is the client id the SDK echoes (SB_E2B_CLIENT_ID). Both are
	// read once in config; the facade parses TemplateMapJSON and applies its
	// own defaults.
	TemplateMapJSON string
	ClientID        string
	// ListGate bounds the cluster-wide lists this node runs at once
	// (clusterlist.Admit); nil admits every list. One gate is shared by v1
	// and every facade: they cost the same fan-out.
	ListGate *apihttp.Gate
}

// Route returns h behind authenticate → authorize(perm) → audit seam
// (plans/identity-and-access.md §5.3).
func (d Deps) Route(perm controlplane.Permission, h http.Handler) http.Handler {
	return apihttp.Router{Authenticate: d.Auth, Deny: writeForbidden, Audit: d.Audit}.Route(perm, h)
}

// writeForbidden keeps E2B's {"code", "message"} body; a token or OIDC
// caller's D9 hint rides in the message.
func writeForbidden(w http.ResponseWriter, _ *http.Request, d apihttp.Denial) {
	WriteError(w, http.StatusForbidden, d.Message())
}

const (
	permRead  = controlplane.PermSandboxRead
	permWrite = controlplane.PermSandboxWrite
	permExec  = controlplane.PermSandboxExec
)

// RegisterRoutes mounts the supported E2B control-plane compatibility surface.
func RegisterRoutes(mux apihttp.Mux, d Deps) {
	h := newHandlers(d)

	mux.Handle("POST "+PathPrefix+"/sandboxes", d.Route(permWrite, http.HandlerFunc(h.createSandbox)))
	mux.Handle("GET "+PathPrefix+"/sandboxes", d.Route(permRead, http.HandlerFunc(h.listSandboxes)))
	mux.Handle("GET "+PathPrefix+"/v2/sandboxes", d.Route(permRead, http.HandlerFunc(h.listSandboxes)))
	// The detail carries the envd access token, which opens the toolbox; a
	// caller without sandbox.exec gets the detail without it.
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}", d.Route(permRead, h.clusterForwardWrap(http.HandlerFunc(h.getSandbox))))
	mux.Handle("DELETE "+PathPrefix+"/sandboxes/{id}", d.Route(permWrite, h.clusterForwardWrap(http.HandlerFunc(h.deleteSandbox))))
	// Connect resumes the sandbox and hands back the envd token so the SDK
	// can run commands in it: sandbox.exec.
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/connect", d.Route(permExec, h.clusterForwardWrap(http.HandlerFunc(h.connectSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/pause", d.Route(permWrite, h.clusterForwardWrap(http.HandlerFunc(h.pauseSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/timeout", d.Route(permWrite, h.clusterForwardWrap(http.HandlerFunc(h.updateTimeout))))
	mux.Handle("PUT "+PathPrefix+"/sandboxes/{id}/network", d.Route(permWrite, h.clusterForwardWrap(http.HandlerFunc(h.updateNetwork))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/snapshots", d.Route(permWrite, h.clusterForwardWrap(http.HandlerFunc(h.createSnapshot))))
	mux.Handle("GET "+PathPrefix+"/snapshots", d.Route(permRead, http.HandlerFunc(h.listSnapshots)))
	mux.Handle("DELETE "+PathPrefix+"/templates/{id}", d.Route(permWrite, h.snapshotForwardWrap(http.HandlerFunc(h.deleteSnapshot))))
	// /runtime carries its sandbox id in the E2b-Sandbox-Id header, not a
	// path value, so it forwards to the owner node by that header (plan B5).
	// Unauthenticated like the rest of /runtime: the envd token guards it.
	runtimeForward := clusterroute.Wrap(h.deps.Service, clusterroute.Options{
		ID:         func(r *http.Request) string { return r.Header.Get("E2b-Sandbox-Id") },
		WriteError: WriteError,
	}, http.HandlerFunc(h.runtimeProxy))
	mux.Handle(RuntimePath, runtimeForward)
	mux.Handle(RuntimePath+"/", runtimeForward)
}

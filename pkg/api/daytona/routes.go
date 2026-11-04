package daytona

import (
	"log/slog"
	"net/http"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
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
	// Auth authenticates a request (pkg/api). Routes never call it
	// directly: Route composes it with the permission check.
	Auth func(http.Handler) http.Handler
	// Audit is the seam task T5 fills with kind "api" records
	// (apihttp.AuditHook). nil records nothing.
	Audit apihttp.AuditHook
	// ContainerEngine selects BuildKit-absent clear errors on containerd hosts.
	ContainerEngine string
	// DefaultImage is the image a create falls back to when the request names
	// neither a snapshot nor a build (SB_DAYTONA_DEFAULT_IMAGE, read once in
	// config). Empty falls back to the built-in default.
	DefaultImage string
	// ListGate bounds the cluster-wide lists this node runs at once
	// (clusterlist.Admit); nil admits every list. One gate is shared by v1
	// and every facade: they cost the same fan-out.
	ListGate *apihttp.Gate
}

// Route returns h behind authenticate → authorize(perm) → audit seam
// (plans/identity-and-access.md §5.3).
func (d Deps) Route(perm controlplane.Permission, h http.Handler) http.Handler {
	return d.router().Route(perm, h)
}

// RouteBy is Route for a route whose permission depends on the request.
func (d Deps) RouteBy(tag string, classify func(*http.Request) controlplane.Permission, h http.Handler) http.Handler {
	return d.router().RouteBy(tag, classify, h)
}

func (d Deps) router() apihttp.Router {
	return apihttp.Router{Authenticate: d.Auth, Deny: writeForbidden, Audit: d.Audit}
}

// writeForbidden keeps the facade's own {"error": …} body; a token or OIDC
// caller's D9 hint rides in the message, with no extra fields.
func writeForbidden(w http.ResponseWriter, _ *http.Request, d apihttp.Denial) {
	apihttp.WriteError(w, http.StatusForbidden, d.Message())
}

const (
	permRead  = controlplane.PermSandboxRead
	permWrite = controlplane.PermSandboxWrite
	permExec  = controlplane.PermSandboxExec
)

// RegisterRoutes mounts the supported Daytona compatibility surface.
func RegisterRoutes(mux apihttp.Mux, d Deps) {
	h := newHandlers(d)

	mux.Handle("POST "+PathPrefix+"/sandbox", d.Route(permWrite, http.HandlerFunc(h.createSandbox)))
	mux.Handle("POST "+PathPrefix+"/snapshots", d.Route(permWrite, http.HandlerFunc(h.createSnapshotFromImage)))
	mux.Handle("GET "+PathPrefix+"/snapshots", d.Route(permRead, http.HandlerFunc(h.listSnapshots)))
	mux.Handle("GET "+PathPrefix+"/snapshots/{id}", d.Route(permRead, h.snapshotForwardWrap(http.HandlerFunc(h.getSnapshot))))
	mux.Handle("DELETE "+PathPrefix+"/snapshots/{id}", d.Route(permWrite, h.snapshotForwardWrap(http.HandlerFunc(h.deleteSnapshot))))
	mux.Handle("GET "+PathPrefix+"/sandbox", d.Route(permRead, http.HandlerFunc(h.listSandboxes)))
	mux.Handle("GET "+PathPrefix+"/sandbox/paginated", d.Route(permRead, http.HandlerFunc(h.listSandboxesPaginated)))
	// A get returns env only with include_env (audited), which needs
	// sandbox.secrets.
	mux.Handle("GET "+PathPrefix+"/sandbox/{idOrName}", d.RouteBy(apihttp.ReadOrSecretsTag, apihttp.ReadOrSecrets, h.clusterForwardWrap("idOrName", http.HandlerFunc(h.getSandbox))))
	mux.Handle("DELETE "+PathPrefix+"/sandbox/{idOrName}", d.Route(permWrite, h.clusterForwardWrap("idOrName", http.HandlerFunc(h.destroySandbox))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/start", d.Route(permWrite, h.clusterForwardWrap("idOrName", http.HandlerFunc(h.startSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/stop", d.Route(permWrite, h.clusterForwardWrap("idOrName", http.HandlerFunc(h.stopSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/snapshot", d.Route(permWrite, h.clusterForwardWrap("idOrName", http.HandlerFunc(h.createSnapshot))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/resize", d.Route(permWrite, h.clusterForwardWrap("idOrName", http.HandlerFunc(h.resizeSandbox))))
	// The proxy URL is only an address; every call through it is a toolbox
	// call, which needs sandbox.exec.
	mux.Handle("GET "+PathPrefix+"/sandbox/{id}/toolbox-proxy-url", d.Route(permRead, h.clusterForwardWrap("id", http.HandlerFunc(h.toolboxProxyURL))))
	// A preview URL exposes the port (Service.ExposePort), so it is a write
	// even though the SDK calls it with GET.
	mux.Handle("GET "+PathPrefix+"/sandbox/{idOrName}/ports/{port}/preview-url", d.Route(permWrite, h.clusterForwardWrap("idOrName", http.HandlerFunc(h.previewURL))))
	mux.Handle("PUT "+PathPrefix+"/sandbox/{idOrName}/labels", d.Route(permWrite, h.clusterForwardWrap("idOrName", http.HandlerFunc(h.replaceLabels))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/autostop/{interval}", d.Route(permWrite, h.clusterForwardWrap("idOrName", http.HandlerFunc(h.setAutoStopInterval))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/autodelete/{interval}", d.Route(permWrite, h.clusterForwardWrap("idOrName", http.HandlerFunc(h.setAutoDeleteInterval))))
	mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/autoarchive/{interval}", d.Route(permWrite, h.clusterForwardWrap("idOrName", http.HandlerFunc(h.setAutoArchiveInterval))))

	// The toolbox proxy is one permission whatever the sub-path.
	mux.Handle(ToolboxPrefix+"/{id}", d.Route(permExec, h.clusterForwardWrap("id", http.HandlerFunc(h.toolbox))))
	mux.Handle(ToolboxPrefix+"/{id}/{path...}", d.Route(permExec, h.clusterForwardWrap("id", http.HandlerFunc(h.toolbox))))

	// Volumes — first-class platform volumes backed by the operator's shared
	// storage (plans/e2b-volume-mounts.md). The handlers gate on whether the
	// operator enabled platform volumes (412 when off), so the SDK still gets a
	// clear signal on deployments that haven't configured a backend.
	// Volume metadata is replicated through the cluster FSM (or local SQLite in
	// single-node mode), so any node answers these consistently — no per-tenant
	// owner routing needed.
	mux.Handle("GET "+PathPrefix+"/volumes", d.Route(permRead, http.HandlerFunc(h.listVolumes)))
	mux.Handle("POST "+PathPrefix+"/volumes", d.Route(permWrite, http.HandlerFunc(h.createVolume)))
	mux.Handle("GET "+PathPrefix+"/volumes/{volumeId}", d.Route(permRead, http.HandlerFunc(h.getVolume)))
	mux.Handle("DELETE "+PathPrefix+"/volumes/{volumeId}", d.Route(permWrite, http.HandlerFunc(h.deleteVolume)))
	mux.Handle("GET "+PathPrefix+"/volumes/by-name/{name}", d.Route(permRead, http.HandlerFunc(h.getVolumeByName)))
}

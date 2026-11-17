package v1

import (
	"errors"
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"

	"github.com/aerol-ai/microvm/internal/service"
)

func (h *handlers) toolboxProxy(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	if path == "" {
		path = "/"
	} else {
		path = "/" + path
	}
	h.proxyToToolbox(w, r, path)
}

// sessionsProxy is sugar for /v1/sandboxes/{id}/sessions[/...] —
// rewrites to /sessions[/...] on the toolbox. WebSocket upgrades pass through
// transparently because httputil.ReverseProxy forwards Upgrade headers.
func (h *handlers) sessionsProxy(w http.ResponseWriter, r *http.Request) {
	// A node bridges an SSH session as itself only for the sandbox's key
	// (service/ssh_bridge_key.go).
	if access, ok := controlplane.AccessFromContext(r.Context()); ok && access.NodeLimited() {
		call, _ := auditlog.SSHGatewayCallFromContext(r.Context())
		if err := h.deps.Service.CheckSSHBridgeKey(r.Context(), r.PathValue("id"), call.KeyFingerprint); err != nil {
			if errors.Is(err, service.ErrSSHBridgeKey) {
				apihttp.WriteError(w, http.StatusForbidden, err.Error())
				return
			}
			apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
			return
		}
	}
	rest := r.PathValue("path")
	target := "/sessions"
	if rest != "" {
		target = "/sessions/" + rest
	}
	h.proxyToToolbox(w, r, target)
}

func (h *handlers) proxyToToolbox(w http.ResponseWriter, r *http.Request, path string) {
	ctx := service.WithToolboxSurface(r.Context(), service.ToolboxSurfaceV1)
	if err := h.deps.Service.ServeToolboxReverseProxy(ctx, r.PathValue("id"), w, r, path); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
	}
}

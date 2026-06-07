package v1

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
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
	rest := r.PathValue("path")
	target := "/sessions"
	if rest != "" {
		target = "/sessions/" + rest
	}
	h.proxyToToolbox(w, r, target)
}

func (h *handlers) proxyToToolbox(w http.ResponseWriter, r *http.Request, path string) {
	if err := h.deps.Service.ServeToolboxReverseProxy(r.Context(), r.PathValue("id"), w, r, path); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
	}
}

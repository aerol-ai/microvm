package v1

import (
	"net/http"
	"net/http/httputil"
	"net/url"

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
	endpoint, err := h.deps.Service.WakeAwareToolboxTarget(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	target, err := url.Parse(endpoint.URL)
	if err != nil {
		apihttp.WriteError(w, http.StatusInternalServerError, "invalid toolbox target")
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	toolboxToken := endpoint.Token
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.URL.Path = path
		req.Host = target.Host
		if toolboxToken != "" {
			req.Header.Set("Authorization", "Bearer "+toolboxToken)
		}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		apihttp.WriteError(w, http.StatusBadGateway, "toolbox unavailable")
	}
	proxy.ServeHTTP(w, r)
}

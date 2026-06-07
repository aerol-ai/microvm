package e2b

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

const runtimeProxyPrefix = PathPrefix + "/runtime"

func (h *handlers) runtimeProxy(w http.ResponseWriter, r *http.Request) {
	sandboxID := strings.TrimSpace(r.Header.Get("E2b-Sandbox-Id"))
	if sandboxID == "" {
		WriteError(w, http.StatusBadRequest, "Missing E2b-Sandbox-Id header")
		return
	}

	sandbox, err := h.deps.Service.GetSandbox(r.Context(), sandboxID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "Sandbox not found")
			return
		}
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	meta, err := h.loadSandboxMeta(r.Context(), sandbox)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	if meta.Secure {
		accessToken := strings.TrimSpace(r.Header.Get("X-Access-Token"))
		if accessToken == "" || accessToken != sandbox.ToolboxToken {
			WriteError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
	}

	publicPath := strings.TrimPrefix(r.URL.Path, runtimeProxyPrefix)
	if publicPath == "" {
		publicPath = "/"
	}
	if !strings.HasPrefix(publicPath, "/") {
		publicPath = "/" + publicPath
	}
	toolboxPath := "/envd" + publicPath

	userAuthorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(userAuthorization, "Basic ") {
		r.Header.Set("X-E2B-User-Authorization", userAuthorization)
	} else {
		r.Header.Del("X-E2B-User-Authorization")
	}
	r.Header.Set("X-E2B-Sandbox-Id", sandboxID)

	if sandbox.Runtime == models.RuntimeWasm {
		if err := h.deps.Service.ServeToolboxReverseProxy(r.Context(), sandboxID, w, r, toolboxPath); err != nil {
			writeStoreAwareError(h.deps.Logger, w, err)
		}
		return
	}

	endpoint, err := h.deps.Service.WakeAwareToolboxTarget(r.Context(), sandboxID)
	if err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	target, err := url.Parse(endpoint.URL)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "Invalid toolbox target")
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	toolboxToken := endpoint.Token
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.URL.Path = toolboxPath
		req.Host = target.Host
		req.Header.Set("X-E2B-Sandbox-Id", sandboxID)
		if strings.HasPrefix(userAuthorization, "Basic ") {
			req.Header.Set("X-E2B-User-Authorization", userAuthorization)
		} else {
			req.Header.Del("X-E2B-User-Authorization")
		}
		if toolboxToken != "" {
			req.Header.Set("Authorization", "Bearer "+toolboxToken)
		} else {
			req.Header.Del("Authorization")
		}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		WriteError(w, http.StatusBadGateway, "Sandbox runtime unavailable")
	}
	proxy.ServeHTTP(w, r)
}

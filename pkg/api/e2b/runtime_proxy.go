package e2b

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/toolboxhttp"
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
		// The access token is this route's only credential (envd has no
		// platform auth), so compare it in constant time.
		accessToken := strings.TrimSpace(r.Header.Get("X-Access-Token"))
		if accessToken == "" || subtle.ConstantTimeCompare([]byte(accessToken), []byte(sandbox.ToolboxToken)) != 1 {
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

	// Registered before the wake reads the sandbox's row, so a stop or
	// destroy while envd works ends the request at once instead of when
	// the connection times out (service/toolbox_calls.go).
	callCtx, release := h.deps.Service.TrackToolboxCall(r.Context(), sandboxID)
	defer release()
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
	// The shared toolbox transport: no connection pooled past its sandbox,
	// and a dead sandbox noticed within the dead-peer bound.
	proxy.Transport = toolboxhttp.Transport
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
	// A sandbox that stopped under the request keeps E2B's 502: the E2B SDK
	// reads 502 from envd as "the sandbox was not found" (Connect's
	// unavailable), its own signal for a sandbox that is gone, where a 409
	// would surface as an unknown error.
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if stopped := service.ToolboxCallEnded(r.Context()); stopped != nil && h.deps.Logger != nil {
			h.deps.Logger.Info("e2b runtime request ended: sandbox stopped", "sandbox_id", sandboxID, "error", stopped)
		}
		WriteError(w, http.StatusBadGateway, "Sandbox runtime unavailable")
	}
	proxy.ServeHTTP(w, r.WithContext(callCtx))
}

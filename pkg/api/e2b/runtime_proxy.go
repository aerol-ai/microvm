package e2b

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/aerol-ai/microvm/internal/observability"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/toolboxhttp"
)

const runtimeProxyPrefix = PathPrefix + "/runtime"

// The E2B SDKs reach every in-sandbox server through E2B_SANDBOX_URL and
// name the sandbox port in a header; the code-interpreter SDKs use port
// 49999, envd is everything else. toolboxd serves the interpreter under
// interpreterToolboxPrefix (plans/code-interpreter.md D7).
const (
	sandboxPortHeader        = "E2b-Sandbox-Port"
	interpreterPort          = "49999"
	interpreterToolboxPrefix = "/interpreter/e2b"
)

// runtimeTokenHeaders are the headers that may carry the sandbox's access
// token. The interpreter SDKs send X-Access-Token only on /execute and the
// traffic token on every call, so either one admits a request.
var runtimeTokenHeaders = []string{"X-Access-Token", "E2B-Traffic-Access-Token"}

// runtimeTokenOK reports whether r carries the sandbox's toolbox token in
// any token header. The token is this route's only credential (envd has no
// platform auth), so each compare is constant time.
func runtimeTokenOK(r *http.Request, want string) bool {
	for _, header := range runtimeTokenHeaders {
		got := strings.TrimSpace(r.Header.Get(header))
		if got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

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
	if meta.Secure && !runtimeTokenOK(r, sandbox.ToolboxToken) {
		WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	interpreter := strings.TrimSpace(r.Header.Get(sandboxPortHeader)) == interpreterPort
	if interpreter && sandbox.Runtime == models.RuntimeIsolate {
		// An isolate runs one tenant fetch handler and no interpreters
		// (plans/code-interpreter.md D9): say so plainly instead of letting
		// the SDK read an unrelated proxy failure.
		WriteError(w, http.StatusNotImplemented, "code interpreter is not supported on V8 isolate sandboxes")
		return
	}

	publicPath := strings.TrimPrefix(r.URL.Path, runtimeProxyPrefix)
	if publicPath == "" {
		publicPath = "/"
	}
	if !strings.HasPrefix(publicPath, "/") {
		publicPath = "/" + publicPath
	}
	toolboxPath := "/envd" + publicPath
	if interpreter {
		toolboxPath = interpreterToolboxPrefix + publicPath
	}

	userAuthorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(userAuthorization, "Basic ") {
		r.Header.Set("X-E2B-User-Authorization", userAuthorization)
	} else {
		r.Header.Del("X-E2B-User-Authorization")
	}
	r.Header.Set("X-E2B-Sandbox-Id", sandboxID)
	r = r.WithContext(service.WithToolboxSurface(r.Context(), service.ToolboxSurfaceE2B))

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
	// The shared toolbox proxy transport: no connection pooled past its
	// sandbox, a dead sandbox noticed within the dead-peer bound, and a dial
	// tried again while envd refuses the connection (I1).
	proxy.Transport = toolboxhttp.ProxyTransport
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
		// This proxy bypasses the service's toolbox proxy, so it sets the
		// W3C trace context toolboxd logs itself (A3).
		observability.InjectTraceContext(req.Context(), req.Header)
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
	// This proxy bypasses the service's toolbox proxy, so it counts its own
	// calls (O4).
	rec := service.NewToolboxStatusRecorder(w)
	proxy.ServeHTTP(rec, r.WithContext(callCtx))
	service.RecordToolboxCall(r.Context(), toolboxPath, rec.Status())
}

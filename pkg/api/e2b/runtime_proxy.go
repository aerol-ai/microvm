package e2b

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
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

const (
	accessTokenHeader  = "X-Access-Token"
	trafficTokenHeader = "E2B-Traffic-Access-Token"
)

// trafficAccessToken is the sandbox's E2B traffic access token. E2B treats
// it as shareable: it lets a caller reach the sandbox's ports, not envd. So
// it is not the toolbox token, which is the envd access token and runs
// commands. An HMAC keyed by the toolbox token is stable for the sandbox's
// life (create and connect hand out the same value), cannot be made
// without the toolbox token, and does not give the toolbox token away.
// A sandbox with no toolbox token gets none: the HMAC would be keyed by
// nothing.
func trafficAccessToken(sandbox *models.Sandbox) string {
	if sandbox == nil || sandbox.ToolboxToken == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(sandbox.ToolboxToken))
	mac.Write([]byte("e2b-traffic:" + sandbox.ID))
	return hex.EncodeToString(mac.Sum(nil))
}

// tokenIs compares a presented token in constant time: the tokens are this
// route's only credential (envd has no platform auth).
func tokenIs(got, want string) bool {
	return got != "" && want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// runtimeAuthorized decides whether r may reach the secure sandbox's
// runtime. The toolbox token (envd's X-Access-Token) opens every path. The
// traffic token opens only the interpreter's context routes and health
// check (trafficTokenPath): the interpreter SDKs send it alone there, and
// send X-Access-Token on /execute, which runs code, as on every envd call.
func runtimeAuthorized(r *http.Request, sandbox *models.Sandbox, interpreter bool, publicPath string) bool {
	access := strings.TrimSpace(r.Header.Get(accessTokenHeader))
	traffic := strings.TrimSpace(r.Header.Get(trafficTokenHeader))
	// The toolbox token is also taken in the traffic header: SDK sessions
	// that connected before the traffic token had its own value hold the
	// toolbox token as their traffic token, and whoever holds it could send
	// it as X-Access-Token anyway.
	if tokenIs(access, sandbox.ToolboxToken) || tokenIs(traffic, sandbox.ToolboxToken) {
		return true
	}
	return interpreter && trafficTokenPath(publicPath) && tokenIs(traffic, trafficAccessToken(sandbox))
}

// trafficTokenPath reports whether the traffic token may open publicPath on
// the interpreter port: /contexts, /contexts/{id}, /contexts/{id}/restart
// and /health. The list is closed, and a path that is not in clean form is
// refused, so no spelling of /execute gets through.
func trafficTokenPath(p string) bool {
	if path.Clean(p) != p {
		return false
	}
	if p == "/contexts" || p == "/health" {
		return true
	}
	rest, ok := strings.CutPrefix(p, "/contexts/")
	if !ok {
		return false
	}
	id, tail, _ := strings.Cut(rest, "/")
	return id != "" && (tail == "" || tail == "restart")
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
	publicPath := strings.TrimPrefix(r.URL.Path, runtimeProxyPrefix)
	if publicPath == "" {
		publicPath = "/"
	}
	if !strings.HasPrefix(publicPath, "/") {
		publicPath = "/" + publicPath
	}
	interpreter := strings.TrimSpace(r.Header.Get(sandboxPortHeader)) == interpreterPort
	if meta.Secure && !runtimeAuthorized(r, sandbox, interpreter, publicPath) {
		WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if interpreter && sandbox.Runtime == models.RuntimeIsolate {
		// An isolate runs one tenant fetch handler and no interpreters
		// (plans/code-interpreter.md D9): say so plainly instead of letting
		// the SDK read an unrelated proxy failure.
		WriteError(w, http.StatusNotImplemented, "code interpreter is not supported on V8 isolate sandboxes")
		return
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

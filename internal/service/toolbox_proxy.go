package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	pathpkg "path"
	"strings"

	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/toolboxhttp"
)

// ServeToolboxReverseProxy forwards a toolbox request to the sandbox toolbox.
// WASM sandboxes are served in-process via the driver's ToolboxHost.
func (s *Service) ServeToolboxReverseProxy(ctx context.Context, sandboxID string, w http.ResponseWriter, r *http.Request, path string) error {
	// A key revoke ends the stream: it holds a toolbox token opened before
	// the revoke (plans/customer-key-custody.md §10).
	ctx, cancel := s.RevocableContext(ctx)
	defer cancel()
	r = r.WithContext(ctx)
	// Cross-node SSH sessions stamp a correlation ID on the forwarded call
	// (see pkg/sshgateway/forward.go). Logging it on the owner side lets an
	// operator join the edge and owner halves of one forwarded SSH session.
	if fid := r.Header.Get("X-Aerol-Ssh-Forward-Id"); fid != "" && s.logger != nil {
		s.logger.Info("ssh forward: owner serving session", "sandbox_id", sandboxID, "forward_id", fid, "path", path)
	}
	if err := refuseToolboxAdminPath(path); err != nil {
		return err
	}
	// Reuse the sandbox the wake helper already read (owner-scoped, post-wake)
	// instead of a second scopedGet — one fewer store read per toolbox call (D15).
	sandbox, err := s.EnsureSandboxAwakeForHTTP(ctx, sandboxID)
	if err != nil {
		return err
	}
	if s.isWasmSandbox(sandbox) {
		if s.wasm == nil {
			return fmt.Errorf("runtime %q: driver not registered", sandbox.Runtime)
		}
		host, ok := s.wasm.(wasmruntime.ToolboxHost)
		if !ok {
			return fmt.Errorf("wasm runtime does not implement toolbox host")
		}
		req := r.Clone(ctx)
		req.URL.Path = path
		host.ServeToolbox(ctx, sandboxID, sandbox.ToolboxToken, w, req)
		return nil
	}
	if s.isIsolateSandbox(sandbox) {
		if s.isolate == nil {
			return fmt.Errorf("runtime %q: driver not registered", sandbox.Runtime)
		}
		host, ok := isolateruntime.AsToolboxHost(s.isolate)
		if !ok {
			return fmt.Errorf("isolate runtime does not implement toolbox host")
		}
		req := r.Clone(ctx)
		req.URL.Path = path
		host.ServeToolbox(ctx, sandboxID, sandbox.ToolboxToken, w, req)
		return nil
	}

	endpoint, err := s.toolboxEndpointForActiveCall(ctx, sandbox)
	if err != nil {
		return err
	}
	target, err := url.Parse(endpoint.URL)
	if err != nil {
		return fmt.Errorf("invalid toolbox target: %w", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = toolboxhttp.Transport
	originalDirector := proxy.Director
	toolboxToken := endpoint.Token
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.URL.Path = path
		req.Host = target.Host
		// Never forward the CALLER's credential into the sandbox. toolboxd runs
		// inside tenant-controlled space and authenticates only from
		// Authorization, so we replace Authorization with the sandbox's own
		// toolbox token and strip the WebSocket subprotocol smuggle
		// ("sandbox.bearer, <token>") the SDK uses on handshakes — otherwise an
		// operator PAT used against a tenant's sandbox would land inside tenant
		// code. The subprotocol NAME is kept so the WS upgrade still negotiates.
		req.Header.Del("Authorization")
		if toolboxToken != "" {
			req.Header.Set("Authorization", "Bearer "+toolboxToken)
		}
		stripSmuggledBearerSubprotocol(req.Header)
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		if s.logger != nil {
			s.logger.Warn("toolbox proxy failed",
				"error", err,
				"sandbox_id", sandboxID,
				"runtime", sandbox.Runtime,
				"target", endpoint.URL,
				"path", path)
		}
		http.Error(w, "toolbox unavailable", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
	return nil
}

// bearerSubprotocol is the WebSocket subprotocol marker the SDKs use to smuggle
// a bearer token past the browser's inability to set Authorization on a
// handshake: `Sec-WebSocket-Protocol: sandbox.bearer, <token>`.
const bearerSubprotocol = "sandbox.bearer"

// stripSmuggledBearerSubprotocol rewrites Sec-WebSocket-Protocol so the caller's
// smuggled bearer token is removed before the request reaches the sandbox,
// keeping only the subprotocol marker so the WebSocket upgrade still negotiates.
// toolboxd authenticates from Authorization, so dropping the token element costs
// nothing there while preventing the caller's credential from reaching
// tenant-controlled code.
func stripSmuggledBearerSubprotocol(h http.Header) {
	const key = "Sec-WebSocket-Protocol"
	vals := h.Values(key)
	if len(vals) == 0 {
		return
	}
	hasMarker := false
	for _, raw := range vals {
		for _, part := range strings.Split(raw, ",") {
			if strings.TrimSpace(part) == bearerSubprotocol {
				hasMarker = true
			}
		}
	}
	h.Del(key)
	// Re-offer only the marker (never the token element after it). If the
	// marker was absent the header carried no smuggle convention we recognize,
	// so we drop it entirely rather than forward an unknown credential.
	if hasMarker {
		h.Set(key, bearerSubprotocol)
	}
}

// refuseToolboxAdminPath answers not found for toolboxd's /admin endpoints.
// They are the daemon's own controls (the port allowlist behind the
// sandbox's public proxy route), reached with the toolbox token; the toolbox
// proxies attach that token for every caller, so without this any caller
// who may reach a sandbox's toolbox could change what the daemon set.
func refuseToolboxAdminPath(toolboxPath string) error {
	clean := pathpkg.Clean("/" + strings.TrimSpace(toolboxPath))
	if clean == "/admin" || strings.HasPrefix(clean, "/admin/") {
		return fmt.Errorf("%w: toolbox path %q", store.ErrNotFound, toolboxPath)
	}
	return nil
}

// RoundTripToolbox performs an HTTP round trip to the sandbox toolbox.
func (s *Service) RoundTripToolbox(ctx context.Context, sandboxID, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Response, error) {
	if err := refuseToolboxAdminPath(path); err != nil {
		return nil, err
	}
	// Reuse the sandbox the wake helper already read (D15).
	sandbox, err := s.EnsureSandboxAwakeForHTTP(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	// WASM and isolate serve their toolbox in-process, like ServeToolboxReverseProxy
	// — not over the container network (B7). Without the isolate branch a Daytona
	// or Runloop call on an isolate sandbox dialled 127.0.0.1:<toolboxPort> and
	// failed with 502. Mirror ServeToolboxReverseProxy's wording so both paths
	// report the same driver/host errors.
	if s.isWasmSandbox(sandbox) {
		if s.wasm == nil {
			return nil, fmt.Errorf("runtime %q: driver not registered", sandbox.Runtime)
		}
		host, ok := s.wasm.(wasmruntime.ToolboxHost)
		if !ok {
			return nil, fmt.Errorf("wasm runtime does not implement toolbox host")
		}
		return s.roundTripHostToolbox(ctx, sandbox, host, method, path, query, body, headers)
	}
	if s.isIsolateSandbox(sandbox) {
		if s.isolate == nil {
			return nil, fmt.Errorf("runtime %q: driver not registered", sandbox.Runtime)
		}
		host, ok := isolateruntime.AsToolboxHost(s.isolate)
		if !ok {
			return nil, fmt.Errorf("isolate runtime does not implement toolbox host")
		}
		return s.roundTripHostToolbox(ctx, sandbox, host, method, path, query, body, headers)
	}
	req, err := s.newNetworkToolboxRequest(ctx, sandbox, method, path, query, body, headers)
	if err != nil {
		return nil, err
	}
	return toolboxhttp.Client(0).Do(req)
}

// toolboxHostServer is the in-process toolbox both the WASM and isolate
// runtimes expose; roundTripHostToolbox serves a request against either.
type toolboxHostServer interface {
	ServeToolbox(ctx context.Context, sandboxID, token string, w http.ResponseWriter, r *http.Request)
}

func (s *Service) roundTripHostToolbox(ctx context.Context, sandbox *models.Sandbox, host toolboxHostServer, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Response, error) {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if enc := query.Encode(); enc != "" {
		path = path + "?" + enc
	}
	req, err := http.NewRequestWithContext(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if sandbox.ToolboxToken != "" {
		req.Header.Set("Authorization", "Bearer "+sandbox.ToolboxToken)
	}
	rec := httptest.NewRecorder()
	host.ServeToolbox(ctx, sandbox.ID, sandbox.ToolboxToken, rec, req)
	return rec.Result(), nil
}

func (s *Service) newNetworkToolboxRequest(ctx context.Context, sandbox *models.Sandbox, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Request, error) {
	endpoint, err := s.toolboxEndpointForActiveCall(ctx, sandbox)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil, err
	}
	resolved := target.ResolveReference(&url.URL{Path: path, RawQuery: query.Encode()})
	req, err := http.NewRequestWithContext(ctx, method, resolved.String(), body)
	if err != nil {
		return nil, err
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if endpoint.Token != "" {
		req.Header.Set("Authorization", "Bearer "+endpoint.Token)
	}
	return req, nil
}

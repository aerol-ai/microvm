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
//
// It returns an error only before anything is written to w. When the
// sandbox stops while the request waits on it, that error is
// ErrSandboxStoppedMidRequest (toolbox_calls.go), so the caller answers 409
// at once instead of a 502 after the connection times out.
func (s *Service) ServeToolboxReverseProxy(ctx context.Context, sandboxID string, w http.ResponseWriter, r *http.Request, path string) error {
	// A key revoke ends the stream: it holds a toolbox token opened before
	// the revoke (plans/customer-key-custody.md §10).
	ctx, cancel := s.RevocableContext(ctx)
	defer cancel()
	// Registered before the sandbox's row is read, so a stop either finds
	// this request or is what the read sees.
	callCtx, release := s.TrackToolboxCall(ctx, sandboxID)
	defer release()
	err := s.serveToolboxReverseProxy(ctx, callCtx, sandboxID, w, r, path)
	if err != nil {
		if stopped := toolboxCallEnded(callCtx); stopped != nil {
			return stopped
		}
	}
	return err
}

// serveToolboxReverseProxy is ServeToolboxReverseProxy once the request is
// registered: the wake runs on ctx, so a stop that ends the request cannot
// abort a start half way, and everything after it on callCtx.
func (s *Service) serveToolboxReverseProxy(ctx, callCtx context.Context, sandboxID string, w http.ResponseWriter, r *http.Request, path string) error {
	r = r.WithContext(callCtx)
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
		req := r.Clone(callCtx)
		req.URL.Path = path
		host.ServeToolbox(callCtx, sandboxID, sandbox.ToolboxToken, w, req)
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
		req := r.Clone(callCtx)
		req.URL.Path = path
		host.ServeToolbox(callCtx, sandboxID, sandbox.ToolboxToken, w, req)
		return nil
	}

	endpoint, err := s.toolboxEndpointForActiveCall(callCtx, sandbox)
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
	// ReverseProxy calls ErrorHandler only before it writes a response, so
	// a stopped sandbox can still be answered by the caller.
	var stopped error
	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		if cause := s.toolboxBrokenCause(req.Context(), sandbox); cause != nil {
			stopped = cause
			return
		}
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
	return stopped
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

// RoundTripToolbox performs an HTTP round trip to the sandbox toolbox. The
// caller must close the response body: the request stays registered (see
// TrackToolboxCall) until it does. When the sandbox stops while the request
// waits on it, the error, or the error reading the body, is
// ErrSandboxStoppedMidRequest.
func (s *Service) RoundTripToolbox(ctx context.Context, sandboxID, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Response, error) {
	if err := refuseToolboxAdminPath(path); err != nil {
		return nil, err
	}
	// Registered before the sandbox's row is read (toolbox_calls.go).
	callCtx, release := s.TrackToolboxCall(ctx, sandboxID)
	resp, held, err := s.roundTripToolbox(ctx, callCtx, sandboxID, method, path, query, body, headers)
	if err != nil {
		stopped := toolboxCallEnded(callCtx)
		release()
		if stopped != nil {
			return nil, stopped
		}
		return nil, err
	}
	if !held {
		release()
		return resp, nil
	}
	resp.Body = &toolboxCallBody{ReadCloser: resp.Body, ctx: callCtx, release: release}
	return resp, nil
}

// roundTripToolbox is RoundTripToolbox once the request is registered. held
// reports a response still streaming from the sandbox, whose registration
// must last until its body is closed.
func (s *Service) roundTripToolbox(ctx, callCtx context.Context, sandboxID, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Response, bool, error) {
	// Reuse the sandbox the wake helper already read (D15). The wake runs
	// on ctx so a stop that ends this request cannot abort a start half way.
	sandbox, err := s.EnsureSandboxAwakeForHTTP(ctx, sandboxID)
	if err != nil {
		return nil, false, err
	}
	// WASM and isolate serve their toolbox in-process, like ServeToolboxReverseProxy
	// — not over the container network (B7). Without the isolate branch a Daytona
	// or Runloop call on an isolate sandbox dialled 127.0.0.1:<toolboxPort> and
	// failed with 502. Mirror ServeToolboxReverseProxy's wording so both paths
	// report the same driver/host errors.
	if s.isWasmSandbox(sandbox) {
		if s.wasm == nil {
			return nil, false, fmt.Errorf("runtime %q: driver not registered", sandbox.Runtime)
		}
		host, ok := s.wasm.(wasmruntime.ToolboxHost)
		if !ok {
			return nil, false, fmt.Errorf("wasm runtime does not implement toolbox host")
		}
		resp, err := s.roundTripHostToolbox(callCtx, sandbox, host, method, path, query, body, headers)
		return resp, false, err
	}
	if s.isIsolateSandbox(sandbox) {
		if s.isolate == nil {
			return nil, false, fmt.Errorf("runtime %q: driver not registered", sandbox.Runtime)
		}
		host, ok := isolateruntime.AsToolboxHost(s.isolate)
		if !ok {
			return nil, false, fmt.Errorf("isolate runtime does not implement toolbox host")
		}
		resp, err := s.roundTripHostToolbox(callCtx, sandbox, host, method, path, query, body, headers)
		return resp, false, err
	}
	req, err := s.newNetworkToolboxRequest(callCtx, sandbox, method, path, query, body, headers)
	if err != nil {
		return nil, false, err
	}
	resp, err := toolboxhttp.Client(0).Do(req)
	if err != nil {
		if stopped := s.toolboxBrokenCause(callCtx, sandbox); stopped != nil {
			return nil, false, stopped
		}
		return nil, false, err
	}
	return resp, true, nil
}

// toolboxCallBody is a toolbox response body that keeps its request
// registered until it is closed, and reports a read cut short by the
// sandbox stopping as ErrSandboxStoppedMidRequest.
type toolboxCallBody struct {
	io.ReadCloser
	ctx     context.Context
	release func()
}

func (b *toolboxCallBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		if stopped := toolboxCallEnded(b.ctx); stopped != nil {
			err = stopped
		}
	}
	return n, err
}

func (b *toolboxCallBody) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
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

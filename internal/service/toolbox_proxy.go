package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"

	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ServeToolboxReverseProxy forwards a toolbox request to the sandbox toolbox.
// WASM sandboxes are served in-process via the driver's ToolboxHost.
func (s *Service) ServeToolboxReverseProxy(ctx context.Context, sandboxID string, w http.ResponseWriter, r *http.Request, path string) error {
	// Cross-node SSH sessions stamp a correlation ID on the forwarded call
	// (see pkg/sshgateway/forward.go). Logging it on the owner side lets an
	// operator join the edge and owner halves of one forwarded SSH session.
	if fid := r.Header.Get("X-Aerol-Ssh-Forward-Id"); fid != "" && s.logger != nil {
		s.logger.Info("ssh forward: owner serving session", "sandbox_id", sandboxID, "forward_id", fid, "path", path)
	}
	if _, err := s.EnsureSandboxAwakeForHTTP(ctx, sandboxID); err != nil {
		return err
	}
	sandbox, err := s.scopedGet(ctx, sandboxID)
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

	endpoint, err := s.ToolboxTarget(ctx, sandboxID)
	if err != nil {
		return err
	}
	target, err := url.Parse(endpoint.URL)
	if err != nil {
		return fmt.Errorf("invalid toolbox target: %w", err)
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

// RoundTripToolbox performs an HTTP round trip to the sandbox toolbox.
func (s *Service) RoundTripToolbox(ctx context.Context, sandboxID, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Response, error) {
	if _, err := s.EnsureSandboxAwakeForHTTP(ctx, sandboxID); err != nil {
		return nil, err
	}
	sandbox, err := s.scopedGet(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	if s.isWasmSandbox(sandbox) {
		return s.roundTripWasmToolbox(ctx, sandbox, method, path, query, body, headers)
	}
	req, err := s.newNetworkToolboxRequest(ctx, sandboxID, method, path, query, body, headers)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

func (s *Service) roundTripWasmToolbox(ctx context.Context, sandbox *models.Sandbox, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Response, error) {
	if s.wasm == nil {
		return nil, fmt.Errorf("runtime %q: driver not registered", sandbox.Runtime)
	}
	host, ok := s.wasm.(wasmruntime.ToolboxHost)
	if !ok {
		return nil, fmt.Errorf("wasm runtime does not implement toolbox host")
	}
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

func (s *Service) newNetworkToolboxRequest(ctx context.Context, sandboxID, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Request, error) {
	endpoint, err := s.ToolboxTarget(ctx, sandboxID)
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

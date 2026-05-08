package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

type Server struct {
	logger   *slog.Logger
	service  *service.Service
	patToken string
	mux      *http.ServeMux
}

func NewServer(logger *slog.Logger, service *service.Service, patToken string) *Server {
	s := &Server{
		logger:   logger,
		service:  service,
		patToken: patToken,
		mux:      http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return loggingMiddleware(s.logger, s.mux)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.Handle("GET /v1/capacity", s.requireAuth(http.HandlerFunc(s.handleCapacity)))
	s.mux.Handle("POST /v1/admin/reconcile", s.requireAuth(http.HandlerFunc(s.handleReconcile)))
	s.mux.HandleFunc("GET /v1/tls-check", s.handleTLSCheck)

	s.mux.Handle("POST /v1/sandboxes", s.requireAuth(http.HandlerFunc(s.handleCreateSandbox)))
	s.mux.Handle("GET /v1/sandboxes", s.requireAuth(http.HandlerFunc(s.handleListSandboxes)))
	s.mux.Handle("GET /v1/sandboxes/{id}", s.requireAuth(http.HandlerFunc(s.handleGetSandbox)))
	s.mux.Handle("POST /v1/sandboxes/{id}/start", s.requireAuth(http.HandlerFunc(s.handleStartSandbox)))
	s.mux.Handle("POST /v1/sandboxes/{id}/stop", s.requireAuth(http.HandlerFunc(s.handleStopSandbox)))
	s.mux.Handle("DELETE /v1/sandboxes/{id}", s.requireAuth(http.HandlerFunc(s.handleDestroySandbox)))
	s.mux.Handle("POST /v1/sandboxes/{id}/resize", s.requireAuth(http.HandlerFunc(s.handleResizeSandbox)))
	s.mux.Handle("PUT /v1/sandboxes/{id}/lifecycle", s.requireAuth(http.HandlerFunc(s.handleUpdateLifecycle)))
	s.mux.Handle("POST /v1/sandboxes/{id}/ports/{port}", s.requireAuth(http.HandlerFunc(s.handleExposePort)))
	s.mux.Handle("DELETE /v1/sandboxes/{id}/ports/{port}", s.requireAuth(http.HandlerFunc(s.handleUnexposePort)))
	s.mux.Handle("GET /v1/sandboxes/{id}/mounts", s.requireAuth(http.HandlerFunc(s.handleListMounts)))
	// Explicit session routes are syntactic sugar for the toolbox proxy:
	// /v1/sandboxes/{id}/sessions/... → toolbox /sessions/...
	s.mux.Handle("/v1/sandboxes/{id}/sessions", s.requireAuth(http.HandlerFunc(s.handleSessionsProxy)))
	s.mux.Handle("/v1/sandboxes/{id}/sessions/{path...}", s.requireAuth(http.HandlerFunc(s.handleSessionsProxy)))
	s.mux.Handle("/v1/sandboxes/{id}/toolbox", s.requireAuth(http.HandlerFunc(s.handleToolboxProxy)))
	s.mux.Handle("/v1/sandboxes/{id}/toolbox/{path...}", s.requireAuth(http.HandlerFunc(s.handleToolboxProxy)))
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if extractBearerToken(r) == s.patToken {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, http.StatusUnauthorized, "unauthorized")
	})
}

// extractBearerToken returns the caller's bearer token from either:
//  1. the Authorization header, or
//  2. the WebSocket Sec-WebSocket-Protocol header in the form
//     `sandbox.bearer, <token>` (browsers cannot set Authorization on a
//     WebSocket handshake, so subprotocol smuggling is the standard pattern).
func extractBearerToken(r *http.Request) string {
	const prefix = "Bearer "
	authorization := r.Header.Get("Authorization")
	if strings.HasPrefix(authorization, prefix) {
		return strings.TrimPrefix(authorization, prefix)
	}

	for _, raw := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, part := range strings.Split(raw, ",") {
			candidate := strings.TrimSpace(part)
			if candidate == "" || candidate == "sandbox.bearer" {
				continue
			}
			return candidate
		}
	}
	return ""
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status, err := s.service.Health(r.Context())
	if err != nil {
		s.logger.Warn("health check failed", "error", err)
		writeError(w, http.StatusInternalServerError, "health check failed")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	if err := s.service.Reconcile(r.Context()); err != nil {
		s.logger.Warn("reconcile failed", "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleCapacity(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.service.Capacity())
}

func (s *Server) handleTLSCheck(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.URL.Query().Get("domain"))
	if host == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if !s.service.TLSDomainAllowed(host) {
		writeError(w, http.StatusForbidden, "domain not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleCreateSandbox(w http.ResponseWriter, r *http.Request) {
	var req models.CreateSandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	response, err := s.service.CreateSandbox(r.Context(), req)
	if err != nil {
		s.writeStoreAwareError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, response)
}

func (s *Server) handleListSandboxes(w http.ResponseWriter, r *http.Request) {
	sandboxes, err := s.service.ListSandboxes(r.Context())
	if err != nil {
		s.logger.Warn("list sandboxes failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, sandboxes)
}

func (s *Server) handleGetSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := s.service.GetSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreAwareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sandbox)
}

func (s *Server) handleStartSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := s.service.StartSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreAwareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sandbox)
}

func (s *Server) handleStopSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := s.service.StopSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreAwareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sandbox)
}

func (s *Server) handleDestroySandbox(w http.ResponseWriter, r *http.Request) {
	if err := s.service.DestroySandbox(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreAwareError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleResizeSandbox(w http.ResponseWriter, r *http.Request) {
	var req models.ResizeSandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	sandbox, err := s.service.ResizeSandbox(r.Context(), r.PathValue("id"), req)
	if err != nil {
		s.writeStoreAwareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sandbox)
}

func (s *Server) handleUpdateLifecycle(w http.ResponseWriter, r *http.Request) {
	var req models.UpdateLifecycleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	sandbox, err := s.service.UpdateLifecycle(r.Context(), r.PathValue("id"), req.Lifecycle)
	if err != nil {
		s.writeStoreAwareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sandbox)
}

func (s *Server) handleExposePort(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid port")
		return
	}
	publicURL, err := s.service.ExposePort(r.Context(), r.PathValue("id"), port)
	if err != nil {
		s.writeStoreAwareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"public_url": publicURL})
}

func (s *Server) handleListMounts(w http.ResponseWriter, r *http.Request) {
	mounts, err := s.service.ListMounts(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreAwareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mounts": mounts})
}

func (s *Server) handleUnexposePort(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid port")
		return
	}
	if err := s.service.UnexposePort(r.Context(), r.PathValue("id"), port); err != nil {
		s.writeStoreAwareError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleToolboxProxy(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	if path == "" {
		path = "/"
	} else {
		path = "/" + path
	}
	s.proxyToToolbox(w, r, path)
}

// handleSessionsProxy is sugar for /v1/sandboxes/{id}/sessions[/...] —
// rewrites to /sessions[/...] on the toolbox. WebSocket upgrades pass through
// transparently because httputil.ReverseProxy forwards Upgrade headers.
func (s *Server) handleSessionsProxy(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("path")
	target := "/sessions"
	if rest != "" {
		target = "/sessions/" + rest
	}
	s.proxyToToolbox(w, r, target)
}

func (s *Server) proxyToToolbox(w http.ResponseWriter, r *http.Request, path string) {
	endpoint, err := s.service.ToolboxTarget(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreAwareError(w, err)
		return
	}

	target, err := url.Parse(endpoint.URL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid toolbox target")
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
		writeError(w, http.StatusBadGateway, "toolbox unavailable")
	}
	proxy.ServeHTTP(w, r)
}

func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Info("request complete", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, models.ErrorResponse{Error: message})
}

func (s *Server) writeStoreAwareError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	// Capacity rejections are 503 with a Retry-After hint so well-behaved
	// clients (and load balancers) back off instead of treating it as a
	// permanent 4xx. The error string already carries human-readable
	// reasons from the admitter.
	if errors.Is(err, capacity.ErrCapacityExceeded) {
		s.logger.Info("capacity rejected", "error", err)
		w.Header().Set("Retry-After", "30")
		msg := err.Error()
		if len(msg) > 200 {
			msg = msg[:200]
		}
		writeError(w, http.StatusServiceUnavailable, msg)
		return
	}
	// Surface only the top-level error message; underlying causes (Docker
	// daemon strings, file paths) stay in the server log.
	s.logger.Warn("request failed", "error", err)
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	writeError(w, http.StatusBadRequest, msg)
}

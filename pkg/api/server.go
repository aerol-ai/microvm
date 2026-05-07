package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

type Server struct {
	logger   *slog.Logger
	service  *service.Service
	apiToken string
	mux      *http.ServeMux
}

func NewServer(logger *slog.Logger, service *service.Service, apiToken string) *Server {
	s := &Server{
		logger:   logger,
		service:  service,
		apiToken: apiToken,
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
	s.mux.HandleFunc("GET /v1/tls-check", s.handleTLSCheck)

	s.mux.Handle("POST /v1/sandboxes", s.requireAuth(http.HandlerFunc(s.handleCreateSandbox)))
	s.mux.Handle("GET /v1/sandboxes", s.requireAuth(http.HandlerFunc(s.handleListSandboxes)))
	s.mux.Handle("GET /v1/sandboxes/{id}", s.requireAuth(http.HandlerFunc(s.handleGetSandbox)))
	s.mux.Handle("POST /v1/sandboxes/{id}/start", s.requireAuth(http.HandlerFunc(s.handleStartSandbox)))
	s.mux.Handle("POST /v1/sandboxes/{id}/stop", s.requireAuth(http.HandlerFunc(s.handleStopSandbox)))
	s.mux.Handle("DELETE /v1/sandboxes/{id}", s.requireAuth(http.HandlerFunc(s.handleDestroySandbox)))
	s.mux.Handle("POST /v1/sandboxes/{id}/resize", s.requireAuth(http.HandlerFunc(s.handleResizeSandbox)))
	s.mux.Handle("POST /v1/sandboxes/{id}/ports/{port}", s.requireAuth(http.HandlerFunc(s.handleExposePort)))
	s.mux.Handle("DELETE /v1/sandboxes/{id}/ports/{port}", s.requireAuth(http.HandlerFunc(s.handleUnexposePort)))
	s.mux.Handle("/v1/sandboxes/{id}/toolbox", s.requireAuth(http.HandlerFunc(s.handleToolboxProxy)))
	s.mux.Handle("/v1/sandboxes/{id}/toolbox/{path...}", s.requireAuth(http.HandlerFunc(s.handleToolboxProxy)))
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, prefix) || strings.TrimPrefix(authorization, prefix) != s.apiToken {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status, err := s.service.Health(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
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
	sandbox, err := s.service.CreateSandbox(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, sandbox)
}

func (s *Server) handleListSandboxes(w http.ResponseWriter, r *http.Request) {
	sandboxes, err := s.service.ListSandboxes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sandboxes)
}

func (s *Server) handleGetSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := s.service.GetSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreAwareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sandbox)
}

func (s *Server) handleStartSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := s.service.StartSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreAwareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sandbox)
}

func (s *Server) handleStopSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := s.service.StopSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreAwareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sandbox)
}

func (s *Server) handleDestroySandbox(w http.ResponseWriter, r *http.Request) {
	if err := s.service.DestroySandbox(r.Context(), r.PathValue("id")); err != nil {
		writeStoreAwareError(w, err)
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
		writeStoreAwareError(w, err)
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
		writeStoreAwareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"public_url": publicURL})
}

func (s *Server) handleUnexposePort(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid port")
		return
	}
	if err := s.service.UnexposePort(r.Context(), r.PathValue("id"), port); err != nil {
		writeStoreAwareError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleToolboxProxy(w http.ResponseWriter, r *http.Request) {
	targetBase, err := s.service.ToolboxTarget(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreAwareError(w, err)
		return
	}

	target, err := url.Parse(targetBase)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	path := r.PathValue("path")
	if path == "" {
		path = "/"
	} else {
		path = "/" + path
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.URL.Path = path
		req.Host = target.Host
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		writeError(w, http.StatusBadGateway, err.Error())
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

func writeStoreAwareError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

var _ = fmt.Sprintf

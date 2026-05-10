// Package api wires the top-level HTTP server. It is intentionally thin —
// per-version routing lives in subpackages (pkg/api/v1, pkg/api/v2, ...) and
// shared HTTP helpers live in pkg/api/apihttp. This file's job is:
//
//  1. construct the *Server with its dependencies,
//  2. mount unversioned routes (/health),
//  3. delegate /v1/... (and any future version) to that version's
//     RegisterRoutes function.
//
// To add v2: create pkg/api/v2 mirroring pkg/api/v1, then add a single
// v2.RegisterRoutes(...) call below. The two versions coexist on the same
// mux without modifying v1.
package api

import (
	"log/slog"
	"net/http"

	apiv1 "github.com/aerol-ai/microvm/pkg/api/v1"
	"github.com/aerol-ai/microvm/internal/service"
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
	// /health is unversioned: it is meant for liveness probes (k8s, load
	// balancers) which should keep working across API version rollouts.
	s.mux.HandleFunc("GET /health", s.handleHealth)

	// Each registered version owns its own URL prefix and is responsible for
	// every route under it. Auth is shared across versions via Deps.Auth.
	apiv1.RegisterRoutes(s.mux, apiv1.Deps{
		Service: s.service,
		Logger:  s.logger,
		Auth:    s.requireAuth,
	})
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

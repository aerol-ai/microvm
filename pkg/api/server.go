// Package api wires the top-level HTTP server. It is intentionally thin —
// per-version routing lives in subpackages (pkg/api/v1, ...) and shared HTTP
// helpers live in pkg/api/apihttp. This file's job is:
//
//  1. construct the *Server with its dependencies,
//  2. mount unversioned routes (/health),
//  3. delegate /v1/... (and any future version) to that version's
//     RegisterRoutes function.
//
// To add a new version: create pkg/api/vN mirroring pkg/api/v1, then add a
// single vN.RegisterRoutes(...) call below. Versions coexist on the same
// mux without modifying each other.
package api

import (
	"log/slog"
	"net/http"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/daytona"
	"github.com/aerol-ai/microvm/pkg/api/e2b"
	apiv1 "github.com/aerol-ai/microvm/pkg/api/v1"
	"github.com/aerol-ai/microvm/pkg/docker"
)

type Server struct {
	logger   *slog.Logger
	service  *service.Service
	builder  *docker.Client
	build    daytona.BuildConfig
	patToken string
	mux      *http.ServeMux
}

func NewServer(logger *slog.Logger, service *service.Service, dockerClient *docker.Client, cfg config.Config, patToken string) *Server {
	s := &Server{
		logger:   logger,
		service:  service,
		builder:  dockerClient,
		build:    daytona.BuildConfig{ContextEnabled: cfg.ImageBuildContextEnabled, Timeout: cfg.ImageBuildTimeout, Registry: cfg.ImageBuildRegistry},
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
	daytona.RegisterRoutes(s.mux, daytona.Deps{
		Service: s.service,
		Logger:  s.logger,
		Auth:    s.requireAuth,
		Builder: s.builder,
		Build:   s.build,
	})

	e2b.RegisterRoutes(s.mux, e2b.Deps{
		Service: s.service,
		Logger:  s.logger,
		Auth:    s.requireE2BAuth,
	})

	apiv1.RegisterRoutes(s.mux, apiv1.Deps{
		Service: s.service,
		Logger:  s.logger,
		Auth:    s.requireAuth,
		Builder: s.builder,
		Build:   apiv1.BuildConfig{ContextEnabled: s.build.ContextEnabled, Timeout: s.build.Timeout, Registry: s.build.Registry},
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

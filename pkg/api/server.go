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
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/api/daytona"
	"github.com/aerol-ai/microvm/pkg/api/e2b"
	"github.com/aerol-ai/microvm/pkg/api/remotemcp"
	"github.com/aerol-ai/microvm/pkg/api/runloop"
	apiv1 "github.com/aerol-ai/microvm/pkg/api/v1"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/docker"
)

type Server struct {
	logger          *slog.Logger
	service         *service.Service
	containerEngine string
	patToken        string
	validator       controlplane.Validator
	auditLimiter    *apiv1.AuditRateLimiter
	clusterEnabled  bool
	mux             *http.ServeMux
	root            http.Handler
	mcp             *remotemcp.Handler

	// Facade config, read once from config.Config (not per request in the
	// facades). Each facade parses its own format.
	daytonaDefaultImage     string
	e2bTemplateMapJSON      string
	e2bClientID             string
	runloopBlueprintMapJSON string
}

// NewServer constructs the API server. validator is the second-token (non-PAT)
// validation path; pass controlplane.Noop().Validator (or any rejecting
// validator) for the open-source PAT-only behavior. A nil validator is treated
// as reject-all so callers can't accidentally open the door by omission.
//
// builder is the image builder the service builds with (every surface's
// builds go through service.BuildImage). On the dockerd engine this is the
// *docker.Client; on the containerd engine the daemon passes a
// buildkit-backed builder. A nil builder falls back to dockerClient so
// existing docker-only callers are unaffected; when both are nil the build
// endpoints return 503 (builder not configured).
func NewServer(logger *slog.Logger, service *service.Service, dockerClient *docker.Client, builder service.ImageBuilder, cfg config.Config, patToken string, validator controlplane.Validator) *Server {
	if validator == nil {
		validator = controlplane.Noop().Validator
	}
	// A nil *docker.Client wrapped in the interface would be a non-nil
	// interface holding a nil pointer, defeating the handlers' `Builder == nil`
	// guard. Only fall back when we actually have a docker client.
	if builder == nil && dockerClient != nil {
		builder = dockerClient
	}
	if service != nil && builder != nil {
		service.SetImageBuilder(builder)
	}
	s := &Server{
		logger:          logger,
		service:         service,
		containerEngine: cfg.ContainerEngine,
		patToken:        patToken,
		validator:       validator,
		clusterEnabled:  cfg.EnableCluster,
		auditLimiter: apiv1.NewAuditRateLimiter(apiv1.AuditRateLimiterConfig{
			IdentityRate: cfg.AuditRateLimitIdentity,
			OperatorRate: cfg.AuditRateLimitOperator,
			NodeRate:     cfg.AuditRateLimitNode,
		}),
		daytonaDefaultImage:     cfg.DaytonaDefaultImage,
		e2bTemplateMapJSON:      cfg.E2BTemplateMapJSON,
		e2bClientID:             cfg.E2BClientID,
		runloopBlueprintMapJSON: cfg.RunloopBlueprintMapJSON,
		mux:                     http.NewServeMux(),
	}
	if cfg.MCPEnabled {
		s.mcp = remotemcp.New(remotemcp.Config{
			AllowedOrigins: cfg.MCPAllowedOrigins,
			AllowedHosts:   cfg.MCPAllowedHosts,
			RateLimit:      cfg.MCPRateLimit,
			Version:        version.Version,
			Logger:         logger,
		}, s.Handler)
	}
	s.routes()
	s.root = loggingMiddleware(s.logger, s.clusterControlHeaderGuard(s.mux))
	return s
}

func (s *Server) Handler() http.Handler {
	if s.root == nil {
		// A Server built without NewServer (tests) still serves its mux.
		return loggingMiddleware(s.logger, s.clusterControlHeaderGuard(s.mux))
	}
	return s.root
}

func (s *Server) routes() {
	// /health is unversioned: it is meant for liveness probes (k8s, load
	// balancers) which should keep working across API version rollouts.
	s.mux.HandleFunc("GET /health", s.handleHealth)

	// Each registered version owns its own URL prefix and is responsible for
	// every route under it. Auth is shared across versions via Deps.Auth.
	daytona.RegisterRoutes(s.mux, daytona.Deps{
		Service:         s.service,
		Logger:          s.logger,
		Auth:            s.requireAuth,
		ContainerEngine: s.containerEngine,
		DefaultImage:    s.daytonaDefaultImage,
	})

	e2b.RegisterRoutes(s.mux, e2b.Deps{
		Service:         s.service,
		Logger:          s.logger,
		Auth:            s.requireE2BAuth,
		TemplateMapJSON: s.e2bTemplateMapJSON,
		ClientID:        s.e2bClientID,
	})

	runloop.RegisterRoutes(s.mux, runloop.Deps{
		Service:          s.service,
		Logger:           s.logger,
		Auth:             s.requireRunloopAuth,
		BlueprintMapJSON: s.runloopBlueprintMapJSON,
	})

	apiv1.RegisterRoutes(s.mux, apiv1.Deps{
		Service:         s.service,
		Logger:          s.logger,
		Auth:            s.requireAuth,
		AuditLimiter:    s.auditLimiter,
		ContainerEngine: s.containerEngine,
	})

	// Remote MCP (opt-in, SB_MCP_ENABLED). Its tools call back into this
	// same handler in-process with the caller's token.
	if s.mcp != nil {
		s.mux.Handle(remotemcp.Path, s.mcp.Wrap(s.requireAuth))
	}

	// Operator dashboard + expvar. /ui is unauth (static HTML; PAT prompted
	// in-page), /debug/vars is PAT-gated. See pkg/api/dashboard.go.
	s.registerDashboard()
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

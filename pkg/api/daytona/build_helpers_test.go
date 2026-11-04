package daytona

import (
	"io"
	"log/slog"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
)

// buildConfig is the build settings a test daemon runs with (the
// ImageBuild* fields of internal/config).
type buildConfig struct {
	ContextEnabled bool
	Timeout        time.Duration
}

// buildService is a daemon service that builds with builder under build;
// builds go through the service, never the handlers.
func buildService(builder service.ImageBuilder, build buildConfig) *service.Service {
	svc := service.New(config.Config{ImageBuildContextEnabled: build.ContextEnabled, ImageBuildTimeout: build.Timeout}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, nil, nil, nil)
	return withBuilder(svc, builder)
}

// withBuilder wires builder into svc and returns svc.
func withBuilder(svc *service.Service, builder service.ImageBuilder) *service.Service {
	if svc != nil && builder != nil {
		svc.SetImageBuilder(builder)
	}
	return svc
}

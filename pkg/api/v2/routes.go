// Package v2 holds the API surface for capabilities introduced after v1
// was soft-frozen. Today it carries a single endpoint — POST /v2/images/build
// — so the aerovm SDK can compile an Image-builder graph into a local image
// tag without piggybacking on the Daytona facade. New non-breaking endpoints
// land here.
package v2

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/docker"
)

// PathPrefix is the URL prefix every v2 route is registered under.
const PathPrefix = "/v2"

// ImageBuilder is the slice of pkg/docker.Client v2 needs. Same shape as the
// daytona facade's analogue — declared independently so the two packages
// don't take a compile-time dep on each other.
type ImageBuilder interface {
	BuildImage(ctx context.Context, req docker.BuildImageRequest) error
	ImageExists(ctx context.Context, imageRef string) (bool, error)
}

// BuildConfig mirrors the operator-configured image-build knobs.
type BuildConfig struct {
	ContextEnabled bool
	Timeout        time.Duration
	Registry       string
}

type Deps struct {
	Service *service.Service
	Logger  *slog.Logger
	Auth    func(http.Handler) http.Handler
	Builder ImageBuilder
	Build   BuildConfig
}

func RegisterRoutes(mux *http.ServeMux, d Deps) {
	h := &handlers{deps: d}
	mux.Handle("POST "+PathPrefix+"/images/build", d.Auth(http.HandlerFunc(h.buildImage)))
}

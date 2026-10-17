package api

import (
	_ "embed"
	"expvar"
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// dashboardHTML is the single-page operator dashboard, embedded so the binary
// is fully self-contained — there is no separate static-asset shipping step
// and no risk of a stale asset on disk diverging from the daemon version.
//
//go:embed dashboard.html
var dashboardHTML []byte

// registerDashboard mounts the dashboard page at /ui, expvar JSON metrics at
// /debug/vars, and Prometheus-compatible metrics at /v1/metrics. The page
// itself is served without auth (it carries no secrets; auth happens
// client-side when the user pastes a token into the sign-in form).
//
// /v1/metrics needs metrics.read, which only roles bound to every team hold
// (CEO review D6): the aerolvm_* counters carry the whole fleet's
// operational shape (lease state, queue depths, secret decrypt failures), so
// a team-bound token or a managed tenant may not read them, but a fleet-wide
// read-only viewer token can be a Prometheus scrape credential.
// /debug/vars stays fleet.admin: expvar also exposes process internals.
func (s *Server) registerDashboard(mux apihttp.Mux) {
	mux.Handle("GET /ui", http.HandlerFunc(s.serveDashboard))
	mux.Handle("GET /ui/", http.HandlerFunc(s.serveDashboard))
	mux.Handle("GET /debug/vars", s.route(controlplane.PermFleetAdmin, expvar.Handler()))
	mux.Handle("GET /v1/metrics", s.route(controlplane.PermMetricsRead, http.HandlerFunc(s.servePrometheusMetrics)))
}

func (s *Server) serveDashboard(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(dashboardHTML)
}

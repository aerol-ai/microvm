package api

import (
	_ "embed"
	"expvar"
	"net/http"
)

// dashboardHTML is the single-page operator dashboard, embedded so the binary
// is fully self-contained — there is no separate static-asset shipping step
// and no risk of a stale asset on disk diverging from the daemon version.
//
//go:embed dashboard.html
var dashboardHTML []byte

// registerDashboard mounts the dashboard page at /ui and the expvar metrics
// at /debug/vars. The page itself is served without auth (it carries no
// secrets; auth happens client-side when the user pastes their PAT into the
// sign-in form). The metrics endpoint IS PAT-gated because the aerolvm_*
// counters carry operational shape (lease state, queue depths, secret
// decrypt failures) we do not want exposed unauthenticated.
func (s *Server) registerDashboard() {
	s.mux.HandleFunc("GET /ui", s.serveDashboard)
	s.mux.HandleFunc("GET /ui/", s.serveDashboard)
	s.mux.Handle("GET /debug/vars", s.requireAuth(expvar.Handler()))
}

func (s *Server) serveDashboard(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(dashboardHTML)
}

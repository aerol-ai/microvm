package api

import (
	"net/http"
	"net/http/pprof"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// registerPprof mounts Go's profiler (net/http/pprof) at /debug/pprof/ when
// the operator turned it on with SB_ENABLE_PPROF (plans/agent-sandbox-
// feature-parity.md O2). Off by default: a profile shows the daemon's
// goroutines, heap and command line, and taking one costs CPU. On, it needs
// fleet.admin, the same as /debug/vars, through the same authenticate and
// authorize chain as every other route. Caddy does not forward /debug/* from
// the API domain, so it is reached on each node's own API port.
//
// The handlers are mounted one by one on the server's own mux. Importing
// net/http/pprof also registers them on http.DefaultServeMux; nothing in
// sandboxd serves that mux, so those copies are unreachable.
func (s *Server) registerPprof(mux apihttp.Mux) {
	if !s.pprofEnabled {
		return
	}
	admin := func(h http.HandlerFunc) http.Handler { return s.route(controlplane.PermFleetAdmin, h) }
	// Index also serves every named profile: /debug/pprof/heap,
	// /goroutine, /allocs, /block, /mutex, /threadcreate.
	mux.Handle("GET /debug/pprof/", admin(pprof.Index))
	mux.Handle("GET /debug/pprof/cmdline", admin(pprof.Cmdline))
	mux.Handle("GET /debug/pprof/profile", admin(pprof.Profile))
	mux.Handle("GET /debug/pprof/symbol", admin(pprof.Symbol))
	mux.Handle("POST /debug/pprof/symbol", admin(pprof.Symbol))
	mux.Handle("GET /debug/pprof/trace", admin(pprof.Trace))
}

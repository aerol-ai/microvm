package service

import "github.com/aerol-ai/microvm/pkg/models"

// RouteShape is the published Caddy shape for a (sandbox, exposed-port).
// One shape is live at a time per exposure; transitions are driven by
// status changes (Start/Stop/Die/Reconcile), never by per-request work.
//
// See plans/warm-direct-route-bypass.md D7/D8 — this enum + chooseRouteShape
// are the single source of truth so HTTP, TCP, TLS, reconcile, and event
// callsites cannot disagree about what shape should be live for a given
// sandbox row.
type RouteShape int

const (
	// RouteShapeNone means no route should be published. Destroyed
	// sandboxes and disarmed-stopped serverless sandboxes fall through
	// to Caddy's fallback (404).
	RouteShapeNone RouteShape = iota
	// RouteShapeDirect publishes the upstream as ContainerIP:port.
	// Used for non-serverless sandboxes always, and for serverless
	// sandboxes only while warm (HTTPWakeDirectBypassEnabled=true).
	RouteShapeDirect
	// RouteShapeWake publishes the upstream as the sandboxd loopback
	// ingress proxy (or per-exposure unix socket for TLS). Used for
	// serverless sandboxes while Stopped+armed, and for serverless
	// sandboxes always when HTTPWakeDirectBypassEnabled=false.
	RouteShapeWake
)

func (r RouteShape) String() string {
	switch r {
	case RouteShapeDirect:
		return "direct"
	case RouteShapeWake:
		return "wake"
	default:
		return "none"
	}
}

// chooseRouteShape is a pure function of the sandbox row and the
// service configuration. No I/O, no locks, no side effects — every
// callsite of installHTTPPortRoute / installTCPPortRoute /
// installTLSPortRoute funnels through this so reconcile, lifecycle,
// and event paths cannot disagree on what shape "should" be live.
//
// The decision tree:
//
//   - Destroyed → none.
//   - Non-serverless (or serverless rollout gate off) → direct always
//     (today's behavior for the entire non-serverless surface).
//   - Bypass disabled (HTTPWakeDirectBypassEnabled=false) → wake always
//     for serverless sandboxes (today's behavior — every request goes
//     through sandboxd regardless of warm/cold).
//   - Bypass enabled + Started + ContainerIP known → direct.
//   - Bypass enabled + Stopped + WakeArmed → wake.
//   - Anything else (Creating, transient states, missing IP) → none;
//     callers that hold the row in a transient state should retry
//     once the row settles.
func (s *Service) chooseRouteShape(sandbox *models.Sandbox) RouteShape {
	if sandbox == nil {
		return RouteShapeNone
	}
	if sandbox.Status == models.SandboxStatusDestroyed {
		return RouteShapeNone
	}
	if !s.serverlessWakeEnabled(sandbox) {
		return RouteShapeDirect
	}
	if !s.cfg.HTTPWakeDirectBypassEnabled {
		return RouteShapeWake
	}
	if sandbox.Status == models.SandboxStatusStarted && sandbox.ContainerIP != "" {
		return RouteShapeDirect
	}
	if sandbox.Status == models.SandboxStatusStopped && sandbox.WakeArmed {
		return RouteShapeWake
	}
	return RouteShapeNone
}

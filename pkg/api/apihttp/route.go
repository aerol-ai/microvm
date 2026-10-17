package apihttp

import (
	"context"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// One registration path for every API route (plans/identity-and-access.md
// §5.3, "Enforcement"):
//
//	Router.Route(perm, h) ─► authenticate ─► authorize(perm) ─► audit seam ─► h
//
// Every v1, Daytona, E2B, Runloop, MCP and dashboard route goes through it,
// and the registry test (pkg/api/route_registry_test.go) fails on any
// handler that did not, except an explicit public allowlist. A route
// registered without authentication used to be fleet-wide by accident (the
// service layer treats "no Access" as an internal caller); now it cannot be
// registered at all without a reviewer seeing it.

// Mux is where an API package mounts its routes. *http.ServeMux satisfies
// it; the registry test passes a recording one.
type Mux interface {
	Handle(pattern string, handler http.Handler)
}

// OperatorRequiredMessage is the 403 text the PAT-era operator gate wrote
// for a fleet route. Managed callers still get exactly this body (L8).
const OperatorRequiredMessage = "operator authorization required"

// Denial is one refused authorization, handed to the surface's 403 writer.
type Denial struct {
	Permission controlplane.Permission
	Access     controlplane.Access
}

// Hint is the D9 hint for a token or OIDC caller ("role viewer on team
// payments cannot sandbox.exec; ask an admin for role runner on team
// payments") and "" for everyone else.
func (d Denial) Hint() string { return controlplane.DenyHint(d.Access, d.Permission) }

// Message is the 403 text every surface writes: the hint for a token or OIDC
// caller, otherwise the text that caller already got before roles existed.
// Every route that is not a team verb was behind the operator gate, so a
// managed caller keeps "operator authorization required" there byte for
// byte; a team verb a managed viewer lacks (new with T1's managed roles)
// names the permission.
func (d Denial) Message() string {
	if hint := d.Hint(); hint != "" {
		return hint
	}
	switch {
	case teamVerb(d.Permission):
		return string(d.Permission) + " permission required"
	case d.Permission == controlplane.PermClusterInternal && d.Access.Principal.Kind == controlplane.PrincipalOperator:
		// The PAT holder is refused only because it is not acting as a
		// cluster node (no peer certificate, or it forwarded a user's
		// request). v1 answers the no-certificate case with the pre-T2 mTLS
		// text before reaching this.
		return "cluster internal endpoints serve cluster nodes only"
	}
	return OperatorRequiredMessage
}

// teamVerb reports whether p was open to every authenticated caller before
// roles existed (the routes behind d.Auth). Everything else (fleet.admin,
// metrics.read, audit.verify, cluster.internal, and T3's token routes) was
// behind the operator gate.
func teamVerb(p controlplane.Permission) bool {
	switch p {
	case controlplane.PermSandboxRead, controlplane.PermSandboxSecrets, controlplane.PermSandboxWrite,
		controlplane.PermSandboxExec, controlplane.PermAuditRead, controlplane.PermAuthenticated:
		return true
	}
	return false
}

// DenyWriter writes one surface's 403 for d, in that surface's body shape.
type DenyWriter func(w http.ResponseWriter, r *http.Request, d Denial)

// WriteForbidden is the v1 403 (also the dashboard's and /mcp's). A token or
// OIDC caller's body adds required_permission and role next to the hint
// (D9); every other caller gets the plain {"error": …} body it always had.
func WriteForbidden(w http.ResponseWriter, _ *http.Request, d Denial) {
	if hint := d.Hint(); hint != "" {
		WriteJSON(w, http.StatusForbidden, models.ErrorResponse{
			Error:              hint,
			RequiredPermission: string(d.Permission),
			Role:               string(d.Access.EffectiveRole()),
		})
		return
	}
	WriteError(w, http.StatusForbidden, d.Message())
}

// RouteCall is what the audit seam learns about one request Route decided.
type RouteCall struct {
	Permission controlplane.Permission
	// Access is the authenticated caller; HasAccess is false only for a
	// Router built without an authenticator (unit tests).
	Access    controlplane.Access
	HasAccess bool
	// Allowed is false for a refused call; its 403 is already written.
	Allowed bool
}

// AuditHook is the seam task T5 fills with kind "api" chain records (§5.9).
// When set, Route hands it every request after authorization: an allowed
// call with next, which the hook must serve (so it can tee the body and
// record the final status); a refused call with next nil, after its 403 is
// written. nil (T2) records nothing and serves next directly.
type AuditHook func(w http.ResponseWriter, r *http.Request, call RouteCall, next http.Handler)

// Router builds the handler for every API route of one surface.
type Router struct {
	// Authenticate is the surface's auth middleware (pkg/api withAuth). It
	// attaches the caller's Access or refuses with 401. nil only in unit
	// tests; the registry test pins that every production route has one.
	Authenticate func(http.Handler) http.Handler
	// Deny writes the surface's 403. nil means WriteForbidden (v1 shape).
	Deny DenyWriter
	// Audit is the T5 seam (AuditHook).
	Audit AuditHook
}

// Route returns next behind authenticate → authorize(perm) → audit seam.
func (rt Router) Route(perm controlplane.Permission, next http.Handler) http.Handler {
	return rt.build(string(perm), func(*http.Request) controlplane.Permission { return perm }, next)
}

// RouteBy is Route for a route whose permission depends on the request:
// GET /v1/sandboxes/{id} needs sandbox.secrets only with include_env, and the
// Runloop facade dispatches many verbs below one mux pattern. tag describes
// the rule for the registry test and reviewers ("sandbox.read|sandbox.secrets").
// classify must return a permission for every request; an unknown path
// should get the strictest team verb, never authenticated.
func (rt Router) RouteBy(tag string, classify func(*http.Request) controlplane.Permission, next http.Handler) http.Handler {
	return rt.build(tag, classify, next)
}

func (rt Router) build(tag string, classify func(*http.Request) controlplane.Permission, next http.Handler) http.Handler {
	deny := rt.Deny
	if deny == nil {
		deny = WriteForbidden
	}
	authorized := authorize(classify, deny, rt.Audit, next)
	serve := authorized
	if rt.Authenticate != nil {
		serve = rt.Authenticate(authorized)
	}
	return &RouteHandler{tag: tag, classify: classify, authenticates: rt.Authenticate != nil, serve: serve}
}

// authorize is the permission check. It runs inside authenticate, so in
// production it always finds the caller's Access. Without an authenticator
// (unit tests only) it keeps the pre-T2 contract: routes that were behind
// d.Auth stay open, and the routes the operator gate guarded stay refused.
func authorize(classify func(*http.Request) controlplane.Permission, deny DenyWriter, audit AuditHook, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		perm := classify(r)
		access, ok := controlplane.AccessFromContext(r.Context())
		call := RouteCall{Permission: perm, Access: access, HasAccess: ok}
		if ok {
			call.Allowed = access.Can(perm)
		} else {
			call.Allowed = teamVerb(perm)
		}
		if !call.Allowed {
			deny(w, r, Denial{Permission: perm, Access: access})
			if audit != nil {
				audit(w, r, call, nil)
			}
			return
		}
		if audit != nil {
			audit(w, r, call, next)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RouteHandler is the handler Route returns. It carries its permission so
// the registry test can tell a tagged route from a bare one.
type RouteHandler struct {
	tag           string
	classify      func(*http.Request) controlplane.Permission
	authenticates bool
	serve         http.Handler
}

func (h *RouteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.serve.ServeHTTP(w, r) }

// PermissionTag is the permission (or, for RouteBy, the rule) the route was
// registered with.
func (h *RouteHandler) PermissionTag() string { return h.tag }

// PermissionFor returns the permission r needs on this route.
func (h *RouteHandler) PermissionFor(r *http.Request) controlplane.Permission { return h.classify(r) }

// Authenticates reports whether the route authenticates before authorizing.
func (h *RouteHandler) Authenticates() bool { return h.authenticates }

// PreAuth registers a handler that runs checks of its own before handing the
// request to a Route-built handler, as remote MCP's origin and host checks
// do. outer must serve every request it accepts through route; the registry
// test follows Unwrap to route to find its permission.
func PreAuth(outer http.Handler, route http.Handler) http.Handler {
	return preAuth{outer: outer, route: route}
}

type preAuth struct{ outer, route http.Handler }

func (p preAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) { p.outer.ServeHTTP(w, r) }
func (p preAuth) Unwrap() http.Handler                             { return p.route }

// RouteOf finds the RouteHandler h was built from, following PreAuth.
func RouteOf(h http.Handler) (*RouteHandler, bool) {
	for h != nil {
		switch v := h.(type) {
		case *RouteHandler:
			return v, true
		case interface{ Unwrap() http.Handler }:
			h = v.Unwrap()
		default:
			return nil, false
		}
	}
	return nil, false
}

// CallerCan reports whether the request's caller holds p, for a handler that
// trims a response by permission rather than refusing it (E2B's envd token).
// No Access is an internal or in-process call, which holds everything.
func CallerCan(ctx context.Context, p controlplane.Permission) bool {
	access, ok := controlplane.AccessFromContext(ctx)
	return !ok || access.Can(p)
}

// IncludeEnvRequested reports whether the request asked for the sandbox env
// (include_env=true|1|yes, case-insensitive), the audited secret read.
func IncludeEnvRequested(r *http.Request) bool {
	switch strings.TrimSpace(strings.ToLower(r.URL.Query().Get("include_env"))) {
	case "true", "1", "yes":
		return true
	}
	return false
}

// ReadOrSecrets is the RouteBy classifier of a sandbox read that can return
// env: sandbox.secrets with include_env, sandbox.read otherwise.
func ReadOrSecrets(r *http.Request) controlplane.Permission {
	if IncludeEnvRequested(r) {
		return controlplane.PermSandboxSecrets
	}
	return controlplane.PermSandboxRead
}

// ReadOrSecretsTag is the registry tag of a ReadOrSecrets route.
const ReadOrSecretsTag = string(controlplane.PermSandboxRead) + "|" + string(controlplane.PermSandboxSecrets) + " with include_env"

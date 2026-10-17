package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// recordingMux records every route registerRoutes mounts.
type recordingMux map[string]http.Handler

func (m recordingMux) Handle(pattern string, h http.Handler) {
	if _, dup := m[pattern]; dup {
		panic("duplicate route " + pattern)
	}
	m[pattern] = h
}

// publicRoutes is the explicit allowlist of routes that carry no API
// principal (plans/identity-and-access.md §5.3, "Enforcement"). Adding to it
// is a security decision a reviewer must see.
var publicRoutes = map[string]string{
	"GET /health":   "liveness probes; reports only daemon health",
	"GET /ui":       "the static dashboard page; the token is asked for in-page",
	"GET /ui/":      "the static dashboard page; the token is asked for in-page",
	"/e2b/runtime":  "envd runtime proxy: the sandbox's own envd token guards it",
	"/e2b/runtime/": "envd runtime proxy: the sandbox's own envd token guards it",
}

// publicRoutePrefixes are public routes later tasks add: identity discovery
// (T6) and RFC 9728 protected-resource metadata (T13).
var publicRoutePrefixes = []string{"GET /.well-known/aerolvm-auth", "GET /.well-known/oauth-protected-resource"}

func isPublicRoute(pattern string) bool {
	if _, ok := publicRoutes[pattern]; ok {
		return true
	}
	for _, prefix := range publicRoutePrefixes {
		if strings.HasPrefix(pattern, prefix) {
			return true
		}
	}
	return false
}

// routePermissions pins every route's permission (§5.3 permissions table).
// A new route, a removed route or a changed permission fails
// TestRouteRegistry until this table says so.
var routePermissions = map[string]string{
	"/daytona/toolbox/{id}":                                    "sandbox.exec",
	"/daytona/toolbox/{id}/{path...}":                          "sandbox.exec",
	"/mcp":                                                     "authenticated",
	"/runloop/v1/devboxes":                                     "runloop: per call (runloop.permissionFor)",
	"/runloop/v1/devboxes/":                                    "runloop: per call (runloop.permissionFor)",
	"/v1/sandboxes/{id}/sessions":                              "sandbox.exec",
	"/v1/sandboxes/{id}/sessions/{path...}":                    "sandbox.exec",
	"/v1/sandboxes/{id}/toolbox":                               "sandbox.exec",
	"/v1/sandboxes/{id}/toolbox/{path...}":                     "sandbox.exec",
	"DELETE /daytona/sandbox/{idOrName}":                       "sandbox.write",
	"DELETE /daytona/snapshots/{id}":                           "sandbox.write",
	"DELETE /daytona/volumes/{volumeId}":                       "sandbox.write",
	"DELETE /e2b/sandboxes/{id}":                               "sandbox.write",
	"DELETE /e2b/templates/{id}":                               "sandbox.write",
	"DELETE /v1/cluster/internal/secrets/{sandboxID}":          "cluster.internal",
	"DELETE /v1/cluster/members/{id}":                          "fleet.admin",
	"DELETE /v1/cluster/nodes/{id}/storage-retired":            "fleet.admin",
	"DELETE /v1/cluster/orphans/{id}":                          "fleet.admin",
	"DELETE /v1/egress-profiles/{name}":                        "sandbox.write",
	"DELETE /v1/js-bundles/{id}":                               "sandbox.write",
	"DELETE /v1/sandboxes/{id}":                                "sandbox.write",
	"DELETE /v1/sandboxes/{id}/custom-domains/{hostname}":      "sandbox.write",
	"DELETE /v1/sandboxes/{id}/ports/{port}":                   "sandbox.write",
	"DELETE /v1/tokens/{id}":                                   "token.write",
	"DELETE /v1/snapshots/{id}":                                "sandbox.write",
	"DELETE /v1/templates/{id}":                                "fleet.admin",
	"DELETE /v1/wasm-modules/{id}":                             "sandbox.write",
	"GET /daytona/sandbox":                                     "sandbox.read",
	"GET /daytona/sandbox/paginated":                           "sandbox.read",
	"GET /daytona/sandbox/{idOrName}":                          apihttp.ReadOrSecretsTag,
	"GET /daytona/sandbox/{idOrName}/ports/{port}/preview-url": "sandbox.write",
	"GET /daytona/sandbox/{id}/toolbox-proxy-url":              "sandbox.read",
	"GET /daytona/snapshots":                                   "sandbox.read",
	"GET /daytona/snapshots/{id}":                              "sandbox.read",
	"GET /daytona/volumes":                                     "sandbox.read",
	"GET /daytona/volumes/by-name/{name}":                      "sandbox.read",
	"GET /daytona/volumes/{volumeId}":                          "sandbox.read",
	"GET /debug/vars":                                          "fleet.admin",
	"GET /e2b/sandboxes":                                       "sandbox.read",
	"GET /e2b/sandboxes/{id}":                                  "sandbox.read",
	"GET /e2b/snapshots":                                       "sandbox.read",
	"GET /e2b/v2/sandboxes":                                    "sandbox.read",
	"GET /v1/capacity":                                         "sandbox.read",
	"GET /v1/cluster/ingress-route/{id}":                       "fleet.admin",
	"GET /v1/cluster/internal/audit-acl/{id}":                  "cluster.internal",
	"GET /v1/cluster/internal/drain/{id}":                      "cluster.internal",
	"GET /v1/cluster/internal/drained-nodes":                   "cluster.internal",
	"GET /v1/cluster/internal/node-storage-retirements":        "cluster.internal",
	"GET /v1/cluster/internal/placement-by-name/{name}":        "cluster.internal",
	"GET /v1/cluster/internal/placement/{id}":                  "cluster.internal",
	"GET /v1/cluster/internal/placements":                      "cluster.internal",
	"GET /v1/cluster/internal/placements/changes":              "cluster.internal",
	"GET /v1/cluster/internal/recovery/{ref}":                  "cluster.internal",
	"GET /v1/cluster/internal/sandboxes/{id}/audit":            "cluster.internal",
	"GET /v1/cluster/internal/snapshot-node":                   "cluster.internal",
	"GET /v1/cluster/internal/storage-obligations":             "cluster.internal",
	"GET /v1/cluster/internal/tokens":                          "cluster.internal",
	"GET /v1/cluster/internal/tokens/page":                     "cluster.internal",
	"GET /v1/cluster/internal/volume":                          "cluster.internal",
	"GET /v1/cluster/internal/wasm-migrate/{id}/export":        "cluster.internal",
	"GET /v1/cluster/leader":                                   "fleet.admin",
	"GET /v1/cluster/members":                                  "fleet.admin",
	"GET /v1/cluster/placements/{id}":                          "fleet.admin",
	"GET /v1/cluster/sandbox-index":                            "fleet.admin",
	"GET /v1/cluster/sandboxes/{id}/secret-holders":            "fleet.admin",
	"GET /v1/cluster/storage-retirements":                      "fleet.admin",
	"GET /v1/egress-profiles":                                  "sandbox.read",
	"GET /v1/egress-profiles/{name}":                           "sandbox.read",
	"GET /v1/ingress/dns":                                      "fleet.admin",
	"GET /v1/js-bundles":                                       "sandbox.read",
	"GET /v1/js-bundles/{id}":                                  "sandbox.read",
	"GET /v1/metrics":                                          "metrics.read",
	"GET /v1/sandboxes":                                        apihttp.ReadOrSecretsTag,
	"GET /v1/sandboxes/{id}":                                   apihttp.ReadOrSecretsTag,
	"GET /v1/sandboxes/{id}/audit":                             "audit.read",
	"GET /v1/sandboxes/{id}/custom-domains":                    "sandbox.read",
	"GET /v1/sandboxes/{id}/custom-domains/dns":                "sandbox.read",
	"GET /v1/sandboxes/{id}/mounts":                            "sandbox.read",
	"GET /v1/sandboxes/{id}/network/learned":                   "sandbox.read",
	"GET /v1/sandboxes/{id}/network/usage":                     "sandbox.read",
	"GET /v1/snapshots":                                        "sandbox.read",
	"GET /v1/snapshots/{id}":                                   "sandbox.read",
	"GET /v1/templates":                                        "fleet.admin",
	"GET /v1/templates/{id}":                                   "fleet.admin",
	"GET /v1/tokens":                                           "token.read",
	"GET /v1/wasm-modules":                                     "sandbox.read",
	"GET /v1/wasm-modules/{id}":                                "sandbox.read",
	"GET /v1/whoami":                                           "authenticated",
	"HEAD /v1/cluster/internal/secrets/{sandboxID}":            "cluster.internal",
	"PATCH /v1/sandboxes/{id}/network/limits":                  "sandbox.write",
	"POST /daytona/sandbox":                                    "sandbox.write",
	"POST /daytona/sandbox/{idOrName}/autoarchive/{interval}":  "sandbox.write",
	"POST /daytona/sandbox/{idOrName}/autodelete/{interval}":   "sandbox.write",
	"POST /daytona/sandbox/{idOrName}/autostop/{interval}":     "sandbox.write",
	"POST /daytona/sandbox/{idOrName}/resize":                  "sandbox.write",
	"POST /daytona/sandbox/{idOrName}/snapshot":                "sandbox.write",
	"POST /daytona/sandbox/{idOrName}/start":                   "sandbox.write",
	"POST /daytona/sandbox/{idOrName}/stop":                    "sandbox.write",
	"POST /daytona/snapshots":                                  "sandbox.write",
	"POST /daytona/volumes":                                    "sandbox.write",
	"POST /e2b/sandboxes":                                      "sandbox.write",
	"POST /e2b/sandboxes/{id}/connect":                         "sandbox.exec",
	"POST /e2b/sandboxes/{id}/pause":                           "sandbox.write",
	"POST /e2b/sandboxes/{id}/snapshots":                       "sandbox.write",
	"POST /e2b/sandboxes/{id}/timeout":                         "sandbox.write",
	"POST /v1/admin/reconcile":                                 "fleet.admin",
	"POST /v1/audit/verify":                                    "audit.verify",
	"POST /v1/cluster/internal/apply":                          "cluster.internal",
	"POST /v1/cluster/internal/artifact-catalog":               "cluster.internal",
	"POST /v1/cluster/internal/artifact-catalog/epoch":         "cluster.internal",
	"POST /v1/cluster/internal/egress-profiles/read":           "cluster.internal",
	"POST /v1/cluster/internal/egress-profiles/write":          "cluster.internal",
	"POST /v1/cluster/internal/tokens/write":                   "cluster.internal",
	"POST /v1/cluster/internal/placements-by-ids":              "cluster.internal",
	"POST /v1/cluster/internal/placements/owned-recovery":      "cluster.internal",
	"POST /v1/cluster/internal/placements/page":                "cluster.internal",
	"POST /v1/cluster/internal/placements/query":               "cluster.internal",
	"POST /v1/cluster/internal/placements/reassign-stuck":      "cluster.internal",
	"POST /v1/cluster/internal/secrets":                        "cluster.internal",
	"POST /v1/cluster/internal/select-placement":               "cluster.internal",
	"POST /v1/cluster/nodes/{id}/drain":                        "fleet.admin",
	"POST /v1/cluster/nodes/{id}/storage-retired":              "fleet.admin",
	"POST /v1/cluster/nodes/{id}/uncordon":                     "fleet.admin",
	"POST /v1/cluster/orphans/{id}/reclaim-local":              "fleet.admin",
	"POST /v1/cluster/wasm-migrate":                            "fleet.admin",
	"POST /v1/images/build":                                    "sandbox.write",
	"POST /v1/js-bundles":                                      "sandbox.write",
	"POST /v1/network/policy/check":                            "sandbox.read",
	"POST /v1/sandboxes":                                       "sandbox.write",
	"POST /v1/sandboxes/{id}/custom-domains":                   "sandbox.write",
	"POST /v1/sandboxes/{id}/ports/{port}":                     "sandbox.write",
	"POST /v1/sandboxes/{id}/resize":                           "sandbox.write",
	"POST /v1/sandboxes/{id}/snapshot":                         "sandbox.write",
	"POST /v1/sandboxes/{id}/start":                            "sandbox.write",
	"POST /v1/sandboxes/{id}/stop":                             "sandbox.write",
	"POST /v1/snapshots":                                       "sandbox.write",
	"POST /v1/templates":                                       "fleet.admin",
	"POST /v1/tokens":                                          "token.write",
	"POST /v1/templates/{id}/rebuild":                          "fleet.admin",
	"POST /v1/wasm-modules":                                    "sandbox.write",
	"POST /v1/wasm-modules/push":                               "sandbox.write",
	"PUT /daytona/sandbox/{idOrName}/labels":                   "sandbox.write",
	"PUT /e2b/sandboxes/{id}/network":                          "sandbox.write",
	"PUT /v1/cluster/internal/wasm-migrate/{id}/import":        "cluster.internal",
	"PUT /v1/egress-profiles/{name}":                           "sandbox.write",
	"PUT /v1/sandboxes/{id}/lifecycle":                         "sandbox.write",
	"PUT /v1/sandboxes/{id}/network/policy":                    "sandbox.write",
}

// registeredRoutes is every route a fully configured server mounts (remote
// MCP on, so /mcp is included).
func registeredRoutes(t *testing.T, s *Server) recordingMux {
	t.Helper()
	m := recordingMux{}
	s.registerRoutes(m)
	return m
}

// TestRouteRegistry is the registry test (H4): every v1, Daytona, E2B,
// Runloop, MCP and dashboard route is permission-tagged and authenticates
// first, except the explicit public allowlist, and each one's permission is
// the one routePermissions pins.
func TestRouteRegistry(t *testing.T) {
	server := NewServer(discardLogger(), nil, nil, nil, config.Config{MCPEnabled: true}, "pat-token", nil)
	routes := registeredRoutes(t, server)
	if len(routes) < len(routePermissions) {
		t.Fatalf("only %d routes registered", len(routes))
	}
	for pattern, h := range routes {
		rh, tagged := apihttp.RouteOf(h)
		switch {
		case isPublicRoute(pattern):
			if tagged {
				t.Errorf("%s is on the public allowlist but registered through Route; drop it from the allowlist", pattern)
			}
			continue
		case !tagged:
			t.Errorf("%s is not permission-tagged: register it with d.Route(perm, …), or add it to publicRoutes with a reason", pattern)
			continue
		case !rh.Authenticates():
			t.Errorf("%s authorizes without authenticating: its Deps has no Auth", pattern)
		}
		want, pinned := routePermissions[pattern]
		if !pinned {
			t.Errorf("%s (%s) is not in routePermissions; add it after checking §5.3", pattern, rh.PermissionTag())
			continue
		}
		if got := rh.PermissionTag(); got != want {
			t.Errorf("%s permission = %q, want %q", pattern, got, want)
		}
	}
	for pattern := range routePermissions {
		if _, ok := routes[pattern]; !ok {
			t.Errorf("routePermissions pins %s, which is no longer registered", pattern)
		}
	}
	for pattern := range publicRoutes {
		if _, ok := routes[pattern]; !ok {
			t.Errorf("publicRoutes allows %s, which is no longer registered", pattern)
		}
	}
}

// A route that skipped Route is caught, and so is one whose Deps had no
// authenticator: the test above is not vacuous.
func TestRouteRegistryCatchesBareRoutes(t *testing.T) {
	bare := http.NotFoundHandler()
	if _, tagged := apihttp.RouteOf(bare); tagged {
		t.Fatal("a bare handler must not look permission-tagged")
	}
	unauthenticated := apihttp.Router{}.Route(controlplane.PermSandboxRead, bare)
	if rh, _ := apihttp.RouteOf(unauthenticated); rh.Authenticates() {
		t.Fatal("a Route built without an authenticator must say so")
	}
	if isPublicRoute("GET /v1/sandboxes") || !isPublicRoute("GET /.well-known/oauth-protected-resource/mcp") {
		t.Fatal("public allowlist matching is wrong")
	}
}

// matrixPrincipals is one credential per binding the role matrix covers.
// Tokens are avm_ (token principals), eyJ… are OIDC, managed-* go to the
// managed provider, and pat-token is the operator.
var matrixPrincipals = map[string]controlplane.Access{
	"avm_viewer_payments": tokenAccess("payments", controlplane.RoleViewer),
	"avm_runner_payments": tokenAccess("payments", controlplane.RoleRunner),
	"avm_viewer_all":      tokenAccess(controlplane.FleetTeam, controlplane.RoleViewer),
	"avm_runner_all":      tokenAccess(controlplane.FleetTeam, controlplane.RoleRunner),
	"avm_auditor":         tokenAccess(controlplane.FleetTeam, controlplane.RoleAuditor),
	"eyJadmin":            oidcAccess(controlplane.FleetTeam, controlplane.RoleAdmin),
	"eyJviewer_payments":  oidcAccess("payments", controlplane.RoleViewer),
}

func oidcAccess(team string, role controlplane.Role) controlplane.Access {
	a := tokenAccess(team, role)
	a.Principal = controlplane.Principal{Kind: controlplane.PrincipalOIDC, ID: "oidc:okta:00u1", Name: "ana@acme.com"}
	return a
}

// managedValidator stands in for a managed control plane with a runner and a
// viewer account.
type managedValidator map[string]controlplane.Identity

func (m managedValidator) Validate(_ context.Context, token string) (controlplane.Identity, error) {
	if id, ok := m[token]; ok {
		return id, nil
	}
	return controlplane.Identity{}, controlplane.ErrTokenRejected
}

func matrixServer() *Server {
	tokens := stubCredential{prefix: "avm_", kind: controlplane.PrincipalToken, accept: map[string]controlplane.Access{}}
	oidc := stubCredential{prefix: "eyJ", kind: controlplane.PrincipalOIDC, accept: map[string]controlplane.Access{}}
	for bearer, a := range matrixPrincipals {
		if strings.HasPrefix(bearer, "avm_") {
			tokens.accept[bearer] = a
		} else {
			oidc.accept[bearer] = a
		}
	}
	managed := managedValidator{
		"managed-runner": {ExternalID: "u1", OwnerRef: "acct-1"},
		"managed-viewer": {ExternalID: "u2", OwnerRef: "acct-1", Role: controlplane.RoleViewer},
	}
	return NewServer(discardLogger(), nil, nil, nil, config.Config{IdentityEnabled: true, MCPEnabled: true}, "pat-token", managed,
		WithCredentialAuthenticator(controlplane.PrincipalToken, tokens),
		WithCredentialAuthenticator(controlplane.PrincipalOIDC, oidc))
}

var patternVar = regexp.MustCompile(`\{[^}]*\}`)

// sampleRequests turns a route pattern into concrete requests. The Runloop
// facade routes by hand below one pattern, so it gets one request per
// dispatch shape.
func sampleRequests(pattern string) []*http.Request {
	method, path, found := strings.Cut(pattern, " ")
	if !found {
		method, path = http.MethodGet, pattern
	}
	if strings.HasPrefix(path, "/runloop/") {
		var out []*http.Request
		for _, mp := range [][2]string{
			{"GET", ""}, {"POST", ""}, {"POST", "/create_and_await_running"}, {"GET", "/disk_snapshots"},
			{"POST", "/disk_snapshots/s1"}, {"GET", "/disk_snapshots/s1/status"}, {"POST", "/disk_snapshots/s1/delete"},
			{"GET", "/dbx_1"}, {"POST", "/dbx_1"}, {"POST", "/dbx_1/shutdown"}, {"POST", "/dbx_1/execute"},
			{"POST", "/dbx_1/read_file_contents"}, {"POST", "/dbx_1/wait_for_status"}, {"GET", "/dbx_1/executions/e1"},
			{"GET", "/dbx_1/no_such_action"},
		} {
			out = append(out, httptest.NewRequest(mp[0], "/runloop/v1/devboxes"+mp[1], nil))
		}
		return out
	}
	path = strings.ReplaceAll(patternVar.ReplaceAllStringFunc(path, func(v string) string {
		if strings.HasSuffix(v, "...}") {
			return "p"
		}
		return "x1"
	}), "//", "/")
	reqs := []*http.Request{httptest.NewRequest(method, path, nil)}
	if strings.HasSuffix(pattern, "/sandboxes/{id}") && method == http.MethodGet || strings.HasSuffix(pattern, "/sandbox/{idOrName}") && method == http.MethodGet || pattern == "GET /v1/sandboxes" {
		reqs = append(reqs, httptest.NewRequest(method, path+"?include_env=true", nil))
	}
	return reqs
}

// TestRolePermissionMatrixOverRoutes drives every registered route with
// every role binding through the real authenticate → authorize chain. A
// binding without the route's permission gets a 403 in the surface's own
// shape (with the D9 hint for token and OIDC callers, without for the PAT
// and managed callers) and never reaches the handler; the cells that are
// allowed are checked against the §5.3 table (TestRolePermissionMatrix in
// pkg/controlplane pins the table itself).
func TestRolePermissionMatrixOverRoutes(t *testing.T) {
	server := matrixServer()
	routes := registeredRoutes(t, server)
	bearers := []string{"pat-token", "managed-runner", "managed-viewer"}
	for bearer := range matrixPrincipals {
		bearers = append(bearers, bearer)
	}
	sort.Strings(bearers)
	denials := map[string]int{}
	for pattern, h := range routes {
		rh, ok := apihttp.RouteOf(h)
		if !ok {
			continue
		}
		for _, sample := range sampleRequests(pattern) {
			perm := rh.PermissionFor(sample)
			for _, bearer := range bearers {
				access, known := matrixPrincipals[bearer]
				switch bearer {
				case "pat-token":
					access, known = controlplane.OperatorAccess(), true
				case "managed-runner":
					access, _ = controlplane.ControlPlaneAccess(controlplane.Identity{ExternalID: "u1", OwnerRef: "acct-1"})
					known = true
				case "managed-viewer":
					access, _ = controlplane.ControlPlaneAccess(controlplane.Identity{ExternalID: "u2", OwnerRef: "acct-1", Role: controlplane.RoleViewer})
					known = true
				}
				if !known || access.Can(perm) {
					continue
				}
				denials[bearer]++
				req := sample.Clone(sample.Context())
				req.Header.Set("Authorization", "Bearer "+bearer)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				checkDenial(t, pattern, req, bearer, access, perm, rec)
			}
		}
	}
	// Every non-admin binding is refused something; the operator only the
	// cluster-internal routes.
	for _, bearer := range []string{"avm_viewer_payments", "avm_runner_payments", "avm_viewer_all", "avm_runner_all", "avm_auditor", "eyJviewer_payments", "managed-runner", "managed-viewer", "pat-token"} {
		if denials[bearer] == 0 {
			t.Errorf("%s was never refused: the matrix is vacuous", bearer)
		}
	}
	t.Logf("refused cells per credential: %v", denials)
	if denials["eyJadmin"] != countPatterns(routes, controlplane.PermClusterInternal) {
		t.Errorf("an admin is refused only cluster.internal: %d denials", denials["eyJadmin"])
	}
}

// TestAuditSeamReachesEverySurface: the one Server.audit seam T5 fills is
// handed to every surface's Route, so each decided request reaches it once,
// refused ones included.
func TestAuditSeamReachesEverySurface(t *testing.T) {
	server := matrixServer()
	var seen []apihttp.RouteCall
	server.audit = func(w http.ResponseWriter, r *http.Request, call apihttp.RouteCall, next http.Handler) {
		seen = append(seen, call)
		if next != nil {
			next.ServeHTTP(w, r)
		}
	}
	routes := registeredRoutes(t, server)
	for _, tc := range []struct{ pattern, method, path string }{
		{"POST /v1/sandboxes", http.MethodPost, "/v1/sandboxes"},
		{"POST /daytona/sandbox", http.MethodPost, "/daytona/sandbox"},
		{"POST /e2b/sandboxes", http.MethodPost, "/e2b/sandboxes"},
		{"/runloop/v1/devboxes", http.MethodPost, "/runloop/v1/devboxes"},
		{"GET /v1/metrics", http.MethodGet, "/v1/metrics"},
	} {
		seen = nil
		rec := serve(routes[tc.pattern], tc.method, tc.path, "avm_viewer_payments", nil)
		if rec.Code != http.StatusForbidden || len(seen) != 1 || seen[0].Allowed || seen[0].Access.Role != controlplane.RoleViewer {
			t.Errorf("%s: %d, audit saw %+v", tc.pattern, rec.Code, seen)
		}
	}
	seen = nil
	if rec := serve(routes["GET /v1/whoami"], http.MethodGet, "/v1/whoami", "avm_viewer_payments", nil); rec.Code != http.StatusOK || len(seen) != 1 || !seen[0].Allowed {
		t.Errorf("whoami: %d, audit saw %+v", rec.Code, seen)
	}
}

func countPatterns(routes recordingMux, perm controlplane.Permission) int {
	n := 0
	for _, h := range routes {
		if rh, ok := apihttp.RouteOf(h); ok && rh.PermissionTag() == string(perm) {
			n++
		}
	}
	return n
}

// checkDenial asserts one refused cell: a 403 in the surface's envelope
// whose text is Denial.Message (the hint for token/OIDC callers), and on v1
// the required_permission and role fields for them only.
func checkDenial(t *testing.T, pattern string, req *http.Request, bearer string, access controlplane.Access, perm controlplane.Permission, rec *httptest.ResponseRecorder) {
	t.Helper()
	cell := pattern + " " + req.Method + " " + req.URL.String() + " as " + bearer
	if rec.Code != http.StatusForbidden {
		t.Errorf("%s: status %d, want 403 for %s; body %s", cell, rec.Code, perm, rec.Body.String())
		return
	}
	if bearer == "pat-token" && perm == controlplane.PermClusterInternal {
		if rec.Body.String() != "cluster internal endpoint requires mTLS\n" {
			t.Errorf("%s: PAT body %q changed", cell, rec.Body.String())
		}
		return
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Errorf("%s: body %q is not JSON", cell, rec.Body.String())
		return
	}
	want := apihttp.Denial{Permission: perm, Access: access}.Message()
	hinted := controlplane.HintPrincipal(access.Principal.Kind)
	field := "error"
	switch {
	case strings.HasPrefix(pattern, "POST /e2b") || strings.HasPrefix(pattern, "GET /e2b") || strings.HasPrefix(pattern, "PUT /e2b") || strings.HasPrefix(pattern, "DELETE /e2b"):
		field = "message"
		if body["code"] != float64(http.StatusForbidden) {
			t.Errorf("%s: E2B envelope code = %v", cell, body["code"])
		}
	case strings.HasPrefix(pattern, "/runloop"):
		field = "message"
	}
	if body[field] != want {
		t.Errorf("%s: %s = %q, want %q", cell, field, body[field], want)
	}
	if hinted != strings.Contains(want, "ask an admin") && perm != controlplane.PermClusterInternal {
		t.Errorf("%s: hint presence wrong in %q", cell, want)
	}
	_, hasPerm := body["required_permission"]
	v1Shape := field == "error" && !strings.Contains(pattern, "/daytona/")
	if hasPerm != (hinted && v1Shape) {
		t.Errorf("%s: required_permission present=%v, want %v (body %s)", cell, hasPerm, hinted && v1Shape, rec.Body.String())
	}
	if hinted && v1Shape && (body["required_permission"] != string(perm) || body["role"] != string(access.Role)) {
		t.Errorf("%s: v1 403 fields = %v / %v", cell, body["required_permission"], body["role"])
	}
}

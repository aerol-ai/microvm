package apihttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// as is a test authenticator that attaches a fixed Access, as pkg/api's
// withAuth does after a credential checks out.
func as(a controlplane.Access) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), a)))
		})
	}
}

func tokenOn(team string, role controlplane.Role) controlplane.Access {
	a := controlplane.Access{Role: role, Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_1", Name: "ci"}}
	if team == controlplane.FleetTeam {
		a.Fleet = true
	} else {
		a.Identity.OwnerRef = controlplane.TeamOwnerRef(team)
	}
	return a
}

func managed(role controlplane.Role) controlplane.Access {
	a, err := controlplane.ControlPlaneAccess(controlplane.Identity{OwnerRef: "acct", ExternalID: "u1", Role: role})
	if err != nil {
		panic(err)
	}
	return a
}

type reached struct{ n int }

func (c *reached) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c.n++
		w.WriteHeader(http.StatusNoContent)
	})
}

// Route authenticates, then authorizes: an allowed caller reaches the
// handler, a refused one gets the surface's 403 and never does.
func TestRouteAuthorizes(t *testing.T) {
	cases := []struct {
		name   string
		access controlplane.Access
		perm   controlplane.Permission
		want   int
	}{
		{"runner may exec", tokenOn("payments", controlplane.RoleRunner), controlplane.PermSandboxExec, http.StatusNoContent},
		{"viewer may not exec", tokenOn("payments", controlplane.RoleViewer), controlplane.PermSandboxExec, http.StatusForbidden},
		{"team viewer may not read metrics", tokenOn("payments", controlplane.RoleViewer), controlplane.PermMetricsRead, http.StatusForbidden},
		{"fleet viewer may read metrics", tokenOn(controlplane.FleetTeam, controlplane.RoleViewer), controlplane.PermMetricsRead, http.StatusNoContent},
		{"operator may administer", controlplane.OperatorAccess(), controlplane.PermFleetAdmin, http.StatusNoContent},
		{"managed runner may not administer", managed(""), controlplane.PermFleetAdmin, http.StatusForbidden},
		{"anyone authenticated", tokenOn("payments", controlplane.RoleViewer), controlplane.PermAuthenticated, http.StatusNoContent},
	}
	for _, tc := range cases {
		var c reached
		h := Router{Authenticate: as(tc.access)}.Route(tc.perm, c.handler())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != tc.want || (tc.want == http.StatusForbidden) != (c.n == 0) {
			t.Errorf("%s: status %d (handler reached %d times), want %d", tc.name, rec.Code, c.n, tc.want)
		}
	}
}

// Without an authenticator (unit tests only) Route keeps the pre-T2
// contract: routes that were behind d.Auth stay open, the ones the operator
// gate guarded stay refused.
func TestRouteWithoutAuthenticatorKeepsThePreRolesContract(t *testing.T) {
	for perm, want := range map[controlplane.Permission]int{
		controlplane.PermSandboxRead:     http.StatusNoContent,
		controlplane.PermSandboxExec:     http.StatusNoContent,
		controlplane.PermAuditRead:       http.StatusNoContent,
		controlplane.PermAuthenticated:   http.StatusNoContent,
		controlplane.PermFleetAdmin:      http.StatusForbidden,
		controlplane.PermMetricsRead:     http.StatusForbidden,
		controlplane.PermClusterInternal: http.StatusForbidden,
		controlplane.PermAuditVerify:     http.StatusForbidden,
		controlplane.PermTokenRead:       http.StatusForbidden,
	} {
		var c reached
		h := Router{}.Route(perm, c.handler())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != want {
			t.Errorf("%s without Access = %d, want %d", perm, rec.Code, want)
		}
		if rh, ok := RouteOf(h); !ok || rh.Authenticates() || rh.PermissionTag() != string(perm) {
			t.Errorf("%s: RouteOf = %v %v", perm, rh, ok)
		}
	}
}

// The deny writer is the surface's: a custom one replaces WriteForbidden.
func TestRouteUsesTheSurfaceDenyWriter(t *testing.T) {
	var got Denial
	rt := Router{
		Authenticate: as(tokenOn("payments", controlplane.RoleViewer)),
		Deny: func(w http.ResponseWriter, _ *http.Request, d Denial) {
			got = d
			w.WriteHeader(http.StatusTeapot)
		},
	}
	rec := httptest.NewRecorder()
	rt.Route(controlplane.PermSandboxWrite, http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
	if rec.Code != http.StatusTeapot || got.Permission != controlplane.PermSandboxWrite || got.Access.Role != controlplane.RoleViewer {
		t.Fatalf("custom deny writer: %d, %+v", rec.Code, got)
	}
}

// The audit seam (T5) sees every decided request once: an allowed call with
// next to serve, a refused one after its 403 with next nil.
func TestRouteAuditSeam(t *testing.T) {
	type seen struct {
		call    RouteCall
		hasNext bool
		status  int
	}
	var calls []seen
	audit := func(w http.ResponseWriter, r *http.Request, call RouteCall, next http.Handler) {
		s := seen{call: call, hasNext: next != nil}
		if next != nil {
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			s.status = rec.Code
			w.WriteHeader(rec.Code)
		}
		calls = append(calls, s)
	}
	var c reached
	for _, access := range []controlplane.Access{tokenOn("payments", controlplane.RoleRunner), tokenOn("payments", controlplane.RoleViewer)} {
		h := Router{Authenticate: as(access), Audit: audit}.Route(controlplane.PermSandboxExec, c.handler())
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/x", nil))
	}
	if len(calls) != 2 || c.n != 1 {
		t.Fatalf("audit calls = %+v, handler reached %d", calls, c.n)
	}
	if allowed := calls[0]; !allowed.call.Allowed || !allowed.hasNext || allowed.status != http.StatusNoContent ||
		allowed.call.Permission != controlplane.PermSandboxExec || !allowed.call.HasAccess {
		t.Errorf("allowed call = %+v", allowed)
	}
	if denied := calls[1]; denied.call.Allowed || denied.hasNext || denied.call.Access.Role != controlplane.RoleViewer {
		t.Errorf("denied call = %+v", denied)
	}
}

// RouteBy picks the permission per request.
func TestRouteByClassifiesEachRequest(t *testing.T) {
	var c reached
	h := Router{Authenticate: as(tokenOn("payments", controlplane.RoleViewer))}.RouteBy(ReadOrSecretsTag, ReadOrSecrets, c.handler())
	for query, want := range map[string]int{"": http.StatusNoContent, "?include_env=false": http.StatusNoContent, "?include_env=TRUE": http.StatusForbidden, "?include_env=1": http.StatusForbidden, "?include_env=yes": http.StatusForbidden} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/sandboxes/x"+query, nil))
		if rec.Code != want {
			t.Errorf("viewer GET %q = %d, want %d", query, rec.Code, want)
		}
	}
	rh, ok := RouteOf(h)
	if !ok || !rh.Authenticates() || rh.PermissionTag() != ReadOrSecretsTag {
		t.Fatalf("RouteOf = %+v %v", rh, ok)
	}
	if got := rh.PermissionFor(httptest.NewRequest(http.MethodGet, "/x?include_env=true", nil)); got != controlplane.PermSandboxSecrets {
		t.Fatalf("PermissionFor(include_env) = %s", got)
	}
}

func TestRouteOfFollowsPreAuth(t *testing.T) {
	route := Router{}.Route(controlplane.PermAuthenticated, http.NotFoundHandler())
	var outerRan bool
	outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outerRan = true
		route.ServeHTTP(w, r)
	})
	wrapped := PreAuth(outer, route)
	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if !outerRan {
		t.Fatal("PreAuth serves through outer")
	}
	if rh, ok := RouteOf(wrapped); !ok || rh.PermissionTag() != string(controlplane.PermAuthenticated) {
		t.Fatalf("RouteOf(PreAuth) = %v %v", rh, ok)
	}
	if _, ok := RouteOf(http.NotFoundHandler()); ok {
		t.Fatal("a bare handler is not a route")
	}
	if _, ok := RouteOf(PreAuth(outer, nil)); ok {
		t.Fatal("PreAuth around nothing is not a route")
	}
}

// TestForbiddenBodies pins the v1 403 bodies byte for byte: a token or OIDC
// caller gets the hint plus required_permission and role (D9); the PAT era's
// callers (managed, pre-roles) get exactly the text they always got (L8).
func TestForbiddenBodies(t *testing.T) {
	cases := []struct {
		name string
		d    Denial
		want string
	}{
		{"token viewer", Denial{Permission: controlplane.PermSandboxExec, Access: tokenOn("payments", controlplane.RoleViewer)},
			`{"error":"role viewer on team payments cannot sandbox.exec; ask an admin for role runner on team payments","required_permission":"sandbox.exec","role":"viewer"}` + "\n"},
		{"managed caller on a fleet route", Denial{Permission: controlplane.PermFleetAdmin, Access: managed("")},
			`{"error":"operator authorization required"}` + "\n"},
		{"managed caller on metrics", Denial{Permission: controlplane.PermMetricsRead, Access: managed("")},
			`{"error":"operator authorization required"}` + "\n"},
		{"managed caller on an internal route", Denial{Permission: controlplane.PermClusterInternal, Access: managed("")},
			`{"error":"operator authorization required"}` + "\n"},
		{"managed caller on audit verify", Denial{Permission: controlplane.PermAuditVerify, Access: managed("")},
			`{"error":"operator authorization required"}` + "\n"},
		{"managed caller on token routes", Denial{Permission: controlplane.PermTokenWrite, Access: managed("")},
			`{"error":"operator authorization required"}` + "\n"},
		{"managed viewer on a team verb", Denial{Permission: controlplane.PermSandboxExec, Access: managed(controlplane.RoleViewer)},
			`{"error":"sandbox.exec permission required"}` + "\n"},
		{"operator on an internal route", Denial{Permission: controlplane.PermClusterInternal, Access: controlplane.OperatorAccess()},
			`{"error":"cluster internal endpoints serve cluster nodes only"}` + "\n"},
		{"pre-roles literal", Denial{Permission: controlplane.PermFleetAdmin, Access: controlplane.Access{Identity: controlplane.Identity{OwnerRef: "acct"}}},
			`{"error":"operator authorization required"}` + "\n"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		WriteForbidden(rec, httptest.NewRequest(http.MethodGet, "/x", nil), tc.d)
		if rec.Code != http.StatusForbidden || rec.Body.String() != tc.want {
			t.Errorf("%s: %d %q\nwant %q", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
	// Facades carry the same text in their own envelope: the hint for a
	// token caller, the pre-roles text otherwise.
	hinted := Denial{Permission: controlplane.PermSandboxWrite, Access: tokenOn(controlplane.FleetTeam, controlplane.RoleViewer)}
	if got := hinted.Message(); got != "role viewer on all teams cannot sandbox.write; ask an admin for role runner on all teams" {
		t.Errorf("hinted Message = %q", got)
	}
}

// BenchmarkRouteAuthorize is the per-request cost Route adds on top of
// authentication: one context lookup and the role-table check.
func BenchmarkRouteAuthorize(b *testing.B) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	h := Router{}.Route(controlplane.PermSandboxExec, next)
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req = req.WithContext(controlplane.ContextWithAccess(req.Context(), tokenOn("payments", controlplane.RoleRunner)))
	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(w, req)
	}
}

func TestCallerCan(t *testing.T) {
	if !CallerCan(context.Background(), controlplane.PermFleetAdmin) {
		t.Fatal("no Access is an internal call: it holds everything")
	}
	viewer := controlplane.ContextWithAccess(context.Background(), tokenOn("payments", controlplane.RoleViewer))
	if CallerCan(viewer, controlplane.PermSandboxExec) || !CallerCan(viewer, controlplane.PermSandboxRead) {
		t.Fatal("a viewer reads but does not exec")
	}
}

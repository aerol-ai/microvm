package daytona

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestDaytonaRoutePermissions drives a viewer and a runner bound to team
// payments through the Daytona routes that read, read env, write and exec.
// A get returns env only with include_env, the audited secret read, so that
// request needs sandbox.secrets. Refusals keep the facade's own {"error"}
// body: the D9 hint rides in the message, with no v1 fields.
func TestDaytonaRoutePermissions(t *testing.T) {
	svc, st, _, _ := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-pay", Image: "alpine", Status: models.SandboxStatusStarted, OwnerRef: controlplane.TeamOwnerRef("payments"),
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	var caller controlplane.Access
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc, Auth: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), caller)))
		})
	}})
	as := func(role controlplane.Role) controlplane.Access {
		return controlplane.Access{
			Identity:  controlplane.Identity{OwnerRef: controlplane.TeamOwnerRef("payments")},
			Role:      role,
			Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_" + string(role)},
		}
	}
	hint := func(perm string) string {
		return `{"error":"role viewer on team payments cannot ` + perm + `; ask an admin for role runner on team payments"}` + "\n"
	}
	cases := []struct {
		role         controlplane.Role
		method, path string
		status       int
		body         string
	}{
		{controlplane.RoleViewer, http.MethodGet, "/daytona/sandbox/sb-pay", http.StatusOK, ""},
		{controlplane.RoleViewer, http.MethodGet, "/daytona/sandbox/sb-pay?include_env=true", http.StatusForbidden, hint("sandbox.secrets")},
		{controlplane.RoleViewer, http.MethodPost, "/daytona/sandbox/sb-pay/stop", http.StatusForbidden, hint("sandbox.write")},
		{controlplane.RoleViewer, http.MethodGet, "/daytona/sandbox/sb-pay/ports/8080/preview-url", http.StatusForbidden, hint("sandbox.write")},
		{controlplane.RoleViewer, http.MethodPost, "/daytona/toolbox/sb-pay/process/execute", http.StatusForbidden, hint("sandbox.exec")},
		{controlplane.RoleRunner, http.MethodGet, "/daytona/sandbox/sb-pay?include_env=true", http.StatusOK, ""},
	}
	for _, tc := range cases {
		caller = as(tc.role)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if rr.Code != tc.status || (tc.body != "" && rr.Body.String() != tc.body) {
			t.Errorf("%s %s %s = %d %q, want %d %q", tc.role, tc.method, tc.path, rr.Code, rr.Body.String(), tc.status, tc.body)
		}
	}
}

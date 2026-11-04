package e2b

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// teamRequest issues one E2B request as a token bound to team with role.
func teamRequest(t *testing.T, handler http.Handler, team string, role controlplane.Role, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = req.WithContext(controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity:  controlplane.Identity{OwnerRef: controlplane.TeamOwnerRef(team)},
		Role:      role,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_" + string(role), Name: string(role)},
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// The sandbox detail carries the envd access token, which opens the
// toolbox through /e2b/runtime. A viewer may read the sandbox but not exec
// in it, so its detail comes back without the token; a runner's keeps it.
// Connect hands the token out too, so it needs sandbox.exec.
func TestE2BEnvdTokenNeedsExec(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	created := teamRequest(t, handler, "payments", controlplane.RoleRunner, http.MethodPost, "/e2b/sandboxes", `{"templateID":"base","timeout":120,"secure":true}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("runner create = %d %s", created.Code, created.Body.String())
	}
	var sb sandboxResponse
	if err := json.NewDecoder(created.Body).Decode(&sb); err != nil || sb.EnvdAccessToken == "" {
		t.Fatalf("create response = %+v, %v; the test needs a secure sandbox", sb, err)
	}

	detail := func(role controlplane.Role) sandboxDetailResponse {
		t.Helper()
		rr := teamRequest(t, handler, "payments", role, http.MethodGet, "/e2b/sandboxes/"+sb.SandboxID, "")
		if rr.Code != http.StatusOK {
			t.Fatalf("%s detail = %d %s", role, rr.Code, rr.Body.String())
		}
		var d sandboxDetailResponse
		if err := json.NewDecoder(rr.Body).Decode(&d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	if got := detail(controlplane.RoleRunner).EnvdAccessToken; got != sb.EnvdAccessToken {
		t.Fatalf("runner detail token = %q, want the sandbox's", got)
	}
	if got := detail(controlplane.RoleViewer); got.EnvdAccessToken != "" || got.SandboxID != sb.SandboxID {
		t.Fatalf("viewer detail = %+v; want the sandbox without its envd token", got)
	}

	connect := teamRequest(t, handler, "payments", controlplane.RoleViewer, http.MethodPost, "/e2b/sandboxes/"+sb.SandboxID+"/connect", `{"timeout":60}`)
	want := `{"code":403,"message":"role viewer on team payments cannot sandbox.exec; ask an admin for role runner on team payments"}` + "\n"
	if connect.Code != http.StatusForbidden || connect.Body.String() != want {
		t.Fatalf("viewer connect = %d %q, want %q", connect.Code, connect.Body.String(), want)
	}
}

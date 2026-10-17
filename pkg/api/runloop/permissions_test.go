package runloop

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// TestPermissionForEveryDispatch pins the permission of each call shape the
// hand router serves. The facade routes every verb below one mux pattern,
// so the classifier is the facade's whole permission table.
func TestPermissionForEveryDispatch(t *testing.T) {
	h := newHandlers(Deps{})
	cases := []struct {
		method, path string
		want         controlplane.Permission
	}{
		{http.MethodGet, "", permRead},
		{http.MethodPost, "", permWrite},
		{http.MethodPost, "/create_and_await_running", permWrite},
		{http.MethodGet, "/create_and_await_running/x", permExec}, // not served: strictest
		{http.MethodGet, "/disk_snapshots", permRead},
		{http.MethodPost, "/disk_snapshots/s1", permWrite},
		{http.MethodGet, "/disk_snapshots/s1/status", permRead},
		{http.MethodPost, "/disk_snapshots/s1/delete", permWrite},
		{http.MethodGet, "/evictions", permRead},
		{http.MethodGet, "/dbx_1", permRead},
		{http.MethodPost, "/dbx_1", permWrite},
		{http.MethodGet, "/dbx_1/executions/e1", permExec},
		{http.MethodPost, "/dbx_1/executions/e1/kill", permExec},
		{http.MethodGet, "/dbx_1/executions/e1/stream_stdout_updates", permExec},
		{http.MethodPost, "/dbx_1/no_such_action", permExec},
		{http.MethodPost, "/dbx_1/shutdown/extra", permExec},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, devboxesPath+tc.path, nil)
		if got := h.permissionFor(req); got != tc.want {
			t.Errorf("%s %s = %s, want %s", tc.method, tc.path, got, tc.want)
		}
	}
	// Every devbox action classifies to the permission its table row
	// names: the check and the dispatch read the same table.
	want := map[string]controlplane.Permission{
		"shutdown": permWrite, "suspend": permWrite, "resume": permWrite, "keep_alive": permWrite,
		"wait_for_status": permRead, "execute": permExec, "execute_async": permExec, "execute_sync": permExec,
		"read_file_contents": permExec, "write_file_contents": permExec, "upload_file": permExec, "download_file": permExec,
		"snapshot_disk": permWrite, "snapshot_disk_async": permWrite, "enable_tunnel": permWrite, "remove_tunnel": permWrite,
		"create_pty_tunnel": permExec, "create_ssh_key": permExec, "create_gateway_token": permExec, "create_mcp_token": permExec,
		"logs": permExec, "usage": permRead,
	}
	actions := h.devboxActions()
	if len(actions) != len(want) {
		t.Fatalf("devboxActions has %d rows, this test pins %d: add the new action here", len(actions), len(want))
	}
	for name, action := range actions {
		req := httptest.NewRequest(action.method, devboxesPath+"/dbx_1/"+name, nil)
		if got := h.permissionFor(req); got != want[name] || got != action.perm {
			t.Errorf("action %s = %s (table %s), want %s", name, got, action.perm, want[name])
		}
	}
}

// A viewer is refused a write with Runloop's own body and the D9 hint.
// The SDKs never retry a 403, so no x-should-retry header is needed.
func TestRunloopForbiddenBody(t *testing.T) {
	env := newTestEnv(t)
	mux := http.NewServeMux()
	viewer := controlplane.Access{
		Identity:  controlplane.Identity{OwnerRef: controlplane.TeamOwnerRef("payments")},
		Role:      controlplane.RoleViewer,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_v"},
	}
	RegisterRoutes(mux, Deps{Service: env.svc, Auth: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), viewer)))
		})
	}})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, devboxesPath, nil))
	want := `{"message":"role viewer on team payments cannot sandbox.write; ask an admin for role runner on team payments"}` + "\n"
	if rr.Code != http.StatusForbidden || rr.Body.String() != want {
		t.Fatalf("viewer create = %d %q, want %q", rr.Code, rr.Body.String(), want)
	}
	// The same viewer lists devboxes fine.
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, devboxesPath, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("viewer list = %d %s", rr.Code, rr.Body.String())
	}
}

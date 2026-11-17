package apihttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Node certificates get only what their role needs: a worker's or
// gateway's node principal reaches a route only through the route's
// grant, and the grant decides nobody else; a server's is held to the
// permission alone. A refused node is told which node and role it is.
func TestRouteForNodes(t *testing.T) {
	onlySelf := func(r *http.Request, a controlplane.Access) bool { return r.URL.Query().Get("id") == a.NodeID() }
	for _, tc := range []struct {
		name   string
		access controlplane.Access
		path   string
		want   int
	}{
		{"worker, granted", controlplane.NodeAccess("w1", controlplane.NodeRoleWorker), "/x?id=w1", http.StatusNoContent},
		{"worker, not granted", controlplane.NodeAccess("w1", controlplane.NodeRoleWorker), "/x?id=w2", http.StatusForbidden},
		{"gateway, granted", controlplane.NodeAccess("g1", controlplane.NodeRoleIngress), "/x?id=g1", http.StatusNoContent},
		{"unknown role, not granted", controlplane.NodeAccess("u1", ""), "/x?id=w2", http.StatusForbidden},
		{"server, by permission", controlplane.NodeAccess("s1", controlplane.NodeRoleServer), "/x?id=w2", http.StatusNoContent},
		{"a runner is not a node: the grant never applies", tokenOn("payments", controlplane.RoleRunner), "/x?id=", http.StatusForbidden},
	} {
		var c reached
		h := Router{Authenticate: as(tc.access)}.RouteForNodes(controlplane.PermFleetAdmin, onlySelf, c.handler())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != tc.want || (c.n == 1) != (tc.want == http.StatusNoContent) {
			t.Fatalf("%s: %d (reached %d) %s", tc.name, rec.Code, c.n, rec.Body.String())
		}
		if tc.want == http.StatusForbidden && tc.access.NodeLimited() {
			var body models.ErrorResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if !strings.Contains(body.Error, tc.access.Principal.ID) || !strings.Contains(body.Error, "may not make this call as itself") {
				t.Fatalf("%s: refusal %q", tc.name, body.Error)
			}
		}
		rh, ok := RouteOf(h)
		if !ok || rh.NodeGrant() == nil || rh.PermissionTag() != string(controlplane.PermFleetAdmin) {
			t.Fatalf("%s: route handler %+v", tc.name, rh)
		}
	}
	if rh, _ := RouteOf(Router{}.Route(controlplane.PermFleetAdmin, http.NotFoundHandler())); rh.NodeGrant() != nil {
		t.Fatal("a plain route grants node certificates")
	}
	// RouteByForNodes: the grant sees the request (no env), the classifier
	// still decides the permission.
	noEnv := func(r *http.Request, _ controlplane.Access) bool { return !IncludeEnvRequested(r) }
	var c reached
	h := Router{Authenticate: as(controlplane.NodeAccess("w1", controlplane.NodeRoleWorker))}.RouteByForNodes(ReadOrSecretsTag, ReadOrSecrets, noEnv, c.handler())
	for path, want := range map[string]int{"/x": http.StatusNoContent, "/x?include_env=1": http.StatusForbidden} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Fatalf("RouteByForNodes %s = %d", path, rec.Code)
		}
	}
	// A refused worker on cluster.internal keeps that route's own text.
	d := Denial{Permission: controlplane.PermClusterInternal, Access: controlplane.NodeAccess("w1", controlplane.NodeRoleWorker)}
	if strings.Contains(d.Message(), "may not make this call") {
		t.Fatalf("cluster.internal message = %q", d.Message())
	}
	if msg := (Denial{Permission: controlplane.PermSandboxRead, Access: controlplane.NodeAccess("u1", "")}).Message(); !strings.Contains(msg, "role unknown") {
		t.Fatalf("unknown role message = %q", msg)
	}
}

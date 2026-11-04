package runloop

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAuditRoute: every Runloop call is described the way a ServeMux
// pattern would be, so its api record names the call and not the facade's
// one catch-all pattern.
func TestAuditRoute(t *testing.T) {
	cases := []struct {
		method, path           string
		route, sandbox, target string
		deletes                bool
	}{
		{"POST", "/runloop/v1/devboxes", "/runloop/v1/devboxes", "", "", false},
		{"POST", "/runloop/v1/devboxes/create_and_await_running", "/runloop/v1/devboxes/create_and_await_running", "", "", false},
		{"GET", "/runloop/v1/devboxes/evictions", "/runloop/v1/devboxes/evictions", "", "", false},
		{"GET", "/runloop/v1/devboxes/disk_snapshots", "/runloop/v1/devboxes/disk_snapshots", "", "", false},
		{"GET", "/runloop/v1/devboxes/disk_snapshots/snap-1/status", "/runloop/v1/devboxes/disk_snapshots/{id}/status", "", "snap-1", false},
		{"POST", "/runloop/v1/devboxes/disk_snapshots/snap-1", "/runloop/v1/devboxes/disk_snapshots/{id}", "", "snap-1", false},
		{"GET", "/runloop/v1/devboxes/dbx-1", "/runloop/v1/devboxes/{id}", "dbx-1", "", false},
		{"POST", "/runloop/v1/devboxes/dbx-1/execute_sync", "/runloop/v1/devboxes/{id}/execute_sync", "dbx-1", "", false},
		{"POST", "/runloop/v1/devboxes/dbx-1/shutdown", "/runloop/v1/devboxes/{id}/shutdown", "dbx-1", "", true},
		{"GET", "/runloop/v1/devboxes/dbx-1/executions", "/runloop/v1/devboxes/{id}/executions", "dbx-1", "", false},
		{"POST", "/runloop/v1/devboxes/dbx-1/executions/ex-9/kill", "/runloop/v1/devboxes/{id}/executions/{execution_id}/kill", "dbx-1", "ex-9", false},
	}
	for _, c := range cases {
		route, sandbox, target, deletes := AuditRoute(httptest.NewRequest(c.method, c.path, nil))
		if route != c.route || sandbox != c.sandbox || target != c.target || deletes != c.deletes {
			t.Errorf("%s %s = (%q, %q, %q, %v), want (%q, %q, %q, %v)", c.method, c.path, route, sandbox, target, deletes, c.route, c.sandbox, c.target, c.deletes)
		}
	}
	long := "/runloop/v1/devboxes/dbx-1/" + strings.Repeat("x", 500)
	if route, _, _, _ := AuditRoute(httptest.NewRequest("POST", long, nil)); len(route) != maxAuditRouteLen {
		t.Errorf("an unknown action segment is not bounded: %d bytes", len(route))
	}
}

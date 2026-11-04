package runloop

import (
	"net/http"
	"strings"
)

// The facade serves every call below one mux pattern, so the pattern alone
// would give every Runloop api record the same route. AuditRoute names the
// call the way a ServeMux pattern would (plans/identity-and-access.md §5.9):
// ids become placeholders, the action names stay, and the devbox id is
// reported as the sandbox.

// DevboxesPath is the root every routed call lives under.
const DevboxesPath = devboxesPath

// maxAuditRouteLen bounds a route built from the request path: an unknown
// action segment is the caller's own text, and the record is evidence, not
// a place to store it.
const maxAuditRouteLen = 200

// AuditRoute describes r for its api record: the route pattern, the devbox
// it acts on (the sandbox id), the object it acts on otherwise (a disk
// snapshot or an execution id), and whether it ends the devbox's life.
func AuditRoute(r *http.Request) (route, sandboxID, target string, deletesSandbox bool) {
	segs := devboxSegments(r)
	route = devboxesPath
	switch {
	case len(segs) == 0:
	case segs[0] == "create_and_await_running" || segs[0] == "evictions":
		route += "/" + segs[0]
	case segs[0] == "disk_snapshots":
		route += "/disk_snapshots"
		if len(segs) > 1 {
			route += "/{id}" + literalTail(segs[2:])
			target = segs[1]
		}
	default:
		sandboxID = segs[0]
		route += "/{id}"
		rest := segs[1:]
		if len(rest) > 0 && rest[0] == "executions" {
			route += "/executions"
			if len(rest) > 1 {
				route += "/{execution_id}" + literalTail(rest[2:])
				target = rest[1]
			}
		} else {
			route += literalTail(rest)
			deletesSandbox = len(rest) == 1 && rest[0] == "shutdown"
		}
	}
	if len(route) > maxAuditRouteLen {
		route = route[:maxAuditRouteLen]
	}
	return route, sandboxID, target, deletesSandbox
}

func literalTail(segs []string) string {
	if len(segs) == 0 {
		return ""
	}
	return "/" + strings.Join(segs, "/")
}

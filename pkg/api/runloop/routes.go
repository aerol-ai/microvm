// Package runloop is a compatibility facade for the official Runloop SDKs
// (@runloop/api-client, runloop_api_client). Pointing RUNLOOP_BASE_URL at
// https://<host>/runloop makes the SDK's /v1/devboxes/... calls land here,
// where they are translated onto internal/service the same way the /e2b
// and /daytona facades are. Devboxes are native sandboxes; executions and
// file calls go through the sandbox toolbox.
package runloop

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

const PathPrefix = "/runloop"

// devboxesPath is the root every routed call lives under. The SDKs join
// RUNLOOP_BASE_URL with absolute /v1/... paths, so the base URL must stop
// at the facade prefix.
const devboxesPath = PathPrefix + "/v1/devboxes"

// Deps are the shared dependencies the Runloop facade needs from the
// top-level API package.
type Deps struct {
	Service *service.Service
	Logger  *slog.Logger
	// Auth authenticates a request (pkg/api). The facade never calls it
	// directly: RouteBy composes it with the permission check.
	Auth func(http.Handler) http.Handler
	// Audit is the seam task T5 fills with kind "api" records
	// (apihttp.AuditHook). nil records nothing.
	Audit apihttp.AuditHook
	// BlueprintMapJSON maps blueprint names/ids → images
	// (SB_RUNLOOP_BLUEPRINT_MAP_JSON), read once in config; the facade parses
	// it and applies its own defaults.
	BlueprintMapJSON string
}

// RouteBy returns h behind authenticate → authorize → audit seam
// (plans/identity-and-access.md §5.3), with the permission chosen per
// request: the facade dispatches every verb below one mux pattern.
func (d Deps) RouteBy(tag string, classify func(*http.Request) controlplane.Permission, h http.Handler) http.Handler {
	return apihttp.Router{Authenticate: d.Auth, Deny: writeForbidden, Audit: d.Audit}.RouteBy(tag, classify, h)
}

// writeForbidden keeps Runloop's {"message"} body; a token or OIDC caller's
// D9 hint rides in the message.
func writeForbidden(w http.ResponseWriter, _ *http.Request, d apihttp.Denial) {
	WriteError(w, http.StatusForbidden, d.Message())
}

const (
	permRead  = controlplane.PermSandboxRead
	permWrite = controlplane.PermSandboxWrite
	permExec  = controlplane.PermSandboxExec
)

// permissionTag is the registry tag of the facade's two mux patterns.
const permissionTag = "runloop: per call (runloop.permissionFor)"

type handlers struct {
	deps       Deps
	blueprints map[string]string
	creates    *createTracker
	execs      *execTracker
	snapshots  *snapshotTracker
	homes      *homeCache
	recovery   execRecovery
}

func newHandlers(d Deps) *handlers {
	return &handlers{
		deps:       d,
		blueprints: loadBlueprintMap(d.BlueprintMapJSON, d.Logger),
		creates:    newCreateTracker(),
		execs:      newExecTracker(),
		snapshots:  newSnapshotTracker(),
		homes:      newHomeCache(),
	}
}

// RegisterRoutes mounts the facade. Routing below /v1/devboxes is done by
// hand rather than with ServeMux patterns: Runloop puts literal segments
// (create_and_await_running, disk_snapshots, evictions) where devbox ids
// go, and ServeMux panics at registration on pairs such as
// "POST .../disk_snapshots/{sid}" vs "POST .../{id}/shutdown", which
// match the same path with neither more specific.
func RegisterRoutes(mux apihttp.Mux, d Deps) {
	h := newHandlers(d)
	// Executions a previous process left running still owe their session
	// cleanup; re-attach watchers to them off the boot path.
	h.recoverExecutionsInBackground()
	mux.Handle(devboxesPath, d.RouteBy(permissionTag, h.permissionFor, http.HandlerFunc(h.route)))
	mux.Handle(devboxesPath+"/", d.RouteBy(permissionTag, h.permissionFor, http.HandlerFunc(h.route)))
}

// devboxSegments splits the path below /v1/devboxes. ServeMux has already
// redirected any non-clean path, so no segment is empty.
func devboxSegments(r *http.Request) []string {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, devboxesPath), "/")
	if rest == "" {
		return nil
	}
	return strings.Split(rest, "/")
}

// permissionFor is the permission a call needs, read off the same segments
// route() dispatches on and the same devboxActions table, so the check and
// the dispatch cannot disagree. It runs on the edge, before a call is
// forwarded to the devbox's owner (which checks again). A path route()
// does not serve needs sandbox.exec, the strictest team verb, so a caller
// that could not run the call never learns whether it exists.
func (h *handlers) permissionFor(r *http.Request) controlplane.Permission {
	segs := devboxSegments(r)
	switch {
	case len(segs) == 0:
		return readOrWrite(r, http.MethodPost)
	case segs[0] == "create_and_await_running" && len(segs) == 1:
		return permWrite
	case segs[0] == "disk_snapshots":
		return snapshotPermission(segs[1:])
	case segs[0] == "evictions":
		return permRead
	}
	rest := segs[1:]
	switch {
	case len(rest) == 0:
		return readOrWrite(r, http.MethodPost)
	case rest[0] == "executions":
		return permExec
	case len(rest) == 1:
		if action, ok := h.devboxActions()[rest[0]]; ok {
			return action.perm
		}
	}
	return permExec
}

// readOrWrite: the method that changes state needs sandbox.write; any
// other is a read.
func readOrWrite(r *http.Request, writeMethod string) controlplane.Permission {
	if r.Method == writeMethod {
		return permWrite
	}
	return permRead
}

// snapshotPermission classifies /v1/devboxes/disk_snapshots/...: the list
// and a status poll read, everything else (update, delete) writes.
func snapshotPermission(segs []string) controlplane.Permission {
	switch {
	case len(segs) == 0:
		return permRead
	case len(segs) == 2 && segs[1] == "status":
		return permRead
	}
	return permWrite
}

func (h *handlers) route(w http.ResponseWriter, r *http.Request) {
	segs := devboxSegments(r)

	switch {
	case len(segs) == 0:
		h.routeMethod(w, r, map[string]http.HandlerFunc{
			http.MethodGet:  h.listDevboxes,
			http.MethodPost: h.createDevbox,
		})
	case segs[0] == "create_and_await_running" && len(segs) == 1:
		h.routeMethod(w, r, map[string]http.HandlerFunc{http.MethodPost: h.createAndAwaitRunning})
	case segs[0] == "disk_snapshots":
		h.routeSnapshots(w, r, segs[1:])
	case segs[0] == "evictions":
		// Only TS devbox.onEvict() opens this; a 404 is harmless there.
		WriteError(w, http.StatusNotFound, "eviction notices are not supported")
	default:
		r.SetPathValue("id", segs[0])
		h.clusterForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.routeDevbox(w, r, segs[0], segs[1:])
		})).ServeHTTP(w, r)
	}
}

func (h *handlers) routeDevbox(w http.ResponseWriter, r *http.Request, id string, segs []string) {
	if len(segs) == 0 {
		h.routeMethod(w, r, map[string]http.HandlerFunc{
			http.MethodGet:  func(w http.ResponseWriter, r *http.Request) { h.getDevbox(w, r, id) },
			http.MethodPost: func(w http.ResponseWriter, r *http.Request) { h.updateDevbox(w, r, id) },
		})
		return
	}
	if segs[0] == "executions" {
		h.routeExecution(w, r, id, segs[1:])
		return
	}
	if len(segs) != 1 {
		WriteError(w, http.StatusNotFound, "not found")
		return
	}
	action, ok := h.devboxActions()[segs[0]]
	switch {
	case ok && r.Method == action.method:
		action.run(w, r, id)
	case ok:
		WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	default:
		WriteError(w, http.StatusNotFound, "not found")
	}
}

// devboxAction is one call below /v1/devboxes/{id}/: the method it answers,
// the permission it needs, and its handler.
type devboxAction struct {
	method string
	perm   controlplane.Permission
	run    func(http.ResponseWriter, *http.Request, string)
}

// devboxActions is the one table routeDevbox dispatches on and
// permissionFor classifies on. Lifecycle calls write; commands, file
// contents and shells exec (files can hold secrets); a status poll reads.
// Unsupported calls carry the permission the real call would need.
func (h *handlers) devboxActions() map[string]devboxAction {
	post := http.MethodPost
	return map[string]devboxAction{
		"shutdown":             {post, permWrite, h.shutdownDevbox},
		"suspend":              {post, permWrite, h.suspendDevbox},
		"resume":               {post, permWrite, h.resumeDevbox},
		"keep_alive":           {post, permWrite, h.keepAlive},
		"wait_for_status":      {post, permRead, h.waitForDevboxStatus},
		"execute":              {post, permExec, h.execute},
		"execute_async":        {post, permExec, h.executeAsync},
		"execute_sync":         {post, permExec, h.executeSync},
		"read_file_contents":   {post, permExec, h.readFileContents},
		"write_file_contents":  {post, permExec, h.writeFileContents},
		"upload_file":          {post, permExec, h.uploadFile},
		"download_file":        {post, permExec, h.downloadFile},
		"snapshot_disk":        {post, permWrite, h.snapshotDisk},
		"snapshot_disk_async":  {post, permWrite, h.snapshotDiskAsync},
		"enable_tunnel":        {post, permWrite, h.unsupported("tunnels")},
		"remove_tunnel":        {post, permWrite, h.unsupported("tunnels")},
		"create_pty_tunnel":    {post, permExec, h.unsupported("PTY tunnels")},
		"create_ssh_key":       {post, permExec, h.unsupported("devbox SSH keys")},
		"create_gateway_token": {post, permExec, h.unsupported("agent gateways")},
		"create_mcp_token":     {post, permExec, h.unsupported("MCP hub tokens")},
		"logs":                 {http.MethodGet, permExec, h.unsupported("devbox logs")},
		"usage":                {http.MethodGet, permRead, h.unsupported("devbox usage reports")},
	}
}

func (h *handlers) routeExecution(w http.ResponseWriter, r *http.Request, devboxID string, segs []string) {
	if len(segs) == 0 || len(segs) > 2 {
		WriteError(w, http.StatusNotFound, "not found")
		return
	}
	// Captured results live in memory keyed by devbox; the scoped lookup
	// is what keeps another tenant from reading them by id.
	if _, err := h.deps.Service.GetSandbox(r.Context(), devboxID); err != nil {
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	execID := segs[0]
	if len(segs) == 1 {
		h.routeMethod(w, r, map[string]http.HandlerFunc{
			http.MethodGet: func(w http.ResponseWriter, r *http.Request) { h.getExecution(w, r, devboxID, execID) },
		})
		return
	}
	switch segs[1] {
	case "wait_for_status":
		h.routeMethod(w, r, map[string]http.HandlerFunc{
			http.MethodPost: func(w http.ResponseWriter, r *http.Request) { h.waitForExecutionStatus(w, r, devboxID, execID) },
		})
	case "kill":
		h.routeMethod(w, r, map[string]http.HandlerFunc{
			http.MethodPost: func(w http.ResponseWriter, r *http.Request) { h.killExecution(w, r, devboxID, execID) },
		})
	case "send_std_in":
		h.routeMethod(w, r, map[string]http.HandlerFunc{
			http.MethodPost: func(w http.ResponseWriter, r *http.Request) { h.sendStdin(w, r, devboxID, execID) },
		})
	case "stream_stdout_updates":
		h.routeMethod(w, r, map[string]http.HandlerFunc{
			http.MethodGet: func(w http.ResponseWriter, r *http.Request) { h.streamOutput(w, r, devboxID, execID, false) },
		})
	case "stream_stderr_updates":
		h.routeMethod(w, r, map[string]http.HandlerFunc{
			http.MethodGet: func(w http.ResponseWriter, r *http.Request) { h.streamOutput(w, r, devboxID, execID, true) },
		})
	default:
		WriteError(w, http.StatusNotFound, "not found")
	}
}

// routeSnapshots serves /v1/devboxes/disk_snapshots/... A snapshot lives in
// the catalogue of the node that took it, and its id names that node, so
// per-snapshot calls go there — whatever happened to the source devbox
// since. The list is node-local, like the /e2b facade's.
func (h *handlers) routeSnapshots(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) > 0 {
		if node, ok := snapshotHomeNode(segs[0]); ok {
			h.forwardToNode(w, r, node, func(w http.ResponseWriter, r *http.Request) {
				h.routeSnapshotItem(w, r, segs)
			})
			return
		}
	}
	h.routeSnapshotItem(w, r, segs)
}

func (h *handlers) routeSnapshotItem(w http.ResponseWriter, r *http.Request, segs []string) {
	switch {
	case len(segs) == 0:
		h.routeMethod(w, r, map[string]http.HandlerFunc{http.MethodGet: h.listSnapshots})
	case len(segs) == 1:
		h.routeMethod(w, r, map[string]http.HandlerFunc{
			http.MethodPost: func(w http.ResponseWriter, r *http.Request) { h.updateSnapshot(w, r, segs[0]) },
		})
	case len(segs) == 2 && segs[1] == "status":
		h.routeMethod(w, r, map[string]http.HandlerFunc{
			http.MethodGet: func(w http.ResponseWriter, r *http.Request) { h.snapshotStatus(w, r, segs[0]) },
		})
	case len(segs) == 2 && segs[1] == "delete":
		h.routeMethod(w, r, map[string]http.HandlerFunc{
			http.MethodPost: func(w http.ResponseWriter, r *http.Request) { h.deleteSnapshot(w, r, segs[0]) },
		})
	default:
		WriteError(w, http.StatusNotFound, "not found")
	}
}

func (h *handlers) routeMethod(w http.ResponseWriter, r *http.Request, byMethod map[string]http.HandlerFunc) {
	if handler, ok := byMethod[r.Method]; ok {
		handler(w, r)
		return
	}
	WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (h *handlers) unsupported(feature string) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, _ *http.Request, _ string) {
		WriteError(w, http.StatusNotImplemented, feature+" are not supported by this AerolVM Runloop facade")
	}
}

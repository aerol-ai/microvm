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
	"sync"

	"github.com/aerol-ai/microvm/internal/service"
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
	Auth    func(http.Handler) http.Handler
}

type handlers struct {
	deps       Deps
	blueprints map[string]string
	creates    *createTracker
	execs      *execTracker
	snapshots  *snapshotTracker
	shutdowns  *tombstones
	homes      sync.Map // devbox id → resolved $HOME for relative file paths
}

func newHandlers(d Deps) *handlers {
	return &handlers{
		deps:       d,
		blueprints: loadBlueprintMap(d.Logger),
		creates:    newCreateTracker(),
		execs:      newExecTracker(),
		snapshots:  newSnapshotTracker(),
		shutdowns:  newTombstones(),
	}
}

// RegisterRoutes mounts the facade. Routing below /v1/devboxes is done by
// hand rather than with ServeMux patterns: Runloop puts literal segments
// (create_and_await_running, disk_snapshots, evictions) where devbox ids
// go, and ServeMux panics at registration on pairs such as
// "POST .../disk_snapshots/{sid}" vs "POST .../{id}/shutdown", which
// match the same path with neither more specific.
func RegisterRoutes(mux *http.ServeMux, d Deps) {
	h := newHandlers(d)
	mux.Handle(devboxesPath, d.Auth(http.HandlerFunc(h.route)))
	mux.Handle(devboxesPath+"/", d.Auth(http.HandlerFunc(h.route)))
}

func (h *handlers) route(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, devboxesPath), "/")
	var segs []string
	if rest != "" {
		segs = strings.Split(rest, "/")
	}
	for _, seg := range segs {
		if seg == "" {
			WriteError(w, http.StatusNotFound, "not found")
			return
		}
	}

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
	posts := map[string]func(http.ResponseWriter, *http.Request, string){
		"shutdown":             h.shutdownDevbox,
		"suspend":              h.suspendDevbox,
		"resume":               h.resumeDevbox,
		"keep_alive":           h.keepAlive,
		"wait_for_status":      h.waitForDevboxStatus,
		"execute":              h.execute,
		"execute_async":        h.executeAsync,
		"execute_sync":         h.executeSync,
		"read_file_contents":   h.readFileContents,
		"write_file_contents":  h.writeFileContents,
		"upload_file":          h.uploadFile,
		"download_file":        h.downloadFile,
		"snapshot_disk":        h.snapshotDisk,
		"snapshot_disk_async":  h.snapshotDiskAsync,
		"enable_tunnel":        h.unsupported("tunnels"),
		"remove_tunnel":        h.unsupported("tunnels"),
		"create_pty_tunnel":    h.unsupported("PTY tunnels"),
		"create_ssh_key":       h.unsupported("devbox SSH keys"),
		"create_gateway_token": h.unsupported("agent gateways"),
		"create_mcp_token":     h.unsupported("MCP hub tokens"),
	}
	gets := map[string]func(http.ResponseWriter, *http.Request, string){
		"logs":  h.unsupported("devbox logs"),
		"usage": h.unsupported("devbox usage reports"),
	}
	action := segs[0]
	post, isPost := posts[action]
	get, isGet := gets[action]
	switch {
	case isPost && r.Method == http.MethodPost:
		post(w, r, id)
	case isGet && r.Method == http.MethodGet:
		get(w, r, id)
	case isPost || isGet:
		WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	default:
		WriteError(w, http.StatusNotFound, "not found")
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

// routeSnapshots serves /v1/devboxes/disk_snapshots/... Snapshots live in
// the node-local catalogue of the node that took them. A facade snapshot
// id names its source devbox, so per-snapshot calls follow that devbox to
// its owner while it exists; the list (like the /e2b facade's) is local.
func (h *handlers) routeSnapshots(w http.ResponseWriter, r *http.Request, segs []string) {
	if len(segs) > 0 {
		if devboxID, ok := snapshotSourceDevbox(segs[0]); ok {
			r.SetPathValue("id", devboxID)
			h.clusterForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h.routeSnapshotItem(w, r, segs)
			})).ServeHTTP(w, r)
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

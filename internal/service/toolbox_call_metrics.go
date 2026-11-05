package service

import (
	"bufio"
	"context"
	"errors"
	"expvar"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/internal/store"
)

// aerolvm_toolbox_calls_total counts toolbox calls by API surface (key),
// route class (key2) and status class (key3), so a release that breaks a
// file, exec, watch or terminal call shows at once, and the 501s show which
// unsupported features callers try (plans/agent-sandbox-feature-parity.md,
// O4). Every class set is fixed and small: at most 5 x 8 x 5 series, with no
// per-sandbox label.
var toolboxCallsTotal = expvar.NewMap("aerolvm_toolbox_calls_total")

// toolboxCallsMu guards creating the nested maps; expvar.Map is safe for
// concurrent Add but not for get-or-create of a child map.
var toolboxCallsMu sync.Mutex

// Surfaces a toolbox call can come from.
const (
	ToolboxSurfaceV1      = "v1"
	ToolboxSurfaceDaytona = "daytona"
	ToolboxSurfaceE2B     = "e2b"
	ToolboxSurfaceRunloop = "runloop"
	toolboxSurfaceOther   = "other"
)

type toolboxSurfaceKey struct{}

// WithToolboxSurface marks ctx with the API surface its toolbox calls come
// from. Each facade sets it once at its entry point.
func WithToolboxSurface(ctx context.Context, surface string) context.Context {
	return context.WithValue(ctx, toolboxSurfaceKey{}, surface)
}

func toolboxSurface(ctx context.Context) string {
	if surface, ok := ctx.Value(toolboxSurfaceKey{}).(string); ok && surface != "" {
		return surface
	}
	return toolboxSurfaceOther
}

// toolboxRouteClass maps a toolboxd path to a small fixed set of classes.
// Watch is checked before files: /files/watch and the envd watcher RPCs are
// file paths too.
func toolboxRouteClass(path string) string {
	switch {
	case path == "/files/watch" || strings.HasPrefix(path, "/files/watch/") ||
		strings.Contains(path, "Filesystem/WatchDir") || strings.Contains(path, "Filesystem/CreateWatcher") ||
		strings.Contains(path, "Filesystem/GetWatcherEvents") || strings.Contains(path, "Filesystem/RemoveWatcher"):
		return "watch"
	case path == "/files" || strings.HasPrefix(path, "/files/") || path == "/envd/files" ||
		strings.HasPrefix(path, "/envd/filesystem.Filesystem/"):
		return "files"
	case path == "/process/execute" || path == "/process/code-run":
		return "exec"
	case path == "/process/exec/stream" || strings.HasPrefix(path, "/envd/process.Process/"):
		return "exec_stream"
	case path == "/sessions" || strings.HasPrefix(path, "/sessions/") ||
		path == "/process/session" || strings.HasPrefix(path, "/process/session/"):
		return "sessions"
	case path == "/process/pty" || strings.HasPrefix(path, "/process/pty/"):
		return "pty"
	case path == "/lsp" || strings.HasPrefix(path, "/lsp/"):
		return "lsp"
	}
	return "other"
}

// toolboxStatusClass folds a status into 2xx, 4xx, 501, 5xx or other. A
// WebSocket upgrade (101) is a success.
func toolboxStatusClass(status int) string {
	switch {
	case status == http.StatusSwitchingProtocols, status >= 200 && status < 300:
		return "2xx"
	case status == http.StatusNotImplemented:
		return "501"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500:
		return "5xx"
	}
	return "other"
}

// toolboxErrorStatus is the status a toolbox call that failed before any
// response would get from the API: a stopped or missing sandbox is the
// caller's 4xx, anything else is a gateway failure.
func toolboxErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrSandboxNotRunning):
		return http.StatusConflict
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, context.Canceled):
		return 499
	}
	return http.StatusBadGateway
}

// RecordToolboxCall counts one toolbox call.
func RecordToolboxCall(ctx context.Context, path string, status int) {
	surface := toolboxSurface(ctx)
	route := toolboxRouteClass(path)
	class := toolboxStatusClass(status)
	toolboxCallsMu.Lock()
	routes := childMap(toolboxCallsTotal, surface)
	classes := childMap(routes, route)
	toolboxCallsMu.Unlock()
	classes.Add(class, 1)
}

func childMap(parent *expvar.Map, key string) *expvar.Map {
	if existing, ok := parent.Get(key).(*expvar.Map); ok {
		return existing
	}
	child := new(expvar.Map).Init()
	parent.Set(key, child)
	return child
}

// ToolboxStatusRecorder remembers the status a toolbox response wrote. It
// keeps WebSocket upgrades (Hijack, recorded as 101) and streaming (Flush)
// working for the reverse proxy.
type ToolboxStatusRecorder struct {
	http.ResponseWriter
	status int
}

// NewToolboxStatusRecorder wraps w.
func NewToolboxStatusRecorder(w http.ResponseWriter) *ToolboxStatusRecorder {
	return &ToolboxStatusRecorder{ResponseWriter: w}
}

// Status is the written status, or 0 when nothing was written.
func (r *ToolboxStatusRecorder) Status() int { return r.status }

func (r *ToolboxStatusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *ToolboxStatusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *ToolboxStatusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *ToolboxStatusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, rw, err := hj.Hijack()
	if err == nil && r.status == 0 {
		r.status = http.StatusSwitchingProtocols
	}
	return conn, rw, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *ToolboxStatusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

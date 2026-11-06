// Package toolhost implements the host-side toolbox for WASM sandboxes
// (plans/wasm-runtime.md §3).
package toolhost

import (
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/internal/version"
)

// Host serves toolbox HTTP routes against a sandbox workdir on the host.
type Host struct {
	sandboxID string
	workDir   string
	authToken string
	exec      Executor
	stateKV   StateKV
	sessions  *sessions.Manager
	daytona   *daytonaCompat
}

// Config wires a toolbox host for one sandbox.
type Config struct {
	SandboxID string
	WorkDir   string
	AuthToken string
	Exec      Executor
	StateKV   StateKV
	Sessions  *sessions.Manager
}

// New constructs a toolbox host.
func New(cfg Config) *Host {
	h := &Host{
		sandboxID: cfg.SandboxID,
		workDir:   cfg.WorkDir,
		authToken: cfg.AuthToken,
		exec:      cfg.Exec,
		stateKV:   cfg.StateKV,
		sessions:  cfg.Sessions,
	}
	if h.sessions != nil {
		h.daytona = newDaytonaCompat()
	}
	return h
}

// Handler returns an http.Handler implementing the core toolbox surface.
func (h *Host) Handler() http.Handler {
	return http.HandlerFunc(h.serveHTTP)
}

func (h *Host) serveHTTP(w http.ResponseWriter, r *http.Request) {
	r = h.stripSandboxPrefix(r)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/":
		writeJSON(w, http.StatusOK, map[string]any{
			"sandbox_id": h.sandboxID,
			"version":    version.Version,
			"runtime":    "wasm",
		})
	case r.Method == http.MethodGet && r.URL.Path == "/health":
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": version.Version})
	case r.Method == http.MethodGet && r.URL.Path == "/version":
		// The WASM host supports none of toolboxd's newer request options;
		// an empty list makes the SDKs refuse them instead of sending them.
		// "runtime" lets the SDKs say why: a restart or a new template, the
		// advice for an older toolboxd, cannot add them here.
		writeJSON(w, http.StatusOK, map[string]any{"version": version.Version, "features": []string{}, "runtime": "wasm"})
	case r.Method == http.MethodPost && r.URL.Path == "/process/execute":
		if !h.requireAuth(w, r) {
			return
		}
		h.handleExec(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/process/code-run":
		if !h.requireAuth(w, r) {
			return
		}
		h.handleCodeRun(w, r)
	case strings.HasPrefix(r.URL.Path, "/process/interpreter/"):
		if !h.requireAuth(w, r) {
			return
		}
		writeError(w, http.StatusNotImplemented, "codeInterpreter is not implemented for wasm runtime")
	case strings.HasPrefix(r.URL.Path, "/process/session"):
		if !h.requireAuth(w, r) {
			return
		}
		if !h.handleDaytonaProcessRoute(w, r) {
			writeError(w, http.StatusNotFound, "not found")
		}
	case r.Method == http.MethodPost && r.URL.Path == "/files/upload":
		if !h.requireAuth(w, r) {
			return
		}
		h.handleUpload(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/files/download":
		if !h.requireAuth(w, r) {
			return
		}
		h.handleDownload(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/files":
		if !h.requireAuth(w, r) {
			return
		}
		h.handleListFiles(w, r)
	case strings.HasPrefix(r.URL.Path, "/state/kv"):
		if !h.requireAuth(w, r) {
			return
		}
		h.handleStateKV(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/process/exec/stream":
		if !h.requireAuth(w, r) {
			return
		}
		h.handleExecStream(w, r)
	case strings.HasPrefix(r.URL.Path, "/sessions"):
		if !h.requireAuth(w, r) {
			return
		}
		if !h.handleSessionsRoute(w, r) {
			writeError(w, http.StatusNotFound, "not found")
		}
	case r.URL.Path == "/files/watch":
		// A WASM sandbox's files live on the host and change only through
		// this host's own handlers; there is no kernel to watch. Same answer
		// as toolboxd on a shared kernel (plan F5, Q8).
		if !h.requireAuth(w, r) {
			return
		}
		writeError(w, http.StatusNotImplemented, "file watching needs a gVisor or Firecracker sandbox")
	case isUnsupportedWasmToolboxRoute(r):
		// Routes the Daytona facade forwards that a WASM sandbox has no
		// filesystem or terminal for. A 501 with a reason, not the default
		// 404, which reads as a bug (plan B1).
		if !h.requireAuth(w, r) {
			return
		}
		writeError(w, http.StatusNotImplemented, "not supported on WASM sandboxes")
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

// isUnsupportedWasmToolboxRoute lists the toolbox routes toolboxd serves for
// container and VM sandboxes but the WASM host does not. Beyond plain upload,
// download and list, the file verbs the SDKs added (plan F1) answer 501 here
// too: info, move, copy, search and find.
func isUnsupportedWasmToolboxRoute(r *http.Request) bool {
	path := r.URL.Path
	switch {
	case r.Method == http.MethodDelete && path == "/files":
		return true
	case r.Method == http.MethodPost && (path == "/files/folder" || path == "/files/replace" || path == "/files/permissions"):
		return true
	case r.Method == http.MethodPost && (path == "/files/move" || path == "/files/copy"):
		return true
	case r.Method == http.MethodGet && (path == "/files/info" || path == "/files/search" || path == "/files/find"):
		return true
	case r.Method == http.MethodHead && path == "/files/download":
		// Plan F4: HEAD and Range are toolboxd's; this host serves the
		// plain download only.
		return true
	case path == "/lsp" || strings.HasPrefix(path, "/lsp/"):
		return true
	case path == "/process/pty" || strings.HasPrefix(path, "/process/pty/"):
		return true
	}
	return false
}

func (h *Host) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if h.authToken == "" {
		return true
	}
	const prefix = "Bearer "
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, prefix) || strings.TrimPrefix(authorization, prefix) != h.authToken {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

func (h *Host) stripSandboxPrefix(r *http.Request) *http.Request {
	path := r.URL.Path
	if h.sandboxID != "" {
		prefix := "/" + h.sandboxID
		if path == prefix || path == prefix+"/" {
			path = "/"
		} else if strings.HasPrefix(path, prefix+"/") {
			path = strings.TrimPrefix(path, prefix)
			if path == "" {
				path = "/"
			}
		}
	}
	r.URL.Path = path
	return r
}

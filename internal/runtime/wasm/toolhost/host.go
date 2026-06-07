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
		writeJSON(w, http.StatusOK, map[string]any{"version": version.Version})
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
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
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

package toolhost

import "net/http"

// Streaming exec is intentionally unsupported on the WASM runtime, and the
// endpoint fails closed with 501.
//
// Why it cannot be served: this toolhost runs IN-PROCESS inside sandboxd, on
// the host. "exec" in a WASM sandbox means invoking an exported function /
// re-instantiating the module inside the wasm engine (plans/wasm-runtime.md),
// which is exactly what the confined POST /process/execute path does via the
// Executor. There is no in-engine equivalent of an interactive, streaming PTY,
// so the only way to implement streaming here would be to spawn a host process
// (`/bin/sh -c <caller command>`) — which is arbitrary command execution on the
// host as the daemon user, NOT execution inside the sandbox. That is a sandbox
// escape, so the host-exec path has been removed entirely rather than left
// dormant. 501 matches the other unsupported wasm toolhost routes
// (codeInterpreter, sessions, statekv).
func (h *Host) handleExecStream(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotImplemented,
		"streaming exec is not supported on the wasm runtime; use POST /process/execute")
}

package toolhost

import (
	"net/http"
	"strings"
)

// The native /sessions routes (create, list, get, delete, signal, resize,
// log, recording, attach) are interactive terminals: a long-lived shell
// with a pty, attach, resize and recordings. A WASM sandbox has no shell
// and no terminal, and this toolhost runs IN-PROCESS in sandboxd on the
// host, so it must never start one (#534 removed a host shell from here).
// Every action answers 501, read-only ones too, so a caller cannot mistake
// an empty session list for a working feature.
//
// What does work on WASM, inside the engine: Daytona-style command
// sessions (/process/session, process_session.go, issue #178), a streamed
// command (GET /process/exec/stream) and a one-shot run (POST
// /process/execute). Sessions in docker / gvisor / firecracker sandboxes
// are served by toolboxd inside the guest and are unaffected.
func (h *Host) handleSessions(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotImplemented,
		"interactive sessions (/sessions) are not supported on the wasm runtime: a wasm sandbox has no shell or terminal; "+
			"use /process/session for command sessions or GET /process/exec/stream to stream a command")
}

// isNativeSessionPath reports whether path is /sessions or under it. A
// sibling such as /sessionsX is not, and falls through to the toolbox's 404.
func isNativeSessionPath(path string) bool {
	return path == "/sessions" || strings.HasPrefix(path, "/sessions/")
}

// isProcessSessionPath is the same for the Daytona-compatible family the
// Daytona and Runloop facades call.
func isProcessSessionPath(path string) bool {
	return path == "/process/session" || strings.HasPrefix(path, "/process/session/")
}

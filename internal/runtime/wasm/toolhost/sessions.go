package toolhost

import (
	"net/http"
	"strings"
)

// Sessions are intentionally unsupported on the WASM runtime, and every session
// route fails closed with 501.
//
// Like code-run (coderun.go) and streaming exec (exec_stream.go), this toolhost
// runs IN-PROCESS in sandboxd, on the host. The /sessions routes (create, list,
// get, delete, signal, resize, log, recording, attach) and the Daytona-style
// /process/session routes (create, list, get, delete, exec, and a command's
// get / logs / input) were backed by the toolboxd sessions Manager, which starts
// a session's shell and commands with exec.Command — on the host, as the daemon
// user, in the daemon's environment, NOT inside the sandbox. A WASM sandbox has
// no shell: the engine runs the sandbox's own module, and there is no in-engine
// equivalent of a long-lived interactive process. So the host path is removed
// rather than left dormant, and the driver no longer builds a Manager at all.
//
// Every action answers 501, read-only ones too, so a caller cannot mistake an
// empty session list for a working feature. To run a command IN a wasm sandbox,
// use the confined POST /process/execute, which runs the module inside the
// engine. Sessions in docker / gvisor / firecracker sandboxes are served by
// toolboxd inside the guest and are unaffected.
func (h *Host) handleSessions(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotImplemented,
		"sessions are not supported on the wasm runtime; use POST /process/execute")
}

// sessionRoots are the two session route families: the native toolbox one and
// the Daytona-compatible one the Daytona and Runloop facades call.
var sessionRoots = [...]string{"/sessions", "/process/session"}

// isSessionPath reports whether path is a session root or under one. A sibling
// such as /sessionsX is not, and falls through to the toolbox's 404.
func isSessionPath(path string) bool {
	for _, root := range sessionRoots {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

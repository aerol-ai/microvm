package toolhost

import "net/http"

// Code-run is intentionally unsupported on the WASM runtime, and the endpoint
// fails closed with 501.
//
// Like streaming exec (see exec_stream.go), this toolhost runs IN-PROCESS in
// sandboxd, on the host. handleCodeRun previously wrote caller-supplied code to
// a script and ran it through a host interpreter (python3 / node / bash, …) via
// exec.CommandContext — i.e. arbitrary code execution on the host as the daemon
// user, NOT inside the sandbox. There is no confined, in-engine equivalent: the
// wasm engine runs the sandbox's own module, not an arbitrary host interpreter.
// So the host path is removed rather than left dormant, matching the already-
// disabled codeInterpreter route.
//
// To run code IN a wasm sandbox, create it from the matching language module
// (e.g. CPython-on-wasm) and use the confined POST /process/execute, which runs
// inside the engine. The in-container toolboxd code-run (docker / firecracker)
// is a separate implementation that runs inside the guest and is unaffected.
func (h *Host) handleCodeRun(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotImplemented,
		"code-run is not supported on the wasm runtime; create the sandbox from a language module and use POST /process/execute")
}

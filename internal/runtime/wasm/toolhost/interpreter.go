package toolhost

import (
	"net/http"
	"strings"
)

// Code interpreter on WASM (issue #178, plans/code-interpreter.md W5). The
// protocol adapters are the shared ones toolboxd uses
// (internal/codeinterp/daytona and internal/codeinterp/e2b); every context
// is a python.wasm instance in the sandbox's own worker, never a host
// process. Their state (contexts, kernels, the per-sandbox cap) outlives a
// request, so it lives on the driver and this host only mounts it.

// Interpreters gives the host the sandbox's interpreter handlers. The WASM
// driver implements it.
type Interpreters interface {
	// Daytona serves Daytona's codeInterpreter protocol, which the AerolVM
	// SDKs speak too, with paths relative to /process/interpreter.
	Daytona() http.Handler
	// E2B serves E2B's Code Interpreter protocol, with paths relative to
	// /interpreter/e2b (the E2B facade sends port-49999 calls there).
	E2B() http.Handler
}

const (
	daytonaInterpreterPrefix = "/process/interpreter"
	e2bInterpreterPrefix     = "/interpreter/e2b"
)

// Limits the WASM driver builds the interpreter adapters with. On toolboxd
// a request's code and the runs queued for a context are held in the
// sandbox's own memory; here they are held in sandboxd's heap, shared by
// every sandbox on the host, so the caps are far below toolboxd's (32 MiB
// and 128 runs).
const (
	// InterpreterMaxRequestBytes caps one Daytona WebSocket message and one
	// E2B request body.
	InterpreterMaxRequestBytes = 8 << 20
	// InterpreterQueueLimit caps the runs waiting for one context.
	InterpreterQueueLimit = 8
)

// isE2BInterpreterPath reports whether path is under the E2B interpreter.
func isE2BInterpreterPath(path string) bool {
	return strings.HasPrefix(path, e2bInterpreterPrefix+"/")
}

// handleInterpreter serves an interpreter route with prefix stripped.
func (h *Host) handleInterpreter(w http.ResponseWriter, r *http.Request, prefix string) {
	if h.interp == nil {
		writeError(w, http.StatusNotImplemented, "codeInterpreter is not implemented for wasm runtime")
		return
	}
	handler := h.interp.Daytona
	if prefix == e2bInterpreterPrefix {
		handler = h.interp.E2B
	}
	// Like toolboxd's stripPathPrefix, not http.StripPrefix: the sandbox
	// prefix was cut from URL.Path only, so an escaped RawPath still carries
	// it and would no longer match.
	r2 := new(http.Request)
	*r2 = *r
	u := *r.URL
	u.Path = strings.TrimPrefix(r.URL.Path, prefix)
	u.RawPath = ""
	r2.URL = &u
	handler().ServeHTTP(w, r2)
}

// features is the /version feature list. The WASM host supports none of
// toolboxd's newer request options; it names the interpreter when it has
// one, so the SDKs' feature gate lets their interpreter calls through.
func (h *Host) features() []string {
	if h.interp == nil {
		// Empty, not null: the SDKs read the list.
		return []string{}
	}
	return []string{"code.interpreter"}
}

package main

import (
	"net/http"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	cie2b "github.com/aerol-ai/microvm/internal/codeinterp/e2b"
)

// e2bInterpPrefix is where toolboxd serves E2B's Code Interpreter, the
// server E2B runs on sandbox port 49999. The E2B facade sends requests
// that carry E2b-Sandbox-Port: 49999 here (plans/code-interpreter.md D7).
const e2bInterpPrefix = "/interpreter/e2b"

// e2bInterpOptions is a var so tests can keep their contexts out of
// /home/user.
var e2bInterpOptions = cie2b.ManagerOptions

// e2bInterpreter returns the E2B interpreter's handler, built on first use
// so boot starts nothing and only a sandbox that uses it gets a
// /home/user. It has its own Manager, so E2B's per-language defaults never
// meet Daytona's "default" context, and shares the sandbox's context cap.
func (s *server) e2bInterpreter() http.Handler {
	s.e2bInterpOnce.Do(func() {
		state := s.codeInterp()
		m := codeinterp.NewManager(e2bInterpOptions(state.launcher, state.limit))
		s.e2bInterp = http.StripPrefix(e2bInterpPrefix, cie2b.NewHandler(m, s.logger))
	})
	return s.e2bInterp
}

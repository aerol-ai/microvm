package main

import (
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	"github.com/aerol-ai/microvm/internal/codeinterp/daytona"
	"github.com/aerol-ai/microvm/internal/codeinterp/proc"
)

// codeInterpContextLimit caps interpreter contexts per sandbox across the
// Daytona and E2B adapters. Each context is a live interpreter process in
// the sandbox, so the cap mirrors the terminal cap (daytonaPTYLimit).
const codeInterpContextLimit = 32

// codeInterpState is the launcher and context cap the interpreter adapters
// share (plans/code-interpreter.md). It is built on first use: nothing is
// started at boot.
type codeInterpState struct {
	launcher codeinterp.Launcher
	limit    *codeinterp.Limit

	// daytona serves /process/interpreter/ (Daytona's protocol, which the
	// AerolVM SDKs speak too), made on its first request.
	daytonaOnce sync.Once
	daytonaMgr  *codeinterp.Manager
	daytona     http.Handler
}

// newCodeInterpLauncher is a var so tests can swap in a fake launcher.
var newCodeInterpLauncher = func() codeinterp.Launcher {
	return proc.New(proc.Config{
		Start: func(cmd *exec.Cmd) (func() error, error) {
			child, err := startTracked(cmd)
			if err != nil {
				return nil, err
			}
			return child.wait, nil
		},
		Env: childEnviron,
	})
}

// codeInterp returns the shared interpreter state, creating it once.
func (s *server) codeInterp() *codeInterpState {
	s.interpOnce.Do(func() {
		s.interp = &codeInterpState{
			launcher: newCodeInterpLauncher(),
			limit:    codeinterp.NewLimit(codeInterpContextLimit),
		}
	})
	return s.interp
}

// daytonaInterpreter is the handler for /process/interpreter/, with that
// prefix stripped before the adapter sees the path.
func (s *server) daytonaInterpreter() http.Handler {
	st := s.codeInterp()
	st.daytonaOnce.Do(func() {
		// Daytona's default context starts in the sandbox's working folder:
		// toolboxd runs in the image's WORKDIR.
		cwd, err := os.Getwd()
		if err != nil {
			cwd = "/"
		}
		st.daytonaMgr = codeinterp.NewManager(daytona.ManagerOptions(st.launcher, st.limit, cwd))
		st.daytona = stripPathPrefix("/process/interpreter", daytona.NewHandler(st.daytonaMgr, s.logger))
	})
	return st.daytona
}

// stripPathPrefix is http.StripPrefix for toolboxd's routes. stripSandboxPrefix
// rewrites only URL.Path, and http.StripPrefix answers 404 when an escaped
// URL.RawPath still carries the sandbox id.
func stripPathPrefix(prefix string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := new(http.Request)
		*r2 = *r
		u := *r.URL
		u.Path = strings.TrimPrefix(r.URL.Path, prefix)
		u.RawPath = ""
		r2.URL = &u
		h.ServeHTTP(w, r2)
	})
}

// closeCodeInterp kills every interpreter the adapters started. toolboxd
// itself never needs it (its exit ends the sandbox); tests do.
func (s *server) closeCodeInterp() {
	s.interpOnce.Do(func() {})
	if st := s.interp; st != nil {
		st.daytonaOnce.Do(func() {})
		if st.daytonaMgr != nil {
			st.daytonaMgr.Close()
		}
	}
}

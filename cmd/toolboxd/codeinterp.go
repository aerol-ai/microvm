package main

import (
	"os/exec"

	"github.com/aerol-ai/microvm/internal/codeinterp"
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

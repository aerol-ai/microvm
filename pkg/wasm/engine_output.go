package wasm

import (
	"io"

	"github.com/tetratelabs/wazero"
)

// InstanceOutputSetter is an engine whose serving instance (the one
// Instantiate creates and InvokeExport calls) can write its stdout and
// stderr somewhere instead of dropping them. The worker gives it a bounded
// buffer, the sandbox's entrypoint log (issue #178). Run keeps its own
// capture: a one-shot exec's output is its result, not the entrypoint's.
type InstanceOutputSetter interface {
	SetInstanceOutput(stdout, stderr io.Writer)
}

// SetInstanceOutput applies from the next Instantiate on. The writers are
// called from the guest's goroutine and must not block.
func (e *wazeroEngine) SetInstanceOutput(stdout, stderr io.Writer) {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	e.instOut, e.instErr = stdout, stderr
}

// withInstanceOutput adds the serving instance's writers to cfg. Caller
// holds lifecycleMu.
func (e *wazeroEngine) withInstanceOutput(cfg wazero.ModuleConfig) wazero.ModuleConfig {
	if e.instOut != nil {
		cfg = cfg.WithStdout(e.instOut)
	}
	if e.instErr != nil {
		cfg = cfg.WithStderr(e.instErr)
	}
	return cfg
}

// ExitCode is the exit code an InvokeExport error stands for: 0 for nil,
// the guest's code for a guest exit, 1 for anything else (a trap, an
// instance closed under the call).
func ExitCode(err error) int {
	return exitCodeFromInvoke(err)
}

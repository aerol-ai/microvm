// Package proc starts code interpreter kernels as local processes (the
// toolboxd launcher). Each kernel is a driver script run by the language's
// interpreter, speaking the codeinterp driver protocol in "fd" mode: requests
// on fd 3, events on fd 4, user output on fd 1 and 2.
package proc

import (
	"context"
	"errors"
	"os/exec"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// StartFunc starts cmd and returns the function that waits for it. toolboxd
// is PID 1 and reaps every child, so it passes its child-table start; a
// plain cmd.Start + cmd.Wait would lose exit statuses to the reaper.
type StartFunc func(cmd *exec.Cmd) (wait func() error, err error)

// Config configures a Launcher.
type Config struct {
	// Start starts a kernel process. Nil means cmd.Start and cmd.Wait.
	Start StartFunc
	// Env returns the base environment of every kernel (toolboxd: the image
	// env plus the sandbox env). Interpreters are looked up on its PATH.
	Env func() []string
	// DriverDir holds the driver scripts, written on first use with mode
	// 0700. Empty means a directory under os.TempDir().
	DriverDir string
}

// Launcher implements codeinterp.Launcher with local processes.
type Launcher struct {
	cfg Config
}

// New returns a Launcher. It starts nothing.
func New(cfg Config) *Launcher { return &Launcher{cfg: cfg} }

// Launch starts a kernel for spec.
func (l *Launcher) Launch(ctx context.Context, spec codeinterp.Spec) (codeinterp.Kernel, error) {
	return nil, errors.New("codeinterp/proc: not implemented yet")
}

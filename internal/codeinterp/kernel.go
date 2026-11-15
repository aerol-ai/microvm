package codeinterp

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Errors the Manager and launchers return. Adapters map them to each
// protocol's status codes.
var (
	ErrNotFound            = errors.New("context not found")
	ErrDefaultContext      = errors.New("the default context cannot be deleted")
	ErrLimit               = errors.New("too many interpreter contexts")
	ErrQueueFull           = errors.New("too many runs waiting for this context")
	ErrUnsupportedLanguage = errors.New("unsupported language")
	ErrClosed              = errors.New("interpreter manager is closed")
)

// MissingInterpreterError says the sandbox image has no program for a
// language. Its message names the programs that were looked for, so a user
// knows what to install.
type MissingInterpreterError struct {
	Language string
	Programs []string
	Detail   string
}

func (e *MissingInterpreterError) Error() string {
	msg := fmt.Sprintf("%s interpreter not found in the sandbox (looked for %v)", e.Language, e.Programs)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// EventKind says what an Event carries.
type EventKind int

const (
	// EventCount starts a run and carries its execution count.
	EventCount EventKind = iota + 1
	EventStdout
	EventStderr
	// EventResult is a rich value: a MIME bundle such as text/plain, image/png.
	EventResult
	// EventError is the run's exception. A run has at most one.
	EventError
)

// Event is one piece of a run's output, in the order the kernel produced it.
type Event struct {
	Kind  EventKind
	Count int
	// Text is the output for EventStdout and EventStderr.
	Text string
	// Bundle maps a MIME type to its value for EventResult. Values are
	// strings, except application/json and the AerolVM "e2b/data" key, which
	// hold decoded JSON.
	Bundle map[string]any
	// Main is true for the value of the run's last expression, false for
	// values shown with display() or for figures.
	Main bool

	ErrName      string
	ErrValue     string
	ErrTraceback string
}

// Sink receives a run's events. A kernel calls it from one goroutine at a
// time, in order. It may block; a slow client then slows the run down
// instead of losing output.
type Sink func(Event)

// Request is one run.
type Request struct {
	Code string
	// Env is set for this run only and restored afterwards.
	Env map[string]string
}

// Outcome is how a run ended.
type Outcome struct {
	// Status is "ok", "error" or "interrupted", from the driver's DONE.
	Status string
	// Died is true when the interpreter process exited (or was killed)
	// before the run finished. The context then needs a new kernel.
	Died bool
}

// Interrupted reports whether the run was interrupted.
func (o Outcome) Interrupted() bool { return o.Status == "interrupted" }

// Kernel is one interpreter process.
type Kernel interface {
	// Execute runs req and blocks until the run ends or the process dies.
	// Only one Execute runs at a time; the Manager guarantees it.
	Execute(req Request, sink Sink) (Outcome, error)
	// Interrupt asks the running code to stop (SIGINT, or a kill on WASM).
	Interrupt() error
	// Close kills the process. It is safe to call more than once.
	Close() error
	// Done is closed when the process has exited.
	Done() <-chan struct{}
}

// Spec says what kind of kernel to start.
type Spec struct {
	Language string
	Cwd      string
	// Env is added to the kernel's base environment.
	Env map[string]string
}

// Launcher starts kernels. ctx bounds the start only; the kernel outlives
// it.
type Launcher interface {
	Launch(ctx context.Context, spec Spec) (Kernel, error)
}

// LaunchTimeout bounds how long a driver may take to say READY. Java's
// single-file source launch plus JShell start is the slowest, a few
// seconds on a small sandbox.
const LaunchTimeout = 60 * time.Second

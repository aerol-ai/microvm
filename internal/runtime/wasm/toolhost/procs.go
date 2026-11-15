package toolhost

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Processes starts confined runs for the exec stream and code-run. The WASM
// driver implements it: every run is a guest instance inside the wasm
// engine in the sandbox's worker. This toolhost runs in sandboxd on the
// host, so it must never start a host process itself (#534 removed exactly
// that); Processes is the only way it runs caller code.
type Processes interface {
	// CanStart reports, before a WebSocket upgrade, whether the sandbox has
	// room for another run (ErrTooManyProcesses when not), so the caller
	// gets HTTP 429 instead of an upgrade that fails at once.
	CanStart() error
	// StartStream runs a command on the sandbox's own module.
	StartStream(ctx context.Context, spec StreamSpec) (ProcessStream, error)
	// StartCodeRun runs code with the language's module. An unknown or
	// unconfigured language returns a *CodeRunLanguageError.
	StartCodeRun(ctx context.Context, spec CodeRunSpec) (ProcessStream, error)
}

// StreamSpec is a run of the sandbox's own module.
type StreamSpec struct {
	// Args is argv, including argv[0].
	Args []string
	Env  map[string]string
	// Stdin opens the run's stdin; NoDeadline lets it run until it exits or
	// is killed.
	Stdin      bool
	NoDeadline bool
}

// CodeRunSpec is one /process/code-run request.
type CodeRunSpec struct {
	Language       string
	Code           string
	Argv           []string
	Env            map[string]string
	Timeout        time.Duration
	MaxOutputBytes int64
}

// ProcessStream is a live run. Close must always be called.
type ProcessStream interface {
	Recv() (ProcessEvent, error)
	WriteStdin(p []byte) error
	CloseStdin() error
	Kill() error
	Close() error
}

// ProcessEvent is output from a run, or its exit (last).
type ProcessEvent struct {
	Stdout []byte
	Stderr []byte
	Exit   *ProcessExit
}

// ProcessExit is how a run ended. ExitCode is -1 when it was killed or timed
// out.
type ProcessExit struct {
	ExitCode  int
	Killed    bool
	TimedOut  bool
	Truncated bool
	// Error is set when the guest trapped (for example, ran out of memory).
	Error string
}

var (
	// ErrStreamingUnsupported: the sandbox's worker cannot stream (adopted
	// from an older sandboxd, or on the wasmtime engine). HTTP 501.
	ErrStreamingUnsupported = errors.New("streaming runs are not supported by this wasm sandbox's worker; restarting the sandbox on a wazero node fixes it")
	// ErrTooManyProcesses: the sandbox is at its run cap. HTTP 429.
	ErrTooManyProcesses = errors.New("this wasm sandbox already runs the maximum number of processes (SB_WASM_MAX_STREAMS_PER_SANDBOX)")
	// ErrSandboxNotRunning: the sandbox is stopped, or is being stopped or
	// passivated, and takes no new runs. HTTP 409.
	ErrSandboxNotRunning = errors.New("the wasm sandbox is not running")
)

// CodeRunLanguageError is a code-run language the node cannot run. HTTP 400.
type CodeRunLanguageError struct {
	Message string
}

func (e *CodeRunLanguageError) Error() string { return e.Message }

// processErrorStatus maps a failed start to its HTTP status.
func processErrorStatus(err error) int {
	var langErr *CodeRunLanguageError
	switch {
	case errors.Is(err, ErrTooManyProcesses):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrStreamingUnsupported):
		return http.StatusNotImplemented
	case errors.Is(err, ErrSandboxNotRunning):
		return http.StatusConflict
	case errors.As(err, &langErr):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

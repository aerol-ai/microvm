package toolhost

import (
	"context"
	"errors"
	"net/http"

	"github.com/aerol-ai/microvm/internal/toolboxwire"
)

// Sessions backs the Daytona-style /process/session routes on WASM (issue
// #178). The WASM driver implements it: a session's commands run one at a
// time, each as a confined run of the sandbox's own module inside the wasm
// engine (Processes' StartStream), and their output is kept, capped, in
// sandboxd. Like Processes it lives on the driver, because this host is
// rebuilt for every request while a session outlives them all.
type Sessions interface {
	// Create makes a session; created is false when it already exists.
	Create(id string) (created bool, err error)
	// List is every session, by id.
	List() []SessionInfo
	Get(id string) (SessionInfo, error)
	// Delete removes a session and kills its running command.
	Delete(id string) error
	// Exec runs a command in a session after the ones before it. Async
	// returns the command id at once; otherwise the result comes back when
	// the command ends. ctx bounds only the wait to start it.
	Exec(ctx context.Context, sessionID string, cmd SessionCommand, async bool) (CommandResult, error)
	Command(sessionID, commandID string) (CommandInfo, error)
	// Logs is a window of each of the command's streams.
	Logs(sessionID, commandID string, q toolboxwire.LogQuery) (stdout, stderr toolboxwire.LogWindow, err error)
	// Follow is the command's output so far, then its live output.
	Follow(sessionID, commandID string) (*LogFollow, error)
	// Input writes to the running command's stdin. It gives up when ctx
	// ends, and answers ErrInputTimeout when the command does not take the
	// bytes in time or ErrInputPending while an earlier input still waits.
	Input(ctx context.Context, sessionID, commandID string, data []byte) error
	// Entrypoint is the sandbox's serving guest, and with logs its output.
	Entrypoint(ctx context.Context, logs bool) (EntrypointInfo, error)
	// FollowEntrypoint is the entrypoint's output so far, then its live
	// output until it exits.
	FollowEntrypoint(ctx context.Context) (*LogFollow, error)
}

// SessionCommand is a command as the caller wrote it (Text, what the
// session lists) and the argv it runs as.
type SessionCommand struct {
	Text string
	Argv []string
}

// SessionInfo is a session and its commands, oldest first.
type SessionInfo struct {
	ID       string
	Commands []CommandInfo
}

// CommandInfo is one command. ExitCode is nil until it ends; Running is
// true only while it runs (not while it waits for the one before it).
type CommandInfo struct {
	ID       string
	Command  string
	ExitCode *int32
	Running  bool
}

// CommandResult answers an exec: the id alone for an async one, the exit
// code and output for a sync one.
type CommandResult struct {
	ID       string
	ExitCode int32
	Stdout   string
	Stderr   string
}

// LogFollow is a live log subscription. Replay is everything kept so far,
// already framed; Frames carries framed live output and is closed when the
// command ends. Close must always be called.
type LogFollow struct {
	Replay []byte
	Frames <-chan []byte
	Close  func()
}

// EntrypointInfo is the sandbox's entrypoint: the command line it runs,
// its exit code once it has ended, and (when asked for) its output.
type EntrypointInfo struct {
	Command  string
	ExitCode *int32
	Stdout   string
	Stderr   string
}

var (
	// The messages are toolboxd's, so a caller sees the same error
	// whichever runtime it reached.
	ErrSessionNotFound   = errors.New("session not found")
	ErrCommandNotFound   = errors.New("command not found")
	ErrCommandNotRunning = errors.New("command is not currently accepting input")

	// ErrTooManySessions, ErrTooManyCommands and ErrTooManyFollowers are
	// the per-sandbox caps that keep sessions' state in sandboxd bounded.
	// HTTP 429.
	ErrTooManySessions  = errors.New("this wasm sandbox already has the maximum number of sessions (SB_WASM_MAX_SESSIONS_PER_SANDBOX)")
	ErrTooManyCommands  = errors.New("this session already has the maximum number of commands waiting to run (SB_WASM_SESSION_COMMANDS_KEPT)")
	ErrTooManyFollowers = errors.New("this command already has the maximum number of log followers")

	// ErrNoEntrypoint: the sandbox's guest has not been started as a
	// serving entrypoint (only HTTP guests are). HTTP 404.
	ErrNoEntrypoint = errors.New("no entrypoint has run in this wasm sandbox; only a guest that serves HTTP runs one")
	// ErrEntrypointUnsupported: the worker keeps no entrypoint output (it
	// predates entrypoint logs, or runs the wasmtime engine). HTTP 501.
	ErrEntrypointUnsupported = errors.New("entrypoint logs are not available for this wasm sandbox: its worker predates them or runs the wasmtime engine")
	// ErrSessionStopped: the sandbox stopped while the request was served.
	ErrSessionStopped = errors.New("the wasm sandbox stopped")

	// ErrInputPending: an earlier input to the command is still waiting
	// for it to read. A second one is refused rather than queued behind
	// it, so input a command never reads cannot pile up in sandboxd. HTTP
	// 409.
	ErrInputPending = errors.New("the command has not read its earlier input yet")
	// ErrInputTimeout: the command did not take the input in time; it
	// stays queued for the command, and later input waits behind it. HTTP
	// 408.
	ErrInputTimeout = errors.New("the command did not read its input in time")
)

// sessionErrorStatus maps a Sessions error to its HTTP status.
func sessionErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrCommandNotFound), errors.Is(err, ErrNoEntrypoint):
		return http.StatusNotFound
	case errors.Is(err, ErrCommandNotRunning), errors.Is(err, ErrSessionStopped), errors.Is(err, ErrInputPending):
		return http.StatusConflict
	case errors.Is(err, ErrInputTimeout):
		return http.StatusRequestTimeout
	case errors.Is(err, ErrTooManySessions), errors.Is(err, ErrTooManyCommands), errors.Is(err, ErrTooManyFollowers):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrEntrypointUnsupported):
		return http.StatusNotImplemented
	}
	return processErrorStatus(err)
}

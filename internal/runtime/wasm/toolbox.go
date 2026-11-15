package wasm

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ToolboxHost serves toolbox HTTP in-process for WASM sandboxes.
type ToolboxHost interface {
	ServeToolbox(ctx context.Context, sandboxID, token string, w http.ResponseWriter, r *http.Request)
}

// ServeToolbox implements ToolboxHost.
func (d *Driver) ServeToolbox(_ context.Context, sandboxID, token string, w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	inst := d.byID[sandboxID]
	d.mu.Unlock()
	if inst == nil {
		writeToolboxError(w, http.StatusNotFound, "wasm sandbox not found")
		return
	}
	// Every command path runs inside the wasm engine (the sandbox's worker):
	// buffered exec, and the exec stream and code-run through Procs. Nothing
	// here may start a host process: this handler runs in sandboxd, so a
	// host shell would run as the daemon, not in the sandbox. That is why
	// there is no sessions Manager (toolhost/sessions.go).
	cfg := toolhost.Config{
		SandboxID: sandboxID,
		WorkDir:   inst.workDir,
		AuthToken: token,
		Exec:      sandboxExecutor{driver: d, id: sandboxID},
		Procs:     sandboxProcesses{driver: d, id: sandboxID},
	}
	if inst.durability == models.DurabilityDurable && d.stateKV != nil {
		cfg.StateKV = d.stateKV
	}
	host := toolhost.New(cfg)
	host.Handler().ServeHTTP(w, r)
}

// sandboxProcesses gives the per-request toolhost the driver's streaming
// runs. The runs and their cap live on the driver (sandboxInstance.streams),
// not on the toolhost, which is rebuilt for every request.
type sandboxProcesses struct {
	driver *Driver
	id     string
}

func (p sandboxProcesses) CanStart() error {
	if !p.driver.streamSlotFree(p.id) {
		return toolhost.ErrTooManyProcesses
	}
	return nil
}

func (p sandboxProcesses) StartStream(ctx context.Context, spec toolhost.StreamSpec) (toolhost.ProcessStream, error) {
	st, err := p.driver.StartStream(ctx, p.id, StreamSpec{
		Args:       spec.Args,
		Env:        spec.Env,
		Stdin:      spec.Stdin,
		NoDeadline: spec.NoDeadline,
	})
	if err != nil {
		return nil, toolhostProcessError(err)
	}
	return processStream{st: st}, nil
}

func (p sandboxProcesses) StartCodeRun(ctx context.Context, spec toolhost.CodeRunSpec) (toolhost.ProcessStream, error) {
	st, err := p.driver.StartCodeRun(ctx, p.id, CodeRunSpec{
		Language:       spec.Language,
		Code:           spec.Code,
		Argv:           spec.Argv,
		Env:            spec.Env,
		Timeout:        spec.Timeout,
		MaxOutputBytes: spec.MaxOutputBytes,
	})
	if err != nil {
		return nil, toolhostProcessError(err)
	}
	return processStream{st: st}, nil
}

// toolhostProcessError maps driver errors onto the ones the toolhost turns
// into HTTP statuses (429, 501, 400).
func toolhostProcessError(err error) error {
	var langErr *CodeRunLanguageError
	switch {
	case errors.Is(err, ErrStreamLimit):
		return toolhost.ErrTooManyProcesses
	case errors.Is(err, ErrStreamingUnsupported):
		return toolhost.ErrStreamingUnsupported
	case errors.As(err, &langErr):
		return &toolhost.CodeRunLanguageError{Message: langErr.Error()}
	}
	return err
}

// processStream adapts a driver Stream to toolhost.ProcessStream.
type processStream struct {
	st *Stream
}

func (p processStream) Recv() (toolhost.ProcessEvent, error) {
	ev, err := p.st.Recv()
	if err != nil {
		return toolhost.ProcessEvent{}, err
	}
	out := toolhost.ProcessEvent{Stdout: ev.Stdout, Stderr: ev.Stderr}
	if ev.Exit != nil {
		out.Exit = &toolhost.ProcessExit{
			ExitCode:  ev.Exit.ExitCode,
			Killed:    ev.Exit.Killed,
			TimedOut:  ev.Exit.TimedOut,
			Truncated: ev.Exit.Truncated,
			Error:     ev.Exit.Error,
		}
	}
	return out, nil
}

func (p processStream) WriteStdin(b []byte) error { return p.st.WriteStdin(b) }
func (p processStream) CloseStdin() error         { return p.st.CloseStdin() }
func (p processStream) Kill() error               { return p.st.Kill() }
func (p processStream) Close() error              { return p.st.Close() }

func writeToolboxError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, msg)
}

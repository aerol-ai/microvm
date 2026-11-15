package wasm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/internal/toolboxwire"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// The Daytona entrypoint session on WASM (issue #178): the sandbox's
// entrypoint is its serving guest, the _start the driver runs for an HTTP
// guest. Its worker keeps the newest of its output (worker/entrypoint.go);
// this reads it, and follows it live over one worker connection. A guest
// that only runs commands has no entrypoint (404), and a worker that keeps
// no output (adopted from an older sandboxd, or wasmtime) answers 501.

// entrypointWorkerClient is the optional entrypoint surface of a worker
// client; a client without it is an older build.
type entrypointWorkerClient interface {
	EntrypointLogs(ctx context.Context, sandboxID string, logs bool) (worker.EntrypointLogs, error)
	FollowEntrypoint(ctx context.Context, sandboxID string) (worker.EntrypointLogs, workerExecStream, error)
}

// entrypointClient is the sandbox's worker client and its command line.
func (d *Driver) entrypointClient(sandboxID string) (entrypointWorkerClient, string, error) {
	d.mu.Lock()
	inst := d.byID[sandboxID]
	var socketPath, command string
	if inst != nil {
		socketPath = inst.socketPath
		command = strings.Join(inst.baseArgs, " ")
		if command == "" {
			command = inst.moduleRef
		}
	}
	d.mu.Unlock()
	if inst == nil {
		return nil, "", fmt.Errorf("wasm sandbox %q not found", sandboxID)
	}
	if socketPath == "" {
		// No worker: nothing has run.
		return nil, "", toolhost.ErrNoEntrypoint
	}
	client, ok := d.newWorkerClient(socketPath).(entrypointWorkerClient)
	if !ok {
		return nil, "", toolhost.ErrEntrypointUnsupported
	}
	return client, command, nil
}

func entrypointError(err error) error {
	switch {
	case errors.Is(err, worker.ErrEntrypointLogsUnsupported):
		return toolhost.ErrEntrypointUnsupported
	case errors.Is(err, worker.ErrStreamLimit):
		return toolhost.ErrTooManyFollowers
	}
	return err
}

// entrypoint is the sandbox's entrypoint, with its kept output when logs
// is set.
func (d *Driver) entrypoint(ctx context.Context, sandboxID string, logs bool) (toolhost.EntrypointInfo, error) {
	client, command, err := d.entrypointClient(sandboxID)
	if err != nil {
		return toolhost.EntrypointInfo{}, err
	}
	el, err := client.EntrypointLogs(ctx, sandboxID, logs)
	if err != nil {
		return toolhost.EntrypointInfo{}, entrypointError(err)
	}
	if !el.Ran {
		return toolhost.EntrypointInfo{}, toolhost.ErrNoEntrypoint
	}
	info := toolhost.EntrypointInfo{Command: command, Stdout: string(el.Stdout), Stderr: string(el.Stderr)}
	if el.ExitCode != nil {
		code := int32(*el.ExitCode)
		info.ExitCode = &code
	}
	return info, nil
}

// entrypointFollow is a live follow of the entrypoint's output. It is
// registered on the sandbox's session set, so the sandbox's end ends it.
type entrypointFollow struct {
	stream workerExecStream
	stop   chan struct{}
	once   sync.Once
}

func (f *entrypointFollow) close() {
	f.once.Do(func() {
		close(f.stop)
		_ = f.stream.Close()
	})
}

// followEntrypoint is the entrypoint's kept output, then its live output
// until it exits.
func (d *Driver) followEntrypoint(ctx context.Context, sandboxID string) (*toolhost.LogFollow, error) {
	client, _, err := d.entrypointClient(sandboxID)
	if err != nil {
		return nil, err
	}
	set, err := d.sessionsFor(sandboxID)
	if err != nil {
		return nil, err
	}
	el, stream, err := client.FollowEntrypoint(ctx, sandboxID)
	if err != nil {
		return nil, entrypointError(err)
	}
	if !el.Ran || stream == nil {
		if stream != nil {
			_ = stream.Close()
		}
		return nil, toolhost.ErrNoEntrypoint
	}
	f := &entrypointFollow{stream: stream, stop: make(chan struct{})}
	if !set.addEntrypointFollow(f) {
		f.close()
		return nil, toolhost.ErrSessionStopped
	}
	frames := make(chan []byte)
	go func() {
		defer close(frames)
		for {
			ev, err := stream.Recv()
			if err != nil || ev.Exit != nil {
				return
			}
			select {
			case frames <- toolboxwire.FrameLog(ev.Stream == worker.StreamStderr, ev.Data):
			case <-f.stop:
				return
			}
		}
	}()
	return &toolhost.LogFollow{
		Replay: toolboxwire.LogReplay(el.Stdout, el.Stderr),
		Frames: frames,
		Close: func() {
			set.removeEntrypointFollow(f)
			f.close()
		},
	}, nil
}

// addEntrypointFollow registers f so close ends it; false once the set has
// closed.
func (s *sessionSet) addEntrypointFollow(f *entrypointFollow) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if s.entry == nil {
		s.entry = map[*entrypointFollow]struct{}{}
	}
	s.entry[f] = struct{}{}
	return true
}

func (s *sessionSet) removeEntrypointFollow(f *entrypointFollow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entry, f)
}

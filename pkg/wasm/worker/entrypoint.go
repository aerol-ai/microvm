package worker

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/aerol-ai/microvm/internal/logring"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// The entrypoint's output (issue #178). A sandbox's entrypoint is its
// serving guest: the _start the driver invokes for an HTTP guest. Its
// stdout and stderr used to be dropped (wazero's default); the per-sandbox
// worker now keeps the newest bytes of each in a bounded ring, read with
// MsgEntrypointLogs, and can stream them live over the same connection.
// The ring lives in the worker, not in sandboxd: it costs the sandbox's own
// process, and a sandbox that never asks costs sandboxd nothing.

var (
	// entrypointLogBytes is kept per stream (stdout, stderr).
	entrypointLogBytes = 1 << 20
	// A follower that stops reading has chunks dropped past this much
	// queued; the guest's writes never wait on a follower.
	entrypointFollowQueueBytes = 256 << 10
	maxEntrypointFollowers     = 8
)

// entrypointLogsPayload asks for the entrypoint's state, with its kept
// output (Logs) and then its live output (Follow).
type entrypointLogsPayload struct {
	Logs   bool `json:"logs,omitempty"`
	Follow bool `json:"follow,omitempty"`
}

// EntrypointLogs answers MsgEntrypointLogs. Ran is false when no entrypoint
// has run for the sandbox. ExitCode is set once it has ended. StdoutTotal
// and StderrTotal count every byte written, kept or not.
type EntrypointLogs struct {
	Ran         bool   `json:"ran"`
	Running     bool   `json:"running,omitempty"`
	ExitCode    *int   `json:"exit_code,omitempty"`
	Stdout      []byte `json:"stdout,omitempty"`
	Stderr      []byte `json:"stderr,omitempty"`
	StdoutTotal int64  `json:"stdout_total,omitempty"`
	StderrTotal int64  `json:"stderr_total,omitempty"`
}

// entrypointLog is a per-sandbox worker's record of its serving guest.
type entrypointLog struct {
	mu        sync.Mutex
	owner     string // the sandbox whose entrypoint ran
	gen       uint64 // bumped by each invoke, so a stale end is ignored
	ran       bool
	running   bool
	exitCode  int
	stdout    logring.Ring
	stderr    logring.Ring
	followers map[*entrypointFollower]struct{}
}

type entrypointChunk struct {
	stream uint8
	data   []byte
}

type entrypointFollower struct {
	queue  []entrypointChunk
	queued int
	ended  bool
	exit   int
	wake   chan struct{}
}

func (f *entrypointFollower) signal() {
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// attach points a freshly loaded engine's serving instance at the log and
// starts it empty: new code is a new entrypoint. An engine that cannot
// (wasmtime) keeps its old behaviour.
func (l *entrypointLog) attach(eng wasmengine.Engine) {
	if setter, ok := eng.(wasmengine.InstanceOutputSetter); ok {
		setter.SetInstanceOutput(entrypointWriter{l, StreamStdout}, entrypointWriter{l, StreamStderr})
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.resetLocked()
	l.owner, l.ran, l.running = "", false, false
}

func (l *entrypointLog) resetLocked() {
	l.stdout, l.stderr = logring.Ring{}, logring.Ring{}
	l.endFollowersLocked()
}

func (l *entrypointLog) endFollowersLocked() {
	for f := range l.followers {
		f.ended, f.exit = true, l.exitCode
		f.signal()
	}
	l.followers = nil
}

// begin records an invoke of the entrypoint. A guest started again (the
// driver revives a serving guest that died) keeps its earlier output, so a
// crash's last words stay readable.
func (l *entrypointLog) begin(sandboxID string) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.owner != sandboxID {
		l.resetLocked()
		l.owner = sandboxID
	}
	l.gen++
	l.ran, l.running = true, true
	return l.gen
}

// end records the invoke's end, unless a later invoke has begun.
func (l *entrypointLog) end(gen uint64, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if gen != l.gen {
		return
	}
	l.running, l.exitCode = false, wasmengine.ExitCode(err)
	l.endFollowersLocked()
}

type entrypointWriter struct {
	l      *entrypointLog
	stream uint8
}

// Write keeps p and queues it for followers. It never blocks the guest.
func (w entrypointWriter) Write(p []byte) (int, error) {
	l := w.l
	l.mu.Lock()
	defer l.mu.Unlock()
	ring := &l.stdout
	if w.stream == StreamStderr {
		ring = &l.stderr
	}
	ring.Write(p, entrypointLogBytes, nil)
	if len(l.followers) > 0 {
		chunk := entrypointChunk{stream: w.stream, data: append([]byte(nil), p...)}
		for f := range l.followers {
			if f.queued > 0 && f.queued+len(p) > entrypointFollowQueueBytes {
				continue
			}
			f.queue = append(f.queue, chunk)
			f.queued += len(p)
			f.signal()
		}
	}
	return len(p), nil
}

// serve answers one MsgEntrypointLogs on conn, which it owns from here.
func (l *entrypointLog) serve(conn net.Conn, env Envelope) error {
	if workerEngineName() == "wasmtime" {
		// wasmtime sends a guest's output to the worker's own stdio.
		return writeStreamError(conn, env.SandboxID, errCodeStreamingUnsupported,
			fmt.Errorf("entrypoint logs are not supported on the wasmtime engine"))
	}
	var p entrypointLogsPayload
	if err := decodePayload(env.Payload, &p); err != nil {
		return writeStreamError(conn, env.SandboxID, "", err)
	}
	l.mu.Lock()
	if !l.ran || l.owner != env.SandboxID {
		l.mu.Unlock()
		return writeEntrypointLogs(conn, env.SandboxID, EntrypointLogs{})
	}
	reply := EntrypointLogs{Ran: true, Running: l.running, StdoutTotal: l.stdout.Total(), StderrTotal: l.stderr.Total()}
	if !l.running {
		code := l.exitCode
		reply.ExitCode = &code
	}
	if p.Logs || p.Follow {
		reply.Stdout, reply.Stderr = l.stdout.Bytes(), l.stderr.Bytes()
	}
	var f *entrypointFollower
	if p.Follow && l.running {
		if len(l.followers) >= maxEntrypointFollowers {
			l.mu.Unlock()
			return writeStreamError(conn, env.SandboxID, errCodeStreamLimit,
				fmt.Errorf("the entrypoint already has %d log followers", maxEntrypointFollowers))
		}
		f = &entrypointFollower{wake: make(chan struct{}, 1)}
		if l.followers == nil {
			l.followers = map[*entrypointFollower]struct{}{}
		}
		l.followers[f] = struct{}{}
	}
	l.mu.Unlock()
	if f != nil {
		defer l.unfollow(f)
	}
	if err := writeEntrypointLogs(conn, env.SandboxID, reply); err != nil || !p.Follow {
		return err
	}
	if f == nil {
		// Already ended: the follow is the replay and the exit.
		return writeEntrypointExit(conn, env.SandboxID, reply.ExitCode)
	}
	gone := make(chan struct{})
	go func() {
		// sandboxd sends nothing more; a read error means it hung up.
		defer close(gone)
		for {
			if _, err := readFrame(conn); err != nil {
				return
			}
		}
	}()
	for {
		chunk, ended, exit, ok := l.next(f, gone)
		if !ok {
			return nil
		}
		if ended {
			return writeEntrypointExit(conn, env.SandboxID, &exit)
		}
		if err := writeFrame(conn, Envelope{Type: MsgExecChunk, SandboxID: env.SandboxID, Stream: chunk.stream, Payload: chunk.data}); err != nil {
			return nil
		}
	}
}

// next is f's next chunk, or its end once the queue is empty. ok is false
// when sandboxd hung up.
func (l *entrypointLog) next(f *entrypointFollower, gone <-chan struct{}) (chunk entrypointChunk, ended bool, exit int, ok bool) {
	for {
		l.mu.Lock()
		if len(f.queue) > 0 {
			chunk = f.queue[0]
			f.queue[0] = entrypointChunk{}
			f.queue = f.queue[1:]
			f.queued -= len(chunk.data)
			l.mu.Unlock()
			return chunk, false, 0, true
		}
		if f.ended {
			exit = f.exit
			l.mu.Unlock()
			return chunk, true, exit, true
		}
		l.mu.Unlock()
		select {
		case <-f.wake:
		case <-gone:
			return chunk, false, 0, false
		}
	}
}

func (l *entrypointLog) unfollow(f *entrypointFollower) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.followers, f)
	f.queue = nil
}

func writeEntrypointLogs(conn io.Writer, sandboxID string, logs EntrypointLogs) error {
	body, err := encodePayload(logs)
	if err != nil {
		return err
	}
	return writeFrame(conn, Envelope{Type: MsgOK, SandboxID: sandboxID, Payload: body})
}

func writeEntrypointExit(conn io.Writer, sandboxID string, code *int) error {
	exit := ExecExit{}
	if code != nil {
		exit.ExitCode = *code
	}
	body, err := encodePayload(exit)
	if err != nil {
		return err
	}
	return writeFrame(conn, Envelope{Type: MsgExecExit, SandboxID: sandboxID, Payload: body})
}

// serveNoEntrypoint answers MsgEntrypointLogs on a resident host, whose
// sandboxes never run a serving entrypoint (it refuses listeners).
func serveNoEntrypoint(conn net.Conn, env Envelope) error {
	return writeEntrypointLogs(conn, env.SandboxID, EntrypointLogs{})
}

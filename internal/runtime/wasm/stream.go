package wasm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// Streaming runs (issue #535): a guest that runs next to the sandbox's own,
// with stdin, stdout and stderr streamed while it runs. Every byte of the
// caller's command or code runs inside the wasm engine in the sandbox's
// worker; nothing here starts a host process. The toolbox's exec stream and
// code-run use it today; Daytona sessions and the code interpreter build on
// the same StartStream.

// ErrStreamingUnsupported means this sandbox's worker cannot stream: it was
// adopted from an older sandboxd, or it runs the wasmtime engine.
var ErrStreamingUnsupported = worker.ErrStreamingUnsupported

// ErrStreamLimit means the sandbox already has MaxStreamsPerSandbox runs.
var ErrStreamLimit = errors.New("wasm sandbox already runs the maximum number of processes")

const defaultMaxStreamsPerSandbox = 8

// StreamSpec describes one streaming run.
type StreamSpec struct {
	// ModulePath runs another module (a language runtime); "" runs the
	// sandbox's own module.
	ModulePath string
	// Args is argv including argv[0]; empty uses the sandbox's own args.
	Args []string
	// Env is added to the sandbox's env.
	Env map[string]string
	// NoDeadline lets the run go until it exits or is killed. Otherwise
	// Timeout (default: the driver's wall timeout) bounds it.
	NoDeadline bool
	Timeout    time.Duration
	// Stdin opens stdin to WriteStdin; without it the guest reads EOF.
	Stdin bool
	// MaxOutputBytes keeps only the first N bytes of each of stdout and
	// stderr. 0 = no cap.
	MaxOutputBytes int64
}

// StreamEvent is output from a run, or its exit (last).
type StreamEvent struct {
	Stdout []byte
	Stderr []byte
	Exit   *StreamExit
}

// StreamExit is how a run ended.
type StreamExit struct {
	// ExitCode is -1 when the run was killed or timed out.
	ExitCode   int
	Killed     bool
	TimedOut   bool
	Truncated  bool
	Error      string
	DurationMS int64
}

// Stream is a live run. Recv from one goroutine; the other methods may be
// called from another. Close must always be called.
type Stream struct {
	ID        string
	sandboxID string
	ws        workerExecStream
	set       *streamSet
	once      sync.Once
	// exited is set once Recv has seen the exit, killed once a kill has
	// reached the worker: either way Close need not send one.
	exited atomic.Bool
	killed atomic.Bool
}

// streamSet tracks a sandbox instance's live runs so stop, destroy,
// passivate and migrate can end them; held runs count toward the cap.
type streamSet struct {
	mu      sync.Mutex
	streams map[*Stream]struct{}
	held    int
}

func (s *streamSet) reserve(limit int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.held >= limit {
		return fmt.Errorf("%w (%d)", ErrStreamLimit, limit)
	}
	s.held++
	return nil
}

func (s *streamSet) unreserve() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.held--
}

func (s *streamSet) add(st *Stream) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streams == nil {
		s.streams = make(map[*Stream]struct{})
	}
	s.streams[st] = struct{}{}
}

// drop releases st's slot once, whether it ended or was closed first.
func (s *streamSet) drop(st *Stream) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.streams[st]; ok {
		delete(s.streams, st)
		s.held--
	}
}

func (s *streamSet) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held
}

// killAll ends every live run and drops its connection. The kills go out
// in parallel: each is a worker round trip, and a hung worker must not
// stretch a stop by one timeout per run.
func (s *streamSet) killAll() {
	if s == nil {
		return
	}
	s.mu.Lock()
	streams := make([]*Stream, 0, len(s.streams))
	for st := range s.streams {
		streams = append(streams, st)
	}
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, st := range streams {
		wg.Add(1)
		go func(st *Stream) {
			defer wg.Done()
			_ = st.Kill()
			_ = st.Close()
		}(st)
	}
	wg.Wait()
}

// killStreams ends an instance's live streaming runs and its sessions. The
// worker also ends the runs on StopInstance, but sandboxd's side of each
// run (its connection, its slot, the toolbox request waiting on it) must go
// now, and a worker process that is about to be killed sends no exit at
// all. Sessions do not outlive the sandbox, as they do not outlive
// toolboxd: a restarted sandbox starts with none.
func (d *Driver) killStreams(inst *sandboxInstance) {
	if inst == nil {
		return
	}
	// Interpreter contexts first: their Managers would otherwise start a
	// new interpreter for a run whose old one was just killed.
	d.closeInterpreters(inst)
	d.mu.Lock()
	set := inst.streams
	sessions := inst.sessions
	inst.sessions = nil
	d.mu.Unlock()
	sessions.close()
	set.killAll()
}

// streamSlotFree reports whether the sandbox has room for another run. The
// toolhost asks before a WebSocket upgrade so it can answer 429; StartStream
// still enforces the cap itself.
func (d *Driver) streamSlotFree(sandboxID string) bool {
	d.mu.Lock()
	inst := d.byID[sandboxID]
	var set *streamSet
	if inst != nil {
		set = inst.streams
	}
	d.mu.Unlock()
	return set == nil || set.count() < d.maxStreamsPerSandbox()
}

func (d *Driver) maxStreamsPerSandbox() int {
	if d.cfg.MaxStreamsPerSandbox > 0 {
		return d.cfg.MaxStreamsPerSandbox
	}
	return defaultMaxStreamsPerSandbox
}

// StartStream starts a streaming run in a started sandbox. The run gets the
// sandbox's /work, memory limit, env, network blocks and egress policy, the
// same as POST /process/execute, but it runs as its own instance next to the
// sandbox's guest instead of replacing it. ctx bounds only the start.
func (d *Driver) StartStream(ctx context.Context, sandboxID string, spec StreamSpec) (*Stream, error) {
	d.mu.Lock()
	inst := d.byID[sandboxID]
	if inst == nil {
		d.mu.Unlock()
		return nil, fmt.Errorf("wasm sandbox %q not found", sandboxID)
	}
	if inst.status != models.SandboxStatusStarted || inst.socketPath == "" {
		d.mu.Unlock()
		return nil, fmt.Errorf("wasm sandbox %q is not running", sandboxID)
	}
	if inst.streams == nil {
		inst.streams = &streamSet{}
	}
	set := inst.streams
	socketPath, workDir, memoryMB := inst.socketPath, inst.workDir, inst.memoryMB
	env := mergeEnv(inst.baseEnv, spec.Env)
	args := append([]string(nil), spec.Args...)
	if len(args) == 0 {
		args = append(args, inst.baseArgs...)
	}
	export := ""
	if spec.ModulePath == "" {
		export = inst.entryExport
	}
	d.mu.Unlock()

	sc, ok := d.newWorkerClient(socketPath).(streamingWorkerClient)
	if !ok {
		return nil, ErrStreamingUnsupported
	}
	if err := set.reserve(d.maxStreamsPerSandbox()); err != nil {
		return nil, err
	}
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = d.cfg.DefaultWallTimeout
	}
	// Only /work, as for /process/execute, and never a listener: a run is
	// a command, and an extra listener fd breaks modules with an embedded
	// file system (see execSandbox).
	caps := wasmengine.CapsFromResourceLimits(wasmengine.Capabilities{
		Env:            env,
		Args:           args,
		Preopens:       []wasmengine.Preopen{{GuestPath: "/work", HostPath: workDir}},
		WASIListenPort: wasmengine.WASIListenPortDisabled,
	}, memoryMB, timeout)
	d.bindNetworkBlocks(sandboxID, &caps)
	ws, err := sc.StartExec(ctx, sandboxID, worker.ExecStartPayload{
		Caps:           caps,
		Export:         export,
		ModulePath:     spec.ModulePath,
		NoDeadline:     spec.NoDeadline,
		MaxOutputBytes: spec.MaxOutputBytes,
		Stdin:          spec.Stdin,
	})
	if err != nil {
		set.unreserve()
		return nil, err
	}
	st := &Stream{sandboxID: sandboxID, ws: ws, set: set}
	if ids, ok := ws.(interface{ RunID() string }); ok {
		st.ID = ids.RunID()
	}
	set.add(st)
	return st, nil
}

// Recv returns the next output, or the exit (after which it returns io.EOF).
func (s *Stream) Recv() (StreamEvent, error) {
	ev, err := s.ws.Recv()
	if err != nil {
		return StreamEvent{}, err
	}
	if ev.Exit == nil {
		if ev.Stream == worker.StreamStderr {
			return StreamEvent{Stderr: ev.Data}, nil
		}
		return StreamEvent{Stdout: ev.Data}, nil
	}
	// The slot frees as soon as the run has ended, not when the caller
	// gets round to Close.
	s.exited.Store(true)
	s.set.drop(s)
	recordWasmUsage(s.sandboxID, ev.Exit.Usage)
	return StreamEvent{Exit: &StreamExit{
		ExitCode:   ev.Exit.ExitCode,
		Killed:     ev.Exit.Killed,
		TimedOut:   ev.Exit.TimedOut,
		Truncated:  ev.Exit.Truncated,
		Error:      ev.Exit.Error,
		DurationMS: ev.Exit.Usage.WallDurationMs,
	}}, nil
}

// WriteStdin sends bytes to the run's stdin.
func (s *Stream) WriteStdin(p []byte) error { return s.ws.WriteStdin(p) }

// CloseStdin sends EOF to the run's stdin.
func (s *Stream) CloseStdin() error { return s.ws.CloseStdin() }

// Kill ends the run; its exit still arrives on Recv.
func (s *Stream) Kill() error {
	err := s.ws.Kill()
	if err == nil {
		s.killed.Store(true)
	}
	return err
}

// Close drops the run's connection, which ends a run still going, and
// frees its slot. A run that has not exited is also killed over a fresh
// connection (best effort): the worker notices a dropped connection only
// when it next reads from it, and it may not read again soon (a guest
// that does not read its stdin backs the worker's reader up), while
// sandboxd frees the run's slot here. The slot frees after the kill, so
// sandboxd never counts fewer runs than the worker still has.
func (s *Stream) Close() error {
	var err error
	s.once.Do(func() {
		err = s.ws.Close()
		if !s.exited.Load() && !s.killed.Load() {
			_ = s.ws.Kill()
		}
		s.set.drop(s)
	})
	return err
}

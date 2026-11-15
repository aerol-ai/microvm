package worker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// Streaming exec, shared by the per-sandbox Server and the ResidentServer.
//
// A run is a named instance ("<sandboxID>/x/<id>") on an aux
// MultiInstanceEngine, never on the server's own engine. On a per-sandbox
// worker that engine is the single wazeroEngine serving the guest: every
// Exec, SetCapability, SetListenPort or memory change re-instantiates it,
// which would cut a stream off, and an Exec there replaces the serving
// guest. A MultiInstanceEngine gives each run its own instance on one
// compiled module, so runs and the serving guest never touch each other.

// MaxStreamsPerSandbox is the worker's own ceiling on one sandbox's live
// runs. sandboxd enforces a lower, configurable cap first
// (SB_WASM_MAX_STREAMS_PER_SANDBOX, default 4) and never sets it above this
// one, which only stops a client that skips sandboxd's cap from exhausting
// the worker. Each run is an instance with the sandbox's full memory limit.
const MaxStreamsPerSandbox = 32

var (
	// maxStreamsPerSandbox is MaxStreamsPerSandbox, lowered by tests.
	maxStreamsPerSandbox = MaxStreamsPerSandbox
	// auxIdleTTL keeps a compiled aux module around between runs, so back
	// to back code-runs pay an Instantiate instead of a compile.
	auxIdleTTL = 2 * time.Minute
	// streamChunkMax splits large guest writes so each frame stays far below
	// maxFrameSize after base64.
	streamChunkMax = 256 << 10
	// streamExitWriteWait bounds the final exec_exit write to a client that
	// stopped reading.
	streamExitWriteWait = 10 * time.Second
	// stdinQueueMax is how much stdin may wait for a guest that is not
	// reading (always at least one frame). Past it the frame reader waits
	// for room, and sandboxd's writes back up behind it as they would
	// behind a pipe.
	stdinQueueMax = 1 << 20
)

// streamHost is what the shared stream code needs from a server.
type streamHost interface {
	mediator() *NetMediator
	streamUsage(sandboxID string) *workerNetUsage
	// ownModule is the sandbox's own module path and memory, for runs that
	// name no module. An empty path means no module is loaded.
	ownModule() (path string, memoryMB int)
}

type auxKey struct {
	path     string
	memoryMB int
}

// auxEngine is one compiled module shared by the runs that use it.
type auxEngine struct {
	key  auxKey
	mu   sync.Mutex // serializes the compile
	eng  *wasmengine.MultiInstanceEngine
	refs int // runs plus starts in flight; guarded by streamRegistry.mu
	idle *time.Timer
}

// streamRegistry owns a worker's aux engines and live runs.
type streamRegistry struct {
	mu      sync.Mutex
	aux     map[auxKey]*auxEngine
	streams map[string]map[string]*workerStream // sandboxID -> id -> run
	slots   map[string]int                      // sandboxID -> runs + starts
	closed  bool
}

// workerStream is one live run and the connection it streams over.
type workerStream struct {
	id        string
	sandboxID string
	conn      net.Conn
	writeMu   sync.Mutex
	run       *wasmengine.Running
	maxOut    int64
	truncated atomic.Bool
	usage     *workerNetUsage
}

func newStreamID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("stream id: %v", err))
	}
	return hex.EncodeToString(b[:])
}

// reserve takes one of the sandbox's run slots before any compile work, so
// a refused start costs nothing.
func (r *streamRegistry) reserve(sandboxID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("worker is shutting down")
	}
	if r.slots == nil {
		r.slots = make(map[string]int)
	}
	if r.slots[sandboxID] >= maxStreamsPerSandbox {
		return fmt.Errorf("sandbox %s already has %d running processes", sandboxID, maxStreamsPerSandbox)
	}
	r.slots[sandboxID]++
	return nil
}

func (r *streamRegistry) unreserve(sandboxID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.slots[sandboxID] <= 1 {
		delete(r.slots, sandboxID)
		return
	}
	r.slots[sandboxID]--
}

// acquire returns the aux engine for key, compiling the module on first
// use. The compile runs outside the registry lock so it never stalls kills.
func (r *streamRegistry) acquire(ctx context.Context, key auxKey) (*auxEngine, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, fmt.Errorf("worker is shutting down")
	}
	if r.aux == nil {
		r.aux = make(map[auxKey]*auxEngine)
	}
	a := r.aux[key]
	if a == nil {
		a = &auxEngine{key: key}
		r.aux[key] = a
	}
	a.refs++
	if a.idle != nil {
		a.idle.Stop()
		a.idle = nil
	}
	r.mu.Unlock()

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.eng != nil {
		return a, nil
	}
	eng, err := wasmengine.NewMultiInstanceEngine(ctx, key.memoryMB)
	if err == nil {
		if err = eng.LoadModule(ctx, key.path); err != nil {
			_ = eng.Close(ctx)
		}
	}
	if err != nil {
		r.release(a)
		return nil, err
	}
	a.eng = eng
	return a, nil
}

// release drops one reference; the last one arms the idle reaper.
func (r *streamRegistry) release(a *auxEngine) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a.refs--
	if a.refs > 0 || r.closed {
		return
	}
	a.idle = time.AfterFunc(auxIdleTTL, func() { r.reapIdle(a) })
}

func (r *streamRegistry) reapIdle(a *auxEngine) {
	r.mu.Lock()
	if a.refs != 0 || r.aux[a.key] != a {
		r.mu.Unlock()
		return
	}
	delete(r.aux, a.key)
	r.mu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.eng != nil {
		_ = a.eng.Close(context.Background())
		a.eng = nil
	}
}

func (r *streamRegistry) add(ws *workerStream) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.streams == nil {
		r.streams = make(map[string]map[string]*workerStream)
	}
	if r.streams[ws.sandboxID] == nil {
		r.streams[ws.sandboxID] = make(map[string]*workerStream)
	}
	r.streams[ws.sandboxID][ws.id] = ws
	if r.closed {
		// closeAll ran while this run was starting; it must not outlive it.
		ws.run.Kill()
	}
}

func (r *streamRegistry) remove(ws *workerStream) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.streams[ws.sandboxID], ws.id)
	if len(r.streams[ws.sandboxID]) == 0 {
		delete(r.streams, ws.sandboxID)
	}
}

// killSandbox stops every run of one sandbox (stop, module reload).
func (r *streamRegistry) killSandbox(sandboxID string) {
	r.mu.Lock()
	runs := make([]*wasmengine.Running, 0, len(r.streams[sandboxID]))
	for _, ws := range r.streams[sandboxID] {
		runs = append(runs, ws.run)
	}
	r.mu.Unlock()
	for _, run := range runs {
		run.Kill()
	}
}

// kill stops one run by id; false when the sandbox has no such run.
func (r *streamRegistry) kill(sandboxID, id string) bool {
	r.mu.Lock()
	ws := r.streams[sandboxID][id]
	r.mu.Unlock()
	if ws == nil {
		return false
	}
	ws.run.Kill()
	return true
}

// count is the number of live runs for a sandbox (tests).
func (r *streamRegistry) count(sandboxID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.streams[sandboxID])
}

// closeAll stops every run and releases every aux engine (worker exit).
func (r *streamRegistry) closeAll() {
	r.mu.Lock()
	r.closed = true
	aux := r.aux
	r.aux = nil
	var runs []*wasmengine.Running
	for _, bySandbox := range r.streams {
		for _, ws := range bySandbox {
			runs = append(runs, ws.run)
		}
	}
	r.mu.Unlock()
	for _, run := range runs {
		run.Kill()
	}
	for _, a := range aux {
		a.mu.Lock()
		if a.idle != nil {
			a.idle.Stop()
		}
		if a.eng != nil {
			_ = a.eng.Close(context.Background())
			a.eng = nil
		}
		a.mu.Unlock()
	}
}

// streamWriter turns guest writes on one stdio stream into exec_chunk
// frames. The guest's stdout and stderr are both written from its single
// call goroutine, so n needs no lock.
type streamWriter struct {
	ws     *workerStream
	stream uint8
	n      int64
}

func (w *streamWriter) Write(p []byte) (int, error) {
	total := len(p)
	if max := w.ws.maxOut; max > 0 {
		remain := max - w.n
		if remain <= 0 {
			w.ws.truncated.Store(true)
			return total, nil
		}
		if int64(len(p)) > remain {
			p = p[:remain]
			w.ws.truncated.Store(true)
		}
	}
	w.n += int64(len(p))
	for len(p) > 0 {
		chunk := p[:min(len(p), streamChunkMax)]
		if err := w.ws.writeChunk(w.stream, chunk); err != nil {
			// sandboxd is gone: nobody will read this run's output, so
			// end it instead of letting it run on unseen.
			w.ws.run.Kill()
			return 0, err
		}
		// Guest-to-host output counts toward network bytes, as for Exec.
		w.ws.usage.bytesOut.Add(int64(len(chunk)))
		p = p[len(chunk):]
	}
	return total, nil
}

func (ws *workerStream) writeChunk(stream uint8, data []byte) error {
	ws.writeMu.Lock()
	defer ws.writeMu.Unlock()
	return writeFrame(ws.conn, Envelope{Type: MsgExecChunk, SandboxID: ws.sandboxID, Stream: stream, Payload: data})
}

func writeStreamError(conn net.Conn, sandboxID, code string, err error) error {
	body, encErr := encodePayload(errorPayload{Message: err.Error(), Code: code})
	if encErr != nil {
		return encErr
	}
	return writeFrame(conn, Envelope{Type: MsgError, SandboxID: sandboxID, Payload: body})
}

// serve runs one exec_start to its end on conn, which it then owns: the
// caller's Serve loop returns once serve does.
func (r *streamRegistry) serve(h streamHost, conn net.Conn, env Envelope) error {
	sandboxID := env.SandboxID
	if workerEngineName() == "wasmtime" {
		// wasmtime only has file-backed stdio here; running the stream on
		// wazero instead would quietly bypass the operator's engine choice.
		return writeStreamError(conn, sandboxID, errCodeStreamingUnsupported,
			fmt.Errorf("streaming exec is not supported on the wasmtime engine"))
	}
	var p ExecStartPayload
	if err := decodePayload(env.Payload, &p); err != nil {
		return writeStreamError(conn, sandboxID, "", err)
	}
	if sandboxID == "" {
		return writeStreamError(conn, sandboxID, "", fmt.Errorf("sandbox id required"))
	}
	key := auxKey{path: p.ModulePath, memoryMB: p.Caps.MemoryMB}
	if key.path == "" {
		own, ownMem := h.ownModule()
		if own == "" {
			return writeStreamError(conn, sandboxID, "", fmt.Errorf("engine not loaded"))
		}
		key.path = own
		if key.memoryMB <= 0 {
			key.memoryMB = ownMem
		}
	}
	if err := r.reserve(sandboxID); err != nil {
		return writeStreamError(conn, sandboxID, errCodeStreamLimit, err)
	}
	// The slot goes back before any reply that ends this run, not after:
	// a caller that reads the refusal or the exit and starts again at once
	// must find it free, or at the cap it is refused for a run that is
	// already over. The defer covers every other way out.
	freeSlot := sync.OnceFunc(func() { r.unreserve(sandboxID) })
	defer freeSlot()

	// The run gets the sandbox's network rules exactly as MsgExec applies
	// them: blocks only ever added from caps, and the policy set from them.
	m := h.mediator()
	m.AddBlocks(sandboxID, p.Caps.NetworkBlockIngress, p.Caps.NetworkBlockEgress)
	m.ApplyCapsPolicy(sandboxID, p.Caps)

	ctx := context.Background()
	aux, err := r.acquire(ctx, key)
	if err != nil {
		freeSlot()
		return writeStreamError(conn, sandboxID, "", err)
	}
	defer r.release(aux)

	ws := &workerStream{
		id:        newStreamID(),
		sandboxID: sandboxID,
		conn:      conn,
		maxOut:    p.MaxOutputBytes,
		usage:     h.streamUsage(sandboxID),
	}
	name := sandboxID + "/x/" + ws.id
	// Keyed by the run's own instance name but dialing as the sandbox, so
	// the run shares the sandbox's blocks, policy, audit and byte counts.
	aux.eng.SetNetworkHook(name, &wasmengine.NetworkHook{
		SandboxID: sandboxID,
		Dial:      mediatorDialer{m: m, sandboxID: sandboxID},
		Meter:     &workerByteMeter{u: ws.usage},
	})
	caps := p.Caps
	caps.WASIListenPort = wasmengine.WASIListenPortDisabled
	if p.NoDeadline {
		caps.WallTimeoutNs = wasmengine.NoWallTimeout
	}
	stdinR, stdinW := io.Pipe()
	stdin := newStdinQueue()
	if !p.Stdin {
		stdin.closeInput()
	}

	// Hold the write lock across Start and exec_started, so output the
	// guest writes at once queues behind the started frame.
	ws.writeMu.Lock()
	run, err := aux.eng.Start(ctx, name, caps, p.Export, wasmengine.Stdio{
		In:  stdinR,
		Out: &streamWriter{ws: ws, stream: StreamStdout},
		Err: &streamWriter{ws: ws, stream: StreamStderr},
	})
	if err != nil {
		ws.writeMu.Unlock()
		aux.eng.ClearNetworkHook(name)
		freeSlot()
		return writeStreamError(conn, sandboxID, "", err)
	}
	ws.run = run
	r.add(ws)
	defer r.remove(ws)
	body, err := encodePayload(execStartedPayload{ID: ws.id})
	if err == nil {
		err = writeFrame(conn, Envelope{Type: MsgExecStarted, SandboxID: sandboxID, Payload: body})
	}
	ws.writeMu.Unlock()
	if err != nil {
		run.Kill()
	}
	feederDone := make(chan struct{})
	go func() {
		defer close(feederDone)
		stdin.feed(stdinW)
	}()

	// The frame reader never writes to the guest itself: stdin goes through
	// the queue to the feeder, so a guest that never reads stdin does not
	// stop the reader from seeing sandboxd hang up. Only a full queue makes
	// it wait, and then sandboxd's exec_kill (sent on a fresh connection
	// when it drops a run that has not exited) still ends the run.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			f, err := readFrame(conn)
			if err != nil {
				// sandboxd hung up (or the run ended and serve closed
				// the conn): a run nobody can see must not go on.
				run.Kill()
				return
			}
			switch f.Type {
			case MsgExecStdin:
				// A run without stdin, or one whose guest is gone, drops it.
				stdin.push(f.Payload)
			case MsgExecStdinClose:
				stdin.closeInput()
			case MsgExecKill:
				run.Kill()
			}
		}
	}()

	res, runErr := run.Wait()
	// Free the reader if it waits for queue room, and the feeder if it is
	// blocked writing stdin the guest never read.
	stdin.end()
	_ = stdinR.CloseWithError(io.ErrClosedPipe)
	exit := ExecExit{
		ExitCode:  res.ExitCode,
		Killed:    run.Killed(),
		TimedOut:  run.TimedOut(),
		Truncated: ws.truncated.Load(),
		Usage:     res.Usage,
	}
	if exit.Killed || exit.TimedOut {
		exit.ExitCode = -1
	}
	if runErr != nil && !exit.Killed && !exit.TimedOut {
		exit.Error = runErr.Error()
	}
	// Same rule as the slot: once the caller sees the exit, the run is
	// gone from the list too (remove is safe to repeat in the defer).
	r.remove(ws)
	freeSlot()
	if body, err := encodePayload(exit); err == nil {
		ws.writeMu.Lock()
		_ = conn.SetWriteDeadline(time.Now().Add(streamExitWriteWait))
		_ = writeFrame(conn, Envelope{Type: MsgExecExit, SandboxID: sandboxID, Payload: body})
		ws.writeMu.Unlock()
	}
	_ = conn.Close()
	<-readerDone
	<-feederDone
	return nil
}

// stdinQueue is a run's stdin between the frame reader, which only queues,
// and the feeder goroutine, which writes to the guest's stdin pipe. The
// queue holds up to stdinQueueMax bytes (always at least one frame).
type stdinQueue struct {
	mu     sync.Mutex
	frames [][]byte
	bytes  int
	eof    bool // stdin closed: later frames are dropped
	ended  bool // the run is over: everything is dropped
	// One waiter each, so a one-slot channel and a non-blocking send are
	// enough to wake it; it then looks at the state again.
	ready chan struct{} // feeder: frames or EOF to deliver
	room  chan struct{} // reader: the queue shrank, or the run ended
}

func newStdinQueue() *stdinQueue {
	return &stdinQueue{ready: make(chan struct{}, 1), room: make(chan struct{}, 1)}
}

func wake(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// push queues p for the guest, waiting while the queue is full.
func (q *stdinQueue) push(p []byte) {
	for {
		q.mu.Lock()
		switch {
		case q.ended || q.eof:
			q.mu.Unlock()
			return
		case q.bytes == 0 || q.bytes+len(p) <= stdinQueueMax:
			q.frames = append(q.frames, p)
			q.bytes += len(p)
			q.mu.Unlock()
			wake(q.ready)
			return
		}
		q.mu.Unlock()
		<-q.room
	}
}

// closeInput ends the guest's stdin once what is queued is delivered.
func (q *stdinQueue) closeInput() {
	q.mu.Lock()
	q.eof = true
	q.mu.Unlock()
	wake(q.ready)
}

// end drops what is queued and releases both sides; the run is over.
func (q *stdinQueue) end() {
	q.mu.Lock()
	q.ended = true
	q.frames, q.bytes = nil, 0
	q.mu.Unlock()
	wake(q.ready)
	wake(q.room)
}

// feed writes queued frames to the guest in order, then closes its stdin
// at EOF. It returns at EOF or when the run is over.
func (q *stdinQueue) feed(w *io.PipeWriter) {
	for {
		q.mu.Lock()
		switch {
		case q.ended:
			q.mu.Unlock()
			return
		case len(q.frames) > 0:
			p := q.frames[0]
			q.frames[0] = nil
			q.frames = q.frames[1:]
			q.mu.Unlock()
			// Blocks while the guest is not reading; end's CloseWithError
			// on the read side frees it. A failed write (the guest closed
			// stdin) drops the frame, as a pipe to a gone reader would.
			_, _ = w.Write(p)
			q.mu.Lock()
			if !q.ended {
				q.bytes -= len(p)
			}
			q.mu.Unlock()
			wake(q.room)
			continue
		case q.eof:
			q.mu.Unlock()
			_ = w.Close()
			return
		}
		q.mu.Unlock()
		<-q.ready
	}
}

// serveExecKill handles an out-of-band exec_kill on a fresh connection.
func (r *streamRegistry) serveExecKill(conn net.Conn, env Envelope) error {
	var p execKillPayload
	if err := decodePayload(env.Payload, &p); err != nil || p.ID == "" {
		if err == nil {
			err = errors.New("exec_kill: run id required")
		}
		return writeStreamError(conn, env.SandboxID, "", err)
	}
	// Killing a run that already ended is not an error: the caller only
	// wants it gone.
	r.kill(env.SandboxID, p.ID)
	body, err := encodePayload(okPayload{OK: true})
	if err != nil {
		return err
	}
	return writeFrame(conn, Envelope{Type: MsgOK, SandboxID: env.SandboxID, Payload: body})
}

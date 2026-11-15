package proc

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

const (
	// readChunk is one read from the stdout or stderr pipe, and so the
	// largest output event.
	readChunk = 32 << 10
	// tailBytes is how much stderr an idle kernel keeps, for the error of
	// a driver that dies before READY.
	tailBytes = 4 << 10
	// exitDrain is how long output and events are still read after the
	// driver exited. A child the code started in the background can hold
	// the pipes open for ever; this bounds the wait for their EOF.
	exitDrain = 2 * time.Second
	// markerRS frames a marker: RS NONCE ":" SEQ RS (doc.go).
	markerRS = 0x1e
	// maxSeqDigits bounds the marker's sequence number.
	maxSeqDigits = 20
)

type frame struct {
	kind    string
	payload []byte
}

// pipe is the host end of the driver's stdout (0) or stderr (1).
type pipe struct {
	f *os.File
	// eof is closed when the reader goroutine has stopped.
	eof chan struct{}

	// The fields below belong to the Execute in progress (execMu).
	pending []byte
	marker  uint64 // highest marker read from this pipe
	done    bool   // eof seen by Execute
}

// activeRun is how the pipe readers hand output to the Execute in progress.
type activeRun struct {
	out  [2]chan []byte
	done chan struct{}
}

type kernel struct {
	pid    int
	marker []byte // RS NONCE ":"
	reqW   *os.File
	evR    *os.File
	pipes  [2]*pipe

	frames  chan frame
	exited  chan struct{}
	closing chan struct{}
	// drained is closed exitDrain after the exit: a frame nobody took by
	// then is dropped, so the reader ends even if no run ever comes.
	drained chan struct{}

	mu      sync.Mutex
	run     *activeRun
	tail    []byte
	waitErr error

	execMu sync.Mutex
	synced uint64 // last SYNC handled

	closeOnce sync.Once
}

// startKernel starts cmd with the driver's descriptors and the goroutines
// that keep every pipe drained.
func startKernel(cmd *exec.Cmd, start StartFunc, nonce string) (*kernel, error) {
	var parent, child []*os.File
	closeAll := func(files []*os.File) {
		for _, f := range files {
			_ = f.Close()
		}
	}
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return nil, err
	}
	child = append(child, devnull)
	pipes := make([][2]*os.File, 4) // requests, events, stdout, stderr
	for i := range pipes {
		r, w, err := os.Pipe()
		if err != nil {
			closeAll(parent)
			closeAll(child)
			return nil, err
		}
		pipes[i] = [2]*os.File{r, w}
	}
	reqR, reqW := pipes[0][0], pipes[0][1]
	evR, evW := pipes[1][0], pipes[1][1]
	outR, outW := pipes[2][0], pipes[2][1]
	errR, errW := pipes[3][0], pipes[3][1]
	parent = append(parent, reqW, evR, outR, errR)
	child = append(child, reqR, evW, outW, errW)

	cmd.Stdin = devnull
	cmd.Stdout = outW
	cmd.Stderr = errW
	cmd.ExtraFiles = []*os.File{reqR, evW}
	wait, err := start(cmd)
	// The child has its copies; ours would keep the pipes open after it
	// exits, and the readers would never see EOF.
	closeAll(child)
	if err != nil {
		closeAll(parent)
		return nil, err
	}

	k := &kernel{
		pid:     cmd.Process.Pid,
		marker:  append(append([]byte{markerRS}, nonce...), ':'),
		reqW:    reqW,
		evR:     evR,
		pipes:   [2]*pipe{{f: outR, eof: make(chan struct{})}, {f: errR, eof: make(chan struct{})}},
		frames:  make(chan frame),
		exited:  make(chan struct{}),
		closing: make(chan struct{}),
		drained: make(chan struct{}),
	}
	go k.readEvents()
	go k.readPipe(0)
	go k.readPipe(1)
	go k.wait(wait)
	return k, nil
}

func (k *kernel) wait(wait func() error) {
	err := wait()
	k.mu.Lock()
	k.waitErr = err
	k.mu.Unlock()
	close(k.exited)
	// Nobody calls Close on a kernel that died on its own (the Manager
	// only forgets it), so the kernel frees its descriptors itself. A
	// background child that inherited stdout must not hold the readers.
	deadline := time.Now().Add(exitDrain)
	_ = k.evR.SetReadDeadline(deadline)
	for _, p := range k.pipes {
		_ = p.f.SetReadDeadline(deadline)
	}
	_ = k.reqW.Close()
	time.AfterFunc(exitDrain, func() { close(k.drained) })
}

func (k *kernel) readEvents() {
	defer close(k.frames)
	defer k.evR.Close()
	fr := codeinterp.NewFrameReader(k.evR)
	for {
		kind, payload, err := fr.Read()
		if err != nil {
			return
		}
		select {
		case k.frames <- frame{kind, payload}:
		case <-k.closing:
			return
		case <-k.drained:
			return
		}
	}
}

// readPipe drains one output pipe at all times, so code that prints between
// runs (a background job) never blocks on a full pipe. Output goes to the
// run in progress; with no run it is dropped, except a short stderr tail.
func (k *kernel) readPipe(i int) {
	p := k.pipes[i]
	defer close(p.eof)
	defer p.f.Close()
	buf := make([]byte, readChunk)
	for {
		n, err := p.f.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			k.mu.Lock()
			run := k.run
			if run == nil && i == 1 {
				k.tail = append(k.tail, data...)
				if len(k.tail) > tailBytes {
					k.tail = append([]byte(nil), k.tail[len(k.tail)-tailBytes:]...)
				}
			}
			k.mu.Unlock()
			if run != nil {
				select {
				case run.out[i] <- data:
				case <-run.done:
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// Interrupt sends SIGINT to the kernel's process group.
func (k *kernel) Interrupt() error {
	select {
	case <-k.exited:
		return nil
	default:
	}
	if err := syscall.Kill(-k.pid, syscall.SIGINT); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

// Close kills the kernel's process group and releases its descriptors.
func (k *kernel) Close() error {
	k.closeOnce.Do(func() {
		close(k.closing)
		select {
		case <-k.exited:
			// The leader is reaped, so its pid (the group id) may belong to
			// a new process by now; never signal it.
		default:
			_ = syscall.Kill(-k.pid, syscall.SIGKILL)
		}
		_ = k.reqW.Close()
		_ = k.evR.Close()
		for _, p := range k.pipes {
			_ = p.f.Close()
		}
	})
	return nil
}

// Done is closed when the driver process has exited.
func (k *kernel) Done() <-chan struct{} { return k.exited }

// Execute runs one request. See codeinterp.Kernel.
func (k *kernel) Execute(req codeinterp.Request, sink codeinterp.Sink) (codeinterp.Outcome, error) {
	k.execMu.Lock()
	defer k.execMu.Unlock()
	if sink == nil {
		sink = func(codeinterp.Event) {}
	}
	select {
	case <-k.exited:
		return codeinterp.Outcome{Died: true}, nil
	case <-k.closing:
		return codeinterp.Outcome{Died: true}, nil
	default:
	}

	run := &activeRun{out: [2]chan []byte{make(chan []byte), make(chan []byte)}, done: make(chan struct{})}
	k.mu.Lock()
	k.run = run
	k.mu.Unlock()
	defer func() {
		k.mu.Lock()
		k.run = nil
		k.mu.Unlock()
		close(run.done)
		// What is left after the run's last marker was printed between
		// runs, by a background job: dropped like all idle output.
		for _, p := range k.pipes {
			p.pending = nil
		}
	}()

	if err := k.writeRequest(req); err != nil {
		return codeinterp.Outcome{Died: true}, nil
	}
	x := &execution{k: k, run: run, sink: sink, released: k.synced, exited: k.exited}
	return x.loop(), nil
}

func (k *kernel) writeRequest(req codeinterp.Request) error {
	var buf bytes.Buffer
	names := make([]string, 0, len(req.Env))
	for name := range req.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := codeinterp.WriteFrame(&buf, "ENV", []byte(name+"="+req.Env[name])); err != nil {
			return err
		}
	}
	if err := codeinterp.WriteFrame(&buf, "EXEC", []byte(req.Code)); err != nil {
		return err
	}
	_, err := k.reqW.Write(buf.Bytes())
	return err
}

// execution is one Execute's event loop.
//
// Ordering. The driver writes a marker to fd 1 and 2 and then sends SYNC n,
// and every SYNC announces exactly one frame (a result, an error or DONE).
// So output before marker n goes out before that frame, and output after
// marker n goes out after it. Output before the run's first frame (COUNT)
// waits for it too: a run starts with its execution count.
type execution struct {
	k    *kernel
	run  *activeRun
	sink codeinterp.Sink
	// started is false until the run's first frame was handled.
	started bool
	// released is the last marker whose following output may be sent.
	released uint64
	exited   <-chan struct{}
	drain    <-chan time.Time
	timer    *time.Timer
}

// all lets every byte through: no frame can come any more.
const all = ^uint64(0)

func (x *execution) died() codeinterp.Outcome {
	if x.timer != nil {
		x.timer.Stop()
	}
	// Whatever the driver printed before it died (a segfault message, a
	// "Killed") is the user's best clue; send it all.
	for i, p := range x.k.pipes {
		x.process(i, all)
		x.text(i, p.pending)
		p.pending = nil
	}
	// The Manager forgets a dead kernel without closing it; a driver that
	// only closed its event stream must not live on unseen.
	_ = x.k.Close()
	return codeinterp.Outcome{Died: true}
}

// startDrain bounds what is left of a run whose driver is gone.
func (x *execution) startDrain() {
	if x.timer == nil {
		x.timer = time.NewTimer(exitDrain)
		x.drain = x.timer.C
	}
}

// readable reports whether pipe i's next bytes may be sent now.
func (x *execution) readable(i int) bool {
	p := x.k.pipes[i]
	return !p.done && x.started && p.marker <= x.released
}

func (x *execution) loop() codeinterp.Outcome {
	k := x.k
	frames := k.frames
	for {
		if frames == nil && k.pipes[0].done && k.pipes[1].done {
			return x.died()
		}
		var in [2]chan []byte
		var eof [2]<-chan struct{}
		for i := range k.pipes {
			if x.readable(i) {
				in[i] = x.run.out[i]
				eof[i] = k.pipes[i].eof
			}
		}
		select {
		case fr, ok := <-frames:
			if !ok {
				// No frame can come any more, so the pipes are read to their
				// end: the output of a crash arrives after its last event.
				frames = nil
				x.started = true
				x.release(all)
				x.startDrain()
				continue
			}
			if out, end := x.handle(fr); end {
				if x.timer != nil {
					x.timer.Stop()
				}
				return out
			}
		case data := <-in[0]:
			x.feed(0, data)
		case data := <-in[1]:
			x.feed(1, data)
		case <-eof[0]:
			k.pipes[0].done = true
		case <-eof[1]:
			k.pipes[1].done = true
		case <-x.exited:
			x.exited = nil
			x.startDrain()
		case <-x.drain:
			return x.died()
		}
	}
}

// release lets output after marker n through.
func (x *execution) release(n uint64) {
	if n > x.released {
		x.released = n
	}
	x.process(0, x.released)
	x.process(1, x.released)
}

// handle processes one event frame. end is true when the run is over.
func (x *execution) handle(fr frame) (codeinterp.Outcome, bool) {
	x.started = true
	if fr.kind == "SYNC" {
		seq, err := strconv.ParseUint(string(fr.payload), 10, 64)
		if err != nil || seq <= x.k.synced {
			// A driver that breaks the protocol cannot be trusted with
			// another run.
			return x.died(), true
		}
		// Two SYNCs in a row: the first announced no frame.
		x.release(x.k.synced)
		if !x.awaitMarkers(seq) {
			return x.died(), true
		}
		x.k.synced = seq
		return codeinterp.Outcome{}, false
	}
	if fr.kind == "DONE" {
		// Output after the last marker was printed after the run, by a
		// background job: not this run's.
		return codeinterp.Outcome{Status: string(fr.payload)}, true
	}
	defer x.release(x.k.synced)
	switch fr.kind {
	case "COUNT":
		if n, err := strconv.Atoi(string(fr.payload)); err == nil {
			x.sink(codeinterp.Event{Kind: codeinterp.EventCount, Count: n})
		}
	case "OUT":
		x.sink(codeinterp.Event{Kind: codeinterp.EventStdout, Text: string(fr.payload)})
	case "ERR":
		x.sink(codeinterp.Event{Kind: codeinterp.EventStderr, Text: string(fr.payload)})
	case "RESULT":
		var r struct {
			Data map[string]any `json:"data"`
			Main bool           `json:"main"`
		}
		dec := json.NewDecoder(bytes.NewReader(fr.payload))
		// Numbers in application/json and table data keep their digits.
		dec.UseNumber()
		if err := dec.Decode(&r); err == nil && len(r.Data) > 0 {
			x.sink(codeinterp.Event{Kind: codeinterp.EventResult, Bundle: r.Data, Main: r.Main})
		}
	case "TEXT":
		x.sink(codeinterp.Event{Kind: codeinterp.EventResult, Main: true, Bundle: map[string]any{"text/plain": string(fr.payload)}})
	case "ERROR":
		name, value, tb := codeinterp.ParseErrorPayload(fr.payload)
		x.sink(codeinterp.Event{Kind: codeinterp.EventError, ErrName: name, ErrValue: value, ErrTraceback: tb})
	}
	// READY, FATAL and kinds a newer driver may add mean nothing mid-run.
	return codeinterp.Outcome{}, false
}

// awaitMarkers reads output until both pipes have shown marker seq (or
// ended), so everything printed before the SYNC is sent before the frame
// it announces. It returns false when the driver died and the marker never
// came.
func (x *execution) awaitMarkers(seq uint64) bool {
	k := x.k
	for {
		var in [2]chan []byte
		var eof [2]<-chan struct{}
		waiting := false
		for i, p := range k.pipes {
			if p.done || p.marker >= seq {
				continue
			}
			waiting = true
			in[i] = x.run.out[i]
			eof[i] = p.eof
		}
		if !waiting {
			return true
		}
		select {
		case data := <-in[0]:
			x.feedUntil(0, data, seq)
		case data := <-in[1]:
			x.feedUntil(1, data, seq)
		case <-eof[0]:
			k.pipes[0].done = true
		case <-eof[1]:
			k.pipes[1].done = true
		case <-x.exited:
			x.exited = nil
			x.startDrain()
		case <-x.drain:
			return false
		}
	}
}

// feedUntil adds data while waiting for marker seq: output up to that
// marker may go now.
func (x *execution) feedUntil(i int, data []byte, seq uint64) {
	p := x.k.pipes[i]
	p.pending = append(p.pending, data...)
	x.process(i, seq-1)
}

func (x *execution) feed(i int, data []byte) {
	p := x.k.pipes[i]
	p.pending = append(p.pending, data...)
	x.process(i, x.released)
}

// process sends pipe i's pending bytes while they follow a marker no later
// than limit. It stops at a later marker, and holds back a possible partial
// marker and a partial UTF-8 character at the end.
func (x *execution) process(i int, limit uint64) {
	p := x.k.pipes[i]
	for len(p.pending) > 0 && p.marker <= limit {
		start, end, seq, keep := findMarker(p.pending, x.k.marker)
		if start >= 0 {
			x.text(i, p.pending[:start])
			p.pending = p.pending[end:]
			p.marker = seq
			continue
		}
		n := completeUTF8(p.pending[:keep])
		x.text(i, p.pending[:n])
		p.pending = append([]byte(nil), p.pending[n:]...)
		return
	}
}

func (x *execution) text(i int, b []byte) {
	if len(b) == 0 {
		return
	}
	kind := codeinterp.EventStdout
	if i == 1 {
		kind = codeinterp.EventStderr
	}
	x.sink(codeinterp.Event{Kind: kind, Text: string(b)})
}

// findMarker finds the first complete marker (prefix = RS NONCE ":") in b.
// With no complete marker, start is -1 and keep is where a marker may be
// starting at the end of b: bytes from keep on must wait for more input.
func findMarker(b, prefix []byte) (start, end int, seq uint64, keep int) {
	off := 0
	for {
		i := bytes.IndexByte(b[off:], markerRS)
		if i < 0 {
			return -1, 0, 0, len(b)
		}
		i += off
		rest := b[i:]
		if len(rest) <= len(prefix) {
			if bytes.HasPrefix(prefix, rest) {
				return -1, 0, 0, i
			}
			off = i + 1
			continue
		}
		if !bytes.HasPrefix(rest, prefix) {
			off = i + 1
			continue
		}
		j := len(prefix)
		for j < len(rest) && j-len(prefix) < maxSeqDigits && rest[j] >= '0' && rest[j] <= '9' {
			j++
		}
		switch {
		case j == len(rest) && j-len(prefix) < maxSeqDigits:
			return -1, 0, 0, i
		case j < len(rest) && rest[j] == markerRS && j > len(prefix):
			n, err := strconv.ParseUint(string(rest[len(prefix):j]), 10, 64)
			if err == nil {
				return i, i + j + 1, n, 0
			}
		}
		off = i + 1
	}
}

// completeUTF8 returns the length of b without a trailing partial UTF-8
// character, so one character is never split across two events.
func completeUTF8(b []byte) int {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		c := b[i]
		if c < utf8.RuneSelf {
			return len(b)
		}
		if utf8.RuneStart(c) {
			if utf8.FullRune(b[i:]) {
				return len(b)
			}
			return i
		}
	}
	return len(b)
}

package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// ErrStreamingUnsupported means the worker cannot stream a run: a worker
// adopted from a sandboxd older than streaming exec, or one on the wasmtime
// engine. Callers answer it like any unsupported toolbox route (HTTP 501).
var ErrStreamingUnsupported = errors.New("streaming exec is not supported by this wasm worker")

// ErrStreamLimit means the sandbox already runs as many streams as the
// worker allows.
var ErrStreamLimit = errors.New("too many running processes in this wasm sandbox")

// stdinFrameMax splits large stdin writes into frames well under maxFrameSize.
const stdinFrameMax = 1 << 20

// streamKillTimeout bounds the out-of-band exec_kill round trip.
var streamKillTimeout = 5 * time.Second

// ExecEvent is one message from a streaming run: output, or its exit.
type ExecEvent struct {
	// Stream is StreamStdout or StreamStderr for output events.
	Stream uint8
	Data   []byte
	// Exit is set on the last event of a run.
	Exit *ExecExit
}

// ExecStream is a live streaming run on a worker. Recv must be called from
// one goroutine; WriteStdin, CloseStdin, Kill and Close may be called from
// another.
type ExecStream struct {
	// ID names the run for an out-of-band kill.
	ID string

	client    *Client
	sandboxID string
	conn      net.Conn
	writeMu   sync.Mutex
	exited    bool
	closeOnce sync.Once
}

// StartExec starts a streaming run (MsgExecStart). ctx bounds the start,
// which includes compiling the module the first time it is used; once the
// run has started, ctx no longer matters: end the run with Kill or Close.
func (c *Client) StartExec(ctx context.Context, sandboxID string, p ExecStartPayload) (*ExecStream, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	body, err := encodePayload(p)
	if err != nil {
		return nil, err
	}
	conn, err := c.dialContext(ctx)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	// A cancel during the handshake must end the blocked read, not only a
	// deadline.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, has := ctx.Deadline(); has {
		_ = conn.SetDeadline(deadline)
	}
	reply, err := func() (Envelope, error) {
		if err := writeFrame(conn, Envelope{Type: MsgExecStart, SandboxID: sandboxID, Payload: body}); err != nil {
			return Envelope{}, err
		}
		return readFrame(conn)
	}()
	if err != nil {
		if ctxErr := contextErr(ctx); ctxErr != nil {
			return nil, ctxErr
		}
		// The conn deadline can fire a moment before ctx's own timer.
		if deadline, has := ctx.Deadline(); has && !time.Now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
	switch reply.Type {
	case MsgExecStarted:
		var started execStartedPayload
		if err := decodePayload(reply.Payload, &started); err != nil {
			return nil, err
		}
		if !stop() {
			// ctx ended after the reply arrived and the deadline was set:
			// treat the start as cancelled.
			return nil, ctx.Err()
		}
		_ = conn.SetDeadline(time.Time{})
		ok = true
		return &ExecStream{ID: started.ID, client: c, sandboxID: sandboxID, conn: conn}, nil
	case MsgError:
		return nil, streamStartError(reply)
	case MsgInvokeResult:
		// A per-sandbox worker older than streaming exec answers every type
		// it does not know with an empty invoke result.
		if len(reply.Payload) == 0 {
			return nil, ErrStreamingUnsupported
		}
	}
	return nil, fmt.Errorf("unexpected reply type %q", reply.Type)
}

// streamStartError maps a refused exec_start to the typed errors.
func streamStartError(reply Envelope) error {
	var p errorPayload
	if err := decodePayload(reply.Payload, &p); err != nil {
		return err
	}
	switch {
	case p.Code == errCodeStreamingUnsupported:
		return fmt.Errorf("%w: %s", ErrStreamingUnsupported, p.Message)
	case p.Code == errCodeStreamLimit:
		return fmt.Errorf("%w: %s", ErrStreamLimit, p.Message)
	case strings.HasPrefix(p.Message, string(MsgExecStart)+" not supported"):
		// A resident host older than streaming exec refuses unknown types
		// by name.
		return ErrStreamingUnsupported
	}
	return errors.New(p.Message)
}

// RunID is the run's id (ID), for callers that hold the stream behind an
// interface.
func (s *ExecStream) RunID() string { return s.ID }

// Recv returns the next output chunk or, last, the exit. After the exit it
// returns io.EOF.
func (s *ExecStream) Recv() (ExecEvent, error) {
	if s.exited {
		return ExecEvent{}, io.EOF
	}
	for {
		f, err := readFrame(s.conn)
		if err != nil {
			return ExecEvent{}, err
		}
		switch f.Type {
		case MsgExecChunk:
			if len(f.Payload) == 0 {
				continue
			}
			return ExecEvent{Stream: f.Stream, Data: f.Payload}, nil
		case MsgExecExit:
			var exit ExecExit
			if err := decodePayload(f.Payload, &exit); err != nil {
				return ExecEvent{}, err
			}
			s.exited = true
			return ExecEvent{Exit: &exit}, nil
		default:
			return ExecEvent{}, fmt.Errorf("unexpected stream frame %q", f.Type)
		}
	}
}

// WriteStdin sends bytes to the run's stdin. It blocks while the guest is
// not reading (backpressure); Kill still works then.
func (s *ExecStream) WriteStdin(p []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	for len(p) > 0 {
		chunk := p[:min(len(p), stdinFrameMax)]
		if err := writeFrame(s.conn, Envelope{Type: MsgExecStdin, SandboxID: s.sandboxID, Payload: chunk}); err != nil {
			return err
		}
		p = p[len(chunk):]
	}
	return nil
}

// CloseStdin sends EOF to the run's stdin.
func (s *ExecStream) CloseStdin() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeFrame(s.conn, Envelope{Type: MsgExecStdinClose, SandboxID: s.sandboxID})
}

// Kill stops the run. It goes over a fresh connection: the run's own may be
// stalled behind stdin the guest never reads. The exit still arrives on
// Recv, marked killed.
func (s *ExecStream) Kill() error {
	body, err := encodePayload(execKillPayload{ID: s.ID})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), streamKillTimeout)
	defer cancel()
	reply, err := s.client.roundTripContext(ctx, Envelope{Type: MsgExecKill, SandboxID: s.sandboxID, Payload: body})
	if err != nil {
		return err
	}
	return s.client.expectOK(reply)
}

// Close drops the connection. A run whose connection drops is killed, so
// Close also ends a run that is still going.
func (s *ExecStream) Close() error {
	var err error
	s.closeOnce.Do(func() { err = s.conn.Close() })
	return err
}

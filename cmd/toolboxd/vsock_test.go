package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// recordingHandler tracks every callback invocation so the protocol
// tests can assert which handler ran for each op. Generic on purpose —
// the real handlers (loggingVsockHandler, future session-flush handler)
// implement the same interface and can be swapped in.
type recordingHandler struct {
	mu     sync.Mutex
	calls  []string
	failOp VsockOp // when set, this op returns an error
	failOn error
}

func (h *recordingHandler) record(op VsockOp) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, string(op))
	if h.failOp == op {
		return h.failOn
	}
	return nil
}

func (h *recordingHandler) Calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := make([]string, len(h.calls))
	copy(c, h.calls)
	return c
}

func (h *recordingHandler) OnPing(context.Context) error { return h.record(OpPing) }
func (h *recordingHandler) OnPreSnapshot(_ context.Context, _ json.RawMessage) error {
	return h.record(OpPreSnapshot)
}
func (h *recordingHandler) OnPostResume(_ context.Context, _ json.RawMessage) error {
	return h.record(OpPostResume)
}

// pipeConn pairs two io.PipeReader/PipeWriter into a full-duplex
// io.ReadWriter so handleVsockConn can be driven from a test goroutine
// as if it were a real connection. We need both directions because the
// handler reads ops AND writes acks back; a single net.Pipe pair would
// do but this is a few lines and explicit about which end is which.
type pipeConn struct {
	r io.Reader
	w io.Writer
}

func (p *pipeConn) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeConn) Write(b []byte) (int, error) { return p.w.Write(b) }

// newPipePair returns the (host, guest) ends of a bidirectional pipe.
// The host end is what the test writes to and reads from; the guest
// end is what handleVsockConn operates on.
func newPipePair() (host, guest *pipeConn) {
	hostReadPipe, guestWritePipe := io.Pipe()
	guestReadPipe, hostWritePipe := io.Pipe()
	host = &pipeConn{r: hostReadPipe, w: hostWritePipe}
	guest = &pipeConn{r: guestReadPipe, w: guestWritePipe}
	return host, guest
}

// runHandlerInBackground drives handleVsockConn on a separate goroutine
// so the test can synchronously send/recv on the host end. Returns a
// done channel the test can wait on after closing the host write side.
func runHandlerInBackground(t *testing.T, guest *pipeConn, handler VsockHandler) chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleVsockConn(context.Background(), guest, handler, nil)
	}()
	return done
}

func TestVsock_Ping(t *testing.T) {
	host, guest := newPipePair()
	h := &recordingHandler{}
	done := runHandlerInBackground(t, guest, h)

	// Send ping.
	if _, err := host.Write([]byte(`{"op":"ping"}` + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Read ack.
	var resp VsockResponse
	if err := json.NewDecoder(host).Decode(&resp); err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if !resp.Ok {
		t.Errorf("expected Ok=true, got %+v", resp)
	}
	// Close host write to signal EOF to the handler.
	closePipeWriter(host)
	<-done

	if got := h.Calls(); len(got) != 1 || got[0] != "ping" {
		t.Errorf("calls = %v, want [ping]", got)
	}
}

func TestVsock_AllOps(t *testing.T) {
	for _, op := range []VsockOp{OpPing, OpPreSnapshot, OpPostResume} {
		t.Run(string(op), func(t *testing.T) {
			host, guest := newPipePair()
			h := &recordingHandler{}
			done := runHandlerInBackground(t, guest, h)

			msg, _ := json.Marshal(VsockMessage{Op: op})
			_, _ = host.Write(append(msg, '\n'))
			var resp VsockResponse
			if err := json.NewDecoder(host).Decode(&resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !resp.Ok {
				t.Errorf("want Ok, got %+v", resp)
			}
			closePipeWriter(host)
			<-done
			if got := h.Calls(); len(got) != 1 || got[0] != string(op) {
				t.Errorf("calls = %v", got)
			}
		})
	}
}

func TestVsock_UnknownOpReturnsError(t *testing.T) {
	host, guest := newPipePair()
	h := &recordingHandler{}
	done := runHandlerInBackground(t, guest, h)

	_, _ = host.Write([]byte(`{"op":"future_op"}` + "\n"))
	var resp VsockResponse
	if err := json.NewDecoder(host).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error == "" {
		t.Errorf("expected Error to be set, got %+v", resp)
	}
	if !strings.Contains(resp.Error, "future_op") {
		t.Errorf("error did not name the unknown op: %q", resp.Error)
	}
	closePipeWriter(host)
	<-done
}

func TestVsock_MissingOp(t *testing.T) {
	host, guest := newPipePair()
	done := runHandlerInBackground(t, guest, newLoggingVsockHandler(nil))

	_, _ = host.Write([]byte(`{}` + "\n"))
	var resp VsockResponse
	_ = json.NewDecoder(host).Decode(&resp)
	if resp.Error == "" || !strings.Contains(resp.Error, "missing op") {
		t.Errorf("expected 'missing op' error, got %+v", resp)
	}
	closePipeWriter(host)
	<-done
}

// TestVsock_HandlerErrorDoesNotCloseConn confirms a per-op error sends
// an Error ack but keeps the connection open for the next op. This is
// the right behavior because the host's reconnect cost is high relative
// to a single-op failure (the host already has the channel established
// for the snapshot lifecycle).
func TestVsock_HandlerErrorDoesNotCloseConn(t *testing.T) {
	host, guest := newPipePair()
	h := &recordingHandler{failOp: OpPreSnapshot, failOn: errors.New("flush failed")}
	done := runHandlerInBackground(t, guest, h)

	_, _ = host.Write([]byte(`{"op":"pre_snapshot"}` + "\n"))
	var resp VsockResponse
	_ = json.NewDecoder(host).Decode(&resp)
	if resp.Error == "" || !strings.Contains(resp.Error, "flush failed") {
		t.Errorf("want flush failed, got %+v", resp)
	}

	// Connection still alive — send a follow-up ping.
	_, _ = host.Write([]byte(`{"op":"ping"}` + "\n"))
	var resp2 VsockResponse
	if err := json.NewDecoder(host).Decode(&resp2); err != nil {
		t.Fatalf("decode follow-up: %v", err)
	}
	if !resp2.Ok {
		t.Errorf("follow-up ping should succeed, got %+v", resp2)
	}

	closePipeWriter(host)
	<-done

	if got := h.Calls(); len(got) != 2 || got[0] != "pre_snapshot" || got[1] != "ping" {
		t.Errorf("calls = %v, want [pre_snapshot ping]", got)
	}
}

// TestVsock_DecodeErrorClosesConn confirms a malformed line is a fatal
// error for the connection (we don't try to skip ahead to the next
// newline). The host should reconnect.
func TestVsock_DecodeErrorClosesConn(t *testing.T) {
	host, guest := newPipePair()
	done := runHandlerInBackground(t, guest, newLoggingVsockHandler(nil))

	_, _ = host.Write([]byte("not json\n"))
	var resp VsockResponse
	if err := json.NewDecoder(host).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(resp.Error, "decode:") {
		t.Errorf("expected decode error, got %+v", resp)
	}
	// Connection should be closed by the handler — closing our side
	// won't help, but the done channel should have already fired.
	closePipeWriter(host)
	<-done
}

// closePipeWriter calls Close on the underlying *io.PipeWriter so the
// handler's Read returns EOF. We have to reach through the wrapper since
// pipeConn doesn't expose the closer directly.
func closePipeWriter(p *pipeConn) {
	if c, ok := p.w.(io.Closer); ok {
		_ = c.Close()
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// stuckSink blocks every Write until release is closed, like a guest serial
// console that stopped draining after a snapshot restore.
type stuckSink struct {
	release chan struct{}
	mu      sync.Mutex
	buf     bytes.Buffer
}

func (s *stuckSink) Write(p []byte) (int, error) {
	<-s.release
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *stuckSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type acceptingAdopter struct{}

func (acceptingAdopter) adoptOverVsock(string, string) (bool, error) { return true, nil }

// The adopt handler logs before it returns, and the vsock loop acks only
// after that. With the console stuck, the ack must still come back.
func TestAdoptAckIsNotHeldByAStuckLogSink(t *testing.T) {
	sink := &stuckSink{release: make(chan struct{})}
	h := newQuiesceHandler(newAgentLogger(sink), nil, nil)
	h.identity = acceptingAdopter{}

	host, guest := newPipePair()
	done := runHandlerInBackground(t, guest, h)
	// Unstick the sink first: without the fix the handler is blocked in a
	// log write, and waiting for it before releasing would hang the test.
	defer func() {
		close(sink.release)
		closePipeWriter(host)
		<-done
	}()

	if _, err := host.Write([]byte(`{"op":"adopt","data":{"sandbox_id":"sb-0123456789abcdef","token":"t"}}` + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make(chan VsockResponse, 1)
	go func() {
		var resp VsockResponse
		if err := json.NewDecoder(host).Decode(&resp); err == nil {
			got <- resp
		}
	}()
	select {
	case resp := <-got:
		if !resp.Ok {
			t.Fatalf("adopt answered %+v, want ok", resp)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no adopt ack within 3 s while the log sink is stuck: a log write held the ack back")
	}
}

// A full queue drops lines instead of waiting, and the sink is told how many
// once it takes writes again.
func TestAsyncWriterDropsWhenFullAndSaysSo(t *testing.T) {
	sink := &stuckSink{release: make(chan struct{})}
	w := newAsyncWriter(sink, 2)
	start := time.Now()
	// One line is taken by the drain goroutine (stuck in Write), two wait in
	// the queue, and the rest are dropped.
	for i := 0; i < 10; i++ {
		if n, err := w.Write([]byte("line\n")); n != 5 || err != nil {
			t.Fatalf("write %d: n=%d err=%v", i, n, err)
		}
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("writes to a stuck sink took %v; they must not wait", took)
	}
	close(sink.release)
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(sink.String(), "dropped") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	out := sink.String()
	if !strings.Contains(out, "log line(s) dropped while the log sink was not taking writes") {
		t.Fatalf("no drop note in sink output:\n%s", out)
	}
	if strings.Count(out, "line\n") < 2 {
		t.Fatalf("queued lines lost:\n%s", out)
	}
}

// The writer copies what it is given: slog reuses its buffer.
func TestAsyncWriterCopiesTheBuffer(t *testing.T) {
	sink := &stuckSink{release: make(chan struct{})}
	close(sink.release)
	w := newAsyncWriter(sink, 4)
	buf := []byte("first\n")
	_, _ = w.Write(buf)
	copy(buf, "XXXXX\n")
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(sink.String(), "\n") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := sink.String(); got != "first\n" {
		t.Fatalf("sink got %q, want %q", got, "first\n")
	}
}

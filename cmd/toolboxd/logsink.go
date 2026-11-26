package main

import (
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
)

// logQueueDepth is how many log records wait for a sink that is slow or has
// stopped. Past it a record is dropped (and counted), never waited for.
const logQueueDepth = 1024

// newAgentLogger is toolboxd's logger. Its records go to w through an
// asyncWriter, so writing a log line can never block the code that logs.
//
// In a Firecracker guest, w is the serial console. After a snapshot restore
// the console can stop draining; a log write then blocks in the kernel's tty
// layer. The vsock loop writes an op's ack only after the op's handler
// returns, and the handlers log before they return (adopt logs "adopt
// applied"), so a blocked log line used to hold the ack back for good: the
// host saw "read ack: i/o timeout" on every retry and lost the sandbox (M2
// spike SP-A, 2026-11-26: 1 in 60 resumes on bare metal, 3 in 60 nested).
func newAgentLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(newAsyncWriter(w, logQueueDepth), &slog.HandlerOptions{}))
}

// asyncWriter hands each write to one goroutine that copies it to the sink.
// A write returns at once: queued when there is room, dropped and counted
// when the queue is full. Once the sink takes writes again, the goroutine
// first writes how many lines were dropped.
type asyncWriter struct {
	queue   chan []byte
	dropped atomic.Uint64
}

func newAsyncWriter(sink io.Writer, depth int) *asyncWriter {
	a := &asyncWriter{queue: make(chan []byte, depth)}
	go a.drain(sink)
	return a
}

func (a *asyncWriter) drain(sink io.Writer) {
	for line := range a.queue {
		if n := a.dropped.Swap(0); n > 0 {
			_, _ = fmt.Fprintf(sink, "toolboxd: %d log line(s) dropped while the log sink was not taking writes\n", n)
		}
		_, _ = sink.Write(line)
	}
}

// Write copies p: slog reuses its buffer after Write returns.
func (a *asyncWriter) Write(p []byte) (int, error) {
	line := append([]byte(nil), p...)
	select {
	case a.queue <- line:
	default:
		a.dropped.Add(1)
	}
	return len(p), nil
}

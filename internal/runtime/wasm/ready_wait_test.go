package wasm

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// readyPingClient answers pings once serving is set, and counts them.
type readyPingClient struct {
	WorkerClient
	serving atomic.Bool
	pings   atomic.Int64
}

func (c *readyPingClient) Ping(string) error {
	c.pings.Add(1)
	if c.serving.Load() {
		return nil
	}
	return errors.New("not serving")
}

// slowPoll stands in a poll whose every step is a minute: only the ready
// signal can end a wait in a test's time.
func slowPoll(t *testing.T) {
	t.Helper()
	prev := pollSleep
	pollSleep = func(ctx context.Context, attempt int, ready <-chan struct{}) bool {
		if attempt <= 0 {
			return false
		}
		select {
		case <-ready:
			return true
		case <-ctx.Done():
		case <-time.After(time.Minute):
		}
		return false
	}
	t.Cleanup(func() { pollSleep = prev })
}

// The worker's signal ends the wait: it is pinged at once, not at the next
// poll step.
func TestWaitWorkerWakesOnReady(t *testing.T) {
	slowPoll(t)
	d := New(Config{}, nil)
	c := &readyPingClient{}
	ready := make(chan struct{})
	go func() {
		time.Sleep(20 * time.Millisecond)
		c.serving.Store(true)
		close(ready)
	}()
	start := time.Now()
	if err := d.waitWorker(context.Background(), c, "sb", ready); err != nil {
		t.Fatal(err)
	}
	// Two pings at once (the first poll step is zero), then one after the
	// signal.
	if took := time.Since(start); took > 10*time.Second || c.pings.Load() != 3 {
		t.Fatalf("took %v with %d pings, want one ping after the signal", took, c.pings.Load())
	}
}

// A signal from a worker that does not serve only moves one ping: the
// wait goes back to the poll steps (no busy loop on a closed channel), and
// finds the worker when it serves.
func TestWaitWorkerReadyWithoutServing(t *testing.T) {
	d := New(Config{}, nil)
	c := &readyPingClient{}
	ready := make(chan struct{})
	close(ready)
	go func() {
		time.Sleep(40 * time.Millisecond)
		c.serving.Store(true)
	}()
	if err := d.waitWorker(context.Background(), c, "sb", ready); err != nil {
		t.Fatal(err)
	}
	if n := c.pings.Load(); n > 10 {
		t.Fatalf("%d pings in about 40ms: the closed signal kept ending the waits", n)
	}
}

// No signal (an adopted worker, a supervisor without one) and a signal that
// never comes (a worker that holds the pipe and never writes) both leave
// the poll as it was.
func TestWaitWorkerPollsWithoutSignal(t *testing.T) {
	for name, ready := range map[string]chan struct{}{"none": nil, "never written": make(chan struct{})} {
		d := New(Config{}, nil)
		c := &readyPingClient{}
		go func() {
			time.Sleep(15 * time.Millisecond)
			c.serving.Store(true)
		}()
		if err := d.waitWorker(context.Background(), c, "sb", ready); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.pings.Load() < 2 {
			t.Fatalf("%s: %d pings", name, c.pings.Load())
		}
	}
}

// The wait keeps its deadline whatever the signal does.
func TestWaitWorkerTimeout(t *testing.T) {
	d := New(Config{}, nil)
	for name, ready := range map[string]chan struct{}{"never written": make(chan struct{}), "written, never serves": func() chan struct{} {
		c := make(chan struct{})
		close(c)
		return c
	}()} {
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		start := time.Now()
		err := d.waitWorker(ctx, &readyPingClient{}, "sb", ready)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "worker not ready") {
			t.Fatalf("%s: %v", name, err)
		}
		if took := time.Since(start); took < 70*time.Millisecond || took > 5*time.Second {
			t.Fatalf("%s: gave up after %v", name, took)
		}
	}
}

type readySignalSupervisor struct {
	WorkerSupervisor
	ch chan struct{}
}

func (s readySignalSupervisor) Ready(string) <-chan struct{} { return s.ch }

func TestWorkerReady(t *testing.T) {
	ch := make(chan struct{})
	if got := workerReady(readySignalSupervisor{ch: ch}, "k"); got != (<-chan struct{})(ch) {
		t.Fatal("the supervisor's signal was not used")
	}
	if workerReady(&startFailEnsureSupervisor{}, "k") != nil {
		t.Fatal("a supervisor without a signal gave one")
	}
}

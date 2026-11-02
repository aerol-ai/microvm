package cluster

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// queued reports how many callers wait on the call queued behind the
// running one for key.
func (g *freshFlight[V]) queued(key string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if c, ok := g.calls[key]; ok && c.next != nil {
		return c.next.waiters
	}
	return 0
}

// Callers that arrive while a read runs share ONE next read, never the
// running one: the running read began before they asked.
func TestFreshFlightCallersBehindARunningReadShareTheNextOne(t *testing.T) {
	var g freshFlight[int]
	var calls atomic.Int32
	release := make(chan struct{})
	fn := func() (int, error) {
		n := int(calls.Add(1))
		if n == 1 {
			<-release
		}
		return n, nil
	}

	leader := make(chan int, 1)
	go func() {
		v, _, shared := g.do("k", fn)
		if shared {
			t.Error("the first caller ran its own read; it must not report it shared")
		}
		leader <- v
	}()
	waitFor(t, 5*time.Second, "the first read to start", func() bool { return calls.Load() == 1 })

	const waiters = 50
	results := make(chan int, waiters)
	var wg sync.WaitGroup
	for range waiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err, shared := g.do("k", fn)
			if err != nil || !shared {
				t.Errorf("waiter: err %v shared %v", err, shared)
			}
			results <- v
		}()
	}
	waitFor(t, 5*time.Second, "the waiters to queue", func() bool { return g.queued("k") == waiters })
	close(release)
	wg.Wait()
	close(results)

	if v := <-leader; v != 1 {
		t.Fatalf("first caller got read %d, want 1", v)
	}
	for v := range results {
		if v != 2 {
			t.Fatalf("a waiter got read %d, want 2 (the read that began after it asked)", v)
		}
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("%d reads for 1 + %d callers, want 2", n, waiters)
	}
}

// Under a storm every answer comes from a read that began after the caller
// asked — the guarantee an uncoalesced read gives — and at most one read
// per key runs at a time.
func TestFreshFlightNeverAnswersWithAReadOlderThanTheRequest(t *testing.T) {
	var g freshFlight[int64]
	var started, running, maxRunning atomic.Int64
	fn := func() (int64, error) {
		seq := started.Add(1)
		if r := running.Add(1); r > maxRunning.Load() {
			maxRunning.Store(r)
		}
		time.Sleep(200 * time.Microsecond)
		running.Add(-1)
		return seq, nil
	}
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				before := started.Load()
				v, err, _ := g.do("k", fn)
				if err != nil {
					t.Error(err)
					return
				}
				if v <= before {
					t.Errorf("answered with read %d, but %d reads had started before the request", v, before)
					return
				}
			}
		}()
	}
	wg.Wait()
	if m := maxRunning.Load(); m != 1 {
		t.Fatalf("%d reads of one key ran at once, want 1", m)
	}
	if started.Load() >= 64*50 {
		t.Fatalf("%d reads for %d requests: nothing was coalesced", started.Load(), 64*50)
	}
}

// Different keys never wait on each other.
func TestFreshFlightKeysAreIndependent(t *testing.T) {
	var g freshFlight[string]
	release := make(chan struct{})
	var inFlight atomic.Int32
	fn := func(key string) func() (string, error) {
		return func() (string, error) {
			inFlight.Add(1)
			<-release
			return key, nil
		}
	}
	got := make(chan string, 2)
	for _, key := range []string{"a", "b"} {
		go func() {
			v, _, _ := g.do(key, fn(key))
			got <- v
		}()
	}
	waitFor(t, 5*time.Second, "both keys' reads to run at once", func() bool { return inFlight.Load() == 2 })
	close(release)
	answers := []string{<-got, <-got}
	if !(answers[0] != answers[1] && strings.Contains("ab", answers[0]) && strings.Contains("ab", answers[1])) {
		t.Fatalf("answers %v, want one per key", answers)
	}
}

// A read that panics answers its caller with an error and does not strand
// the callers queued behind it, whose own read still runs.
func TestFreshFlightAPanicStrandsNoOne(t *testing.T) {
	var g freshFlight[int]
	release := make(chan struct{})
	var calls atomic.Int32
	fn := func() (int, error) {
		if calls.Add(1) == 1 {
			<-release
			panic("boom")
		}
		return 7, nil
	}
	leaderErr := make(chan error, 1)
	go func() {
		_, err, _ := g.do("k", fn)
		leaderErr <- err
	}()
	waitFor(t, 5*time.Second, "the first read to start", func() bool { return calls.Load() == 1 })
	waiter := make(chan int, 1)
	go func() {
		v, _, _ := g.do("k", fn)
		waiter <- v
	}()
	waitFor(t, 5*time.Second, "the waiter to queue", func() bool { return g.queued("k") == 1 })
	close(release)
	if err := <-leaderErr; err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("leader error = %v, want the panic as an error", err)
	}
	select {
	case v := <-waiter:
		if v != 7 {
			t.Fatalf("waiter got %d, want 7", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter behind a panicking read was stranded")
	}
	// Nothing is left behind for the key.
	waitFor(t, 5*time.Second, "the key to be released", func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		return len(g.calls) == 0
	})
}

// An error is shared like a value.
func TestFreshFlightSharesErrors(t *testing.T) {
	var g freshFlight[int]
	want := errors.New("control plane down")
	if _, err, _ := g.do("k", func() (int, error) { return 0, want }); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

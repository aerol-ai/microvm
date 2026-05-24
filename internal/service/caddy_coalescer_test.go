package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestCoalescerCollapsesSameKey is the load-bearing invariant: a rapid
// sequence of Enqueues on the same (id, port) reduces to exactly one
// execution per tick — the LAST intent.
func TestCoalescerCollapsesSameKey(t *testing.T) {
	c := newCaddyCoalescer(quietLogger(), 50*time.Millisecond)
	go c.Run(t.Context())
	defer c.Stop()

	var (
		mu        sync.Mutex
		observed  []string
		callCount atomic.Int64
	)
	record := func(label string) func() error {
		return func() error {
			callCount.Add(1)
			mu.Lock()
			observed = append(observed, label)
			mu.Unlock()
			return nil
		}
	}

	// 5 enqueues for the same key before the tick fires; only the last
	// (op-4) should land. callCount = 1 proves coalescing happened.
	for i := range 5 {
		c.Enqueue("sb-1", 8080, record(fmt.Sprintf("op-%d", i)))
	}

	// Wait for the next tick to drain.
	deadline := time.Now().Add(500 * time.Millisecond)
	for callCount.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	if got := callCount.Load(); got != 1 {
		t.Fatalf("got %d executions, want 1 (coalesce failed)", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(observed) != 1 || observed[0] != "op-4" {
		t.Fatalf("observed = %v, want [op-4] — coalescer kept the wrong intent", observed)
	}
}

// TestCoalescerDistinctKeysIndependent: different (id, port) keys must
// NOT collapse — each runs its own op in the tick.
func TestCoalescerDistinctKeysIndependent(t *testing.T) {
	c := newCaddyCoalescer(quietLogger(), 30*time.Millisecond)
	go c.Run(t.Context())
	defer c.Stop()

	var seen sync.Map
	mark := func(key string) func() error {
		return func() error {
			seen.Store(key, true)
			return nil
		}
	}

	c.Enqueue("sb-a", 8080, mark("a:8080"))
	c.Enqueue("sb-a", 9090, mark("a:9090")) // same id, different port → distinct key
	c.Enqueue("sb-b", 8080, mark("b:8080"))

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, a1 := seen.Load("a:8080")
		_, a2 := seen.Load("a:9090")
		_, b1 := seen.Load("b:8080")
		if a1 && a2 && b1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("not all distinct keys executed within window")
}

// TestCoalescerFlushWaitsForResult: Flush is the ordering-critical API
// — it must block until the op runs and return its error verbatim.
func TestCoalescerFlushWaitsForResult(t *testing.T) {
	// Use a long tick so we prove Flush is driving the drain, not the
	// ticker.
	c := newCaddyCoalescer(quietLogger(), time.Hour)
	go c.Run(t.Context())
	defer c.Stop()

	want := errors.New("write rejected by caddy")
	err := c.Flush(context.Background(), "sb-flush", 8080, func() error {
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("Flush returned %v, want %v", err, want)
	}
}

// TestCoalescerFlushRespectsCtx: a cancelled ctx unblocks the Flush
// caller while leaving the op queued for the tick.
func TestCoalescerFlushRespectsCtx(t *testing.T) {
	c := newCaddyCoalescer(quietLogger(), time.Hour)
	go c.Run(t.Context())
	defer c.Stop()

	// Block the do func until release fires, so the drain triggered by
	// Flush is in-flight when the ctx is cancelled. Without this the
	// tight drain races the ctx cancellation.
	release := make(chan struct{})
	executed := make(chan struct{})
	op := func() error {
		<-release
		close(executed)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := c.Flush(ctx, "sb-ctx", 8080, op)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Flush returned %v, want DeadlineExceeded", err)
	}
	// The op eventually runs; release it so the test can exit cleanly.
	close(release)
	select {
	case <-executed:
	case <-time.After(time.Second):
		t.Fatalf("op never executed after ctx cancellation")
	}
}

// TestCoalescerDropNotifiesPriorWaiterWithNil: when a later Enqueue
// supersedes a pending op that had a notify channel attached, the
// prior waiter must receive nil (eventual consistency, not a failure).
//
// We drive the internal enqueue helper directly so the test does not
// race the goroutine that Flush kicks for its immediate drain. The
// guarantee under test is independent of whether Flush or some other
// caller wired up the notify channel.
func TestCoalescerDropNotifiesPriorWaiterWithNil(t *testing.T) {
	c := newCaddyCoalescer(quietLogger(), time.Hour) // ticker won't fire
	// Do NOT start Run — no drain pressure, so the prior op stays
	// pending until the supersession lands.

	notify := make(chan error, 1)
	c.enqueue("sb-drop", 8080, func() error {
		return errors.New("stale op ran")
	}, notify)

	c.Enqueue("sb-drop", 8080, func() error { return nil })

	select {
	case err := <-notify:
		if err != nil {
			t.Fatalf("dropped waiter got %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("dropped waiter never woke up")
	}
}

// TestCoalescerStopDrainsFinalBatch: Stop must execute any pending op
// before returning so shutdown does not silently drop writes.
func TestCoalescerStopDrainsFinalBatch(t *testing.T) {
	c := newCaddyCoalescer(quietLogger(), time.Hour) // ticker won't fire
	go c.Run(t.Context())

	var ran atomic.Bool
	c.Enqueue("sb-final", 8080, func() error {
		ran.Store(true)
		return nil
	})
	c.Stop()
	if !ran.Load() {
		t.Fatalf("Stop returned without draining pending op")
	}
}

// TestCoalescerCtxCancelDrains: ctx cancellation should drain on the
// way out, same as Stop.
func TestCoalescerCtxCancelDrains(t *testing.T) {
	c := newCaddyCoalescer(quietLogger(), time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)

	var ran atomic.Bool
	c.Enqueue("sb-ctx-drain", 8080, func() error {
		ran.Store(true)
		return nil
	})
	cancel()
	// Run returns after its final drain; wait for done.
	deadline := time.Now().Add(time.Second)
	for !ran.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !ran.Load() {
		t.Fatalf("ctx cancel did not drain final op")
	}
}

// TestCoalescerPendingSize: the diagnostic counter must reflect what
// the next drain will process.
func TestCoalescerPendingSize(t *testing.T) {
	c := newCaddyCoalescer(quietLogger(), time.Hour)
	// Don't start Run — we want to inspect pending without the ticker
	// draining underneath us.
	noop := func() error { return nil }
	c.Enqueue("sb-1", 8080, noop)
	c.Enqueue("sb-2", 8080, noop)
	c.Enqueue("sb-1", 8080, noop) // collapses with sb-1
	if got := c.pendingSize(); got != 2 {
		t.Fatalf("pendingSize = %d, want 2", got)
	}
}

// BenchmarkCoalescerThroughput is the D6 baseline number. We measure
// Enqueue cost under a tight loop because that is the actual hot path
// the bypass-on rollout will hammer: each Start/Stop produces 1
// Enqueue per HTTP exposure. Drain throughput is not the bottleneck
// (Caddy admin is) — Enqueue is.
//
// Run with: go test -bench=BenchmarkCoalescerThroughput -benchmem
//
//	./internal/service/...
func BenchmarkCoalescerThroughput(b *testing.B) {
	c := newCaddyCoalescer(quietLogger(), 10*time.Millisecond)
	go c.Run(b.Context())
	defer c.Stop()

	op := func() error { return nil }
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Distinct keys per goroutine so we measure the lock-contention
		// floor, not artificial coalesce collapse.
		gid := fmt.Sprintf("sb-%p", pb)
		i := 0
		for pb.Next() {
			c.Enqueue(gid, i%64, op)
			i++
		}
	})
}

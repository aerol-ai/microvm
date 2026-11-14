package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// keyedLocks: one holder per key, other keys never wait, a lockCtx waiter
// gives up with its caller, a free lock is taken even by a caller whose ctx
// already ended, and a key with no holder or waiter leaves nothing behind.
func TestKeyedLocks(t *testing.T) {
	var l keyedLocks[string]
	ctx := context.Background()
	unlockA := l.lock("a")
	// Another key is free while "a" is held.
	unlockB, err := l.lockCtx(ctx, "b")
	if err != nil {
		t.Fatalf("an unrelated key waited: %v", err)
	}
	unlockB()

	// A second caller for "a" waits until the first lets go.
	got := make(chan struct{})
	go func() {
		unlock, err := l.lockCtx(ctx, "a")
		if err == nil {
			unlock()
		}
		close(got)
	}()
	if !waitFor(5*time.Second, func() bool { return l.refs("a") == 2 }) {
		t.Fatal("the second caller never queued")
	}
	select {
	case <-got:
		t.Fatal("the second caller took a held lock")
	case <-time.After(20 * time.Millisecond):
	}

	// A waiter whose caller leaves gives up and is not counted.
	short, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	if _, err := l.lockCtx(short, "a"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("abandoned wait = %v", err)
	}
	unlockA()
	<-got
	if n := l.refs("a"); n != 0 {
		t.Fatalf("waiters after everyone left = %d", n)
	}
	// A caller whose ctx already ended still takes a free lock (lockCtx's
	// rule; callers that must not start check ctx.Err() first).
	unlockC, err := l.lockCtx(short, "c")
	if err != nil {
		t.Fatalf("a free lock refused a done ctx: %v", err)
	}
	unlockC()
	if n := l.keys(); n != 0 {
		t.Fatalf("keys left behind: %d", n)
	}
}

// A resize or a spec-lock caller whose ctx already ended starts nothing,
// even on a free lock: they check ctx.Err() before lockCtx.
func TestStrictLockCallersRefuseAnEndedCaller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc := &Service{}
	if _, err := svc.ResizeSandbox(ctx, "sb", models.ResizeSandboxRequest{CPU: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("resize with an ended caller = %v, want context.Canceled", err)
	}
	if n := svc.resizeLocks.keys(); n != 0 {
		t.Fatalf("resize left %d lock entries", n)
	}
}

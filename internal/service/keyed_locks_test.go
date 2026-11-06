package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ctxKeyedLocks: one holder per key, other keys never wait, a waiter gives up
// with its caller, and a key with no holder or waiter leaves nothing behind.
func TestKeyedLocks(t *testing.T) {
	var l ctxKeyedLocks
	ctx := context.Background()
	unlockA, err := l.lock(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	// Another key is free while "a" is held.
	unlockB, err := l.lock(ctx, "b")
	if err != nil {
		t.Fatalf("an unrelated key waited: %v", err)
	}
	unlockB()

	// A second caller for "a" waits until the first lets go.
	got := make(chan struct{})
	go func() {
		unlock, err := l.lock(ctx, "a")
		if err == nil {
			unlock()
		}
		close(got)
	}()
	if !waitFor(5*time.Second, func() bool { return l.waiters("a") == 2 }) {
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
	if _, err := l.lock(short, "a"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("abandoned wait = %v", err)
	}
	unlockA()
	<-got
	if n := l.waiters("a"); n != 0 {
		t.Fatalf("waiters after everyone left = %d", n)
	}
	if len(l.locks) != 0 {
		t.Fatalf("keys left behind: %v", l.locks)
	}
	// A caller that already left takes nothing, even from a free lock.
	if _, err := l.lock(short, "c"); err == nil || l.waiters("c") != 0 {
		t.Fatalf("a cancelled caller took a free lock: %v", err)
	}
}

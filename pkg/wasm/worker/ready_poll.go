package worker

import (
	"context"
	"time"
)

// ReadyPollSleep waits before the next worker readiness ping. attempt 0 is a
// no-op (first ping fires immediately); subsequent attempts use 2ms doubling to
// a 25ms cap (plans/wasm-create-latency.md Phase 4).
func ReadyPollSleep(ctx context.Context, attempt int) {
	ReadyPollSleepOr(ctx, attempt, nil)
}

// ReadyPollSleepOr is ReadyPollSleep that also ends when ready closes (the
// worker said it serves: Supervisor.Ready), and reports whether that is
// what ended it. A nil ready never ends it. Callers ping right after it
// either way, and pass nil from then on once ready has fired, so a worker
// that signals without serving only moves one ping earlier.
func ReadyPollSleepOr(ctx context.Context, attempt int, ready <-chan struct{}) bool {
	if attempt <= 0 {
		return false
	}
	delay := 2 * time.Millisecond
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= 25*time.Millisecond {
			delay = 25 * time.Millisecond
			break
		}
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	case <-ready:
		return true
	}
	return false
}

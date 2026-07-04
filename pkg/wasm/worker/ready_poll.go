package worker

import (
	"context"
	"time"
)

// ReadyPollSleep waits before the next worker readiness ping. attempt 0 is a
// no-op (first ping fires immediately); subsequent attempts use 2ms doubling to
// a 25ms cap (plans/wasm-create-latency.md Phase 4).
func ReadyPollSleep(ctx context.Context, attempt int) {
	if attempt <= 0 {
		return
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
	}
}

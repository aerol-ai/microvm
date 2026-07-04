package worker

import (
	"context"
	"testing"
	"time"
)

func TestReadyPollSleep_BackoffSequence(t *testing.T) {
	start := time.Now()
	ctx := context.Background()
	for attempt := 1; attempt <= 4; attempt++ {
		ReadyPollSleep(ctx, attempt)
	}
	elapsed := time.Since(start)
	// 2ms + 4ms + 8ms + 16ms = 30ms minimum; allow scheduler slack.
	if elapsed < 25*time.Millisecond {
		t.Fatalf("backoff too short: %v", elapsed)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("backoff too long: %v", elapsed)
	}
}

func TestReadyPollSleep_AttemptZeroIsImmediate(t *testing.T) {
	start := time.Now()
	ReadyPollSleep(context.Background(), 0)
	if time.Since(start) > 5*time.Millisecond {
		t.Fatalf("attempt 0 should not sleep")
	}
}

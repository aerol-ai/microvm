package worker

import (
	"context"
	"testing"
	"time"
)

func TestCoverage95ReadyPollSleepCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	ReadyPollSleep(ctx, 3)
	if time.Since(start) > 5*time.Millisecond {
		t.Fatalf("canceled context should not sleep")
	}
	ReadyPollSleep(context.Background(), 5)
}
